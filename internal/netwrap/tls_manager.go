package netwrap

import (
	"container/list"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

const (
	defaultDynamicCertCN = "prod-internal-gw.corp.local"
	defaultLRUCapacity   = 512
)

// TLSManagerConfig configures Dual-Mode ACME decoy domains + dynamic raw-IP/unknown-SNI TLS certs.
type TLSManagerConfig struct {
	StateDir     string
	DecoyDomains []string
	ACMEEmail    string
	ACMECA       string // optional override (e.g., staging CA)
	EnableACME   bool
	MaxLRU       int
}

// TLSManager manages persistent ACME certificates for decoy SNIs and dynamic self-signed ECDSA certs
// for raw IP or unknown-SNI scanners.
type TLSManager struct {
	magicCfg   *certmagic.Config
	acmeIssuer *certmagic.ACMEIssuer
	managedSet map[string]bool
	sanBundles [][]string

	mu       sync.Mutex
	maxLRU   int
	lruList  *list.List
	lruItems map[string]*list.Element
}

type cachedCertEntry struct {
	key  string
	cert *tls.Certificate
	exp  time.Time
}

// NewTLSManager initializes certmagic storage + optional ACME HTTP-01/TLS-ALPN-01 plus the dynamic self-signed cache.
func NewTLSManager(ctx context.Context, cfg TLSManagerConfig) (*TLSManager, error) {
	maxLRU := cfg.MaxLRU
	if maxLRU <= 0 {
		maxLRU = defaultLRUCapacity
	}
	tm := &TLSManager{
		managedSet: make(map[string]bool),
		maxLRU:     maxLRU,
		lruList:    list.New(),
		lruItems:   make(map[string]*list.Element),
	}

	var domains []string
	for _, d := range cfg.DecoyDomains {
		clean := strings.ToLower(strings.TrimSpace(d))
		if clean != "" {
			tm.managedSet[clean] = true
			domains = append(domains, clean)
		}
	}
	tm.sanBundles = groupDomainBundles(domains, 5)

	if cfg.StateDir != "" {
		storage := &certmagic.FileStorage{Path: filepath.Join(cfg.StateDir, "certmagic")}
		var magic *certmagic.Config
		cache := certmagic.NewCache(certmagic.CacheOptions{
			GetConfigForCert: func(_ certmagic.Certificate) (*certmagic.Config, error) {
				return magic, nil
			},
			Logger: zap.NewNop(),
		})
		magic = certmagic.New(cache, certmagic.Config{
			Storage: storage,
			Logger:  zap.NewNop(),
		})
		caEndpoint := cfg.ACMECA
		if caEndpoint == "" {
			caEndpoint = certmagic.LetsEncryptProductionCA
		}
		acmeIss := certmagic.NewACMEIssuer(magic, certmagic.ACMEIssuer{
			CA:     caEndpoint,
			Email:  cfg.ACMEEmail,
			Agreed: cfg.ACMEEmail != "",
			Logger: zap.NewNop(),
		})
		magic.Issuers = []certmagic.Issuer{acmeIss}
		tm.magicCfg = magic
		tm.acmeIssuer = acmeIss

		if cfg.EnableACME && len(domains) > 0 {
			if err := magic.ManageAsync(ctx, domains); err != nil {
				return nil, fmt.Errorf("certmagic manage async: %w", err)
			}
		}
	}

	return tm, nil
}

// SANBundles returns domain groupings where >5 subdomains under one root are bundled cleanly.
func (tm *TLSManager) SANBundles() [][]string {
	return tm.sanBundles
}

// TLSConfig builds a net/http-compatible *tls.Config preserving acme-tls/1 in NextProtos.
func (tm *TLSManager) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1", "acme-tls/1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return tm.GetCertificate(hello)
		},
	}
}

// GetCertificate selects managed ACME cert for known decoy SNIs, or dynamically issues a cached
// self-signed ECDSA P-256 cert for raw IP / unknown SNI connections.
func (tm *TLSManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	sni := ""
	if hello != nil {
		sni = strings.ToLower(strings.TrimSpace(hello.ServerName))
	}
	if sni != "" && tm.managedSet[sni] && tm.magicCfg != nil {
		if cert, err := tm.magicCfg.GetCertificate(hello); err == nil && cert != nil {
			return cert, nil
		}
	}

	cacheKey := sni
	var localIP net.IP
	if cacheKey == "" && hello != nil && hello.Conn != nil {
		if addr, ok := hello.Conn.LocalAddr().(*net.TCPAddr); ok && addr.IP != nil {
			localIP = addr.IP
			cacheKey = "ip:" + addr.IP.String()
		}
	}
	if cacheKey == "" {
		cacheKey = "ip:127.0.0.1"
		localIP = net.ParseIP("127.0.0.1")
	}

	return tm.getOrCreateDynamicCert(cacheKey, sni, localIP)
}

// HTTPChallengeHandler delegates /.well-known/acme-challenge/ to certmagic when ACME is active.
func (tm *TLSManager) HTTPChallengeHandler(next http.Handler) http.Handler {
	if tm.acmeIssuer != nil {
		return tm.acmeIssuer.HTTPChallengeHandler(next)
	}
	return next
}

func (tm *TLSManager) getOrCreateDynamicCert(cacheKey, sni string, localIP net.IP) (*tls.Certificate, error) {
	now := time.Now().UTC()

	tm.mu.Lock()
	if elem, ok := tm.lruItems[cacheKey]; ok {
		entry := elem.Value.(*cachedCertEntry)
		if now.Before(entry.exp) {
			tm.lruList.MoveToFront(elem)
			cert := entry.cert
			tm.mu.Unlock()
			return cert, nil
		}
		tm.lruList.Remove(elem)
		delete(tm.lruItems, cacheKey)
	}
	tm.mu.Unlock()

	cert, exp, err := generateSelfSignedECDSA(sni, localIP)
	if err != nil {
		return nil, err
	}

	tm.mu.Lock()
	defer tm.mu.Unlock()
	if elem, ok := tm.lruItems[cacheKey]; ok {
		return elem.Value.(*cachedCertEntry).cert, nil
	}
	elem := tm.lruList.PushFront(&cachedCertEntry{key: cacheKey, cert: cert, exp: exp})
	tm.lruItems[cacheKey] = elem
	for tm.lruList.Len() > tm.maxLRU {
		tail := tm.lruList.Back()
		if tail == nil {
			break
		}
		old := tail.Value.(*cachedCertEntry)
		tm.lruList.Remove(tail)
		delete(tm.lruItems, old.key)
	}
	return cert, nil
}

func generateSelfSignedECDSA(sni string, localIP net.IP) (*tls.Certificate, time.Time, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, time.Time{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		return nil, time.Time{}, err
	}

	now := time.Now().UTC()
	exp := now.Add(30 * 24 * time.Hour)
	cn := defaultDynamicCertCN
	if sni != "" && net.ParseIP(sni) == nil {
		cn = sni
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"Internal Edge Gateway"}},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              exp,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(sni); ip != nil {
		tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
	} else if sni != "" {
		tmpl.DNSNames = append(tmpl.DNSNames, sni)
	}
	if localIP != nil {
		tmpl.IPAddresses = append(tmpl.IPAddresses, localIP)
	} else if len(tmpl.IPAddresses) == 0 && len(tmpl.DNSNames) == 0 {
		tmpl.IPAddresses = append(tmpl.IPAddresses, net.ParseIP("127.0.0.1"))
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, time.Time{}, err
	}
	leaf, _ := x509.ParseCertificate(der)
	return &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
		Leaf:        leaf,
	}, now.Add(24 * time.Hour), nil
}

// groupDomainBundles groups subdomains sharing the same root domain into SAN bundles when > threshold.
func groupDomainBundles(domains []string, threshold int) [][]string {
	byRoot := make(map[string][]string)
	for _, d := range domains {
		parts := strings.Split(d, ".")
		root := d
		if len(parts) >= 2 {
			root = strings.Join(parts[len(parts)-2:], ".")
		}
		byRoot[root] = append(byRoot[root], d)
	}
	var out [][]string
	for _, grp := range byRoot {
		if len(grp) > threshold {
			out = append(out, grp)
			continue
		}
		for _, single := range grp {
			out = append(out, []string{single})
		}
	}
	return out
}
