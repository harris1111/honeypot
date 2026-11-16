package pki

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	caCertFile       = "root_ca.crt"
	caKeyFile        = "root_ca.key"
	feedPrivFile     = "feed_ed25519.key"
	feedPubFile      = "feed_ed25519.pub"
	defaultLeafTTL   = 90 * 24 * time.Hour
	defaultServerTTL = 365 * 24 * time.Hour
)

// CA manages the internal ECDSA Root CA and Ed25519 Nginx feed signing keys.
type CA struct {
	dir        string
	rootCert   *x509.Certificate
	rootCertPEM []byte
	rootKey    *ecdsa.PrivateKey
	feedPriv   ed25519.PrivateKey
	feedPub    ed25519.PublicKey
}

// InitOrLoad loads existing PKI artifacts from dir or generates a new Root CA and Ed25519 feed keypair.
func InitOrLoad(dir string) (*CA, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir pki dir: %w", err)
	}

	ca := &CA{dir: dir}
	caCertPath := filepath.Join(dir, caCertFile)
	caKeyPath := filepath.Join(dir, caKeyFile)
	if fileExists(caCertPath) && fileExists(caKeyPath) {
		if err := ca.loadRootCA(caCertPath, caKeyPath); err != nil {
			return nil, err
		}
	} else {
		if err := ca.generateRootCA(caCertPath, caKeyPath); err != nil {
			return nil, err
		}
	}

	feedPrivPath := filepath.Join(dir, feedPrivFile)
	feedPubPath := filepath.Join(dir, feedPubFile)
	if fileExists(feedPrivPath) && fileExists(feedPubPath) {
		if err := ca.loadFeedKeys(feedPrivPath, feedPubPath); err != nil {
			return nil, err
		}
	} else {
		if err := ca.generateFeedKeys(feedPrivPath, feedPubPath); err != nil {
			return nil, err
		}
	}

	return ca, nil
}

func (c *CA) generateRootCA(certPath, keyPath string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate root key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "Honeypot Internal Root CA",
			Organization: []string{"Deception Control Plane"},
		},
		NotBefore:             now.Add(-10 * time.Minute),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("create root cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("parse root cert: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal root key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("write root key: %w", err)
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return fmt.Errorf("write root cert: %w", err)
	}
	c.rootCert = cert
	c.rootCertPEM = certPEM
	c.rootKey = key
	return nil
}

func (c *CA) loadRootCA(certPath, keyPath string) error {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("read root cert: %w", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return errors.New("invalid root cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse root cert: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("read root key: %w", err)
	}
	kblock, _ := pem.Decode(keyPEM)
	if kblock == nil {
		return errors.New("invalid root key PEM")
	}
	key, err := x509.ParseECPrivateKey(kblock.Bytes)
	if err != nil {
		return fmt.Errorf("parse root key: %w", err)
	}
	c.rootCert = cert
	c.rootCertPEM = certPEM
	c.rootKey = key
	return nil
}

func (c *CA) generateFeedKeys(privPath, pubPath string) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate ed25519 feed keys: %w", err)
	}
	if err := os.WriteFile(privPath, []byte(hex.EncodeToString(priv)), 0o600); err != nil {
		return fmt.Errorf("write feed privkey: %w", err)
	}
	if err := os.WriteFile(pubPath, []byte(hex.EncodeToString(pub)), 0o644); err != nil {
		return fmt.Errorf("write feed pubkey: %w", err)
	}
	c.feedPriv = priv
	c.feedPub = pub
	return nil
}

func (c *CA) loadFeedKeys(privPath, pubPath string) error {
	privHex, err := os.ReadFile(privPath)
	if err != nil {
		return fmt.Errorf("read feed privkey: %w", err)
	}
	pubHex, err := os.ReadFile(pubPath)
	if err != nil {
		return fmt.Errorf("read feed pubkey: %w", err)
	}
	priv, err := hex.DecodeString(strings.TrimSpace(string(privHex)))
	if err != nil || len(priv) != ed25519.PrivateKeySize {
		return errors.New("invalid ed25519 feed private key")
	}
	pub, err := hex.DecodeString(strings.TrimSpace(string(pubHex)))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("invalid ed25519 feed public key")
	}
	c.feedPriv = ed25519.PrivateKey(priv)
	c.feedPub = ed25519.PublicKey(pub)
	return nil
}

// RootCertPEM returns the PEM-encoded Root CA certificate.
func (c *CA) RootCertPEM() []byte {
	return append([]byte(nil), c.rootCertPEM...)
}

// RootPool returns an x509.CertPool containing the internal Root CA.
func (c *CA) RootPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(c.rootCert)
	return pool
}

// RootFingerprintSHA256 returns the lowercase hex SHA-256 fingerprint of the Root CA certificate.
func (c *CA) RootFingerprintSHA256() string {
	sum := sha256.Sum256(c.rootCert.Raw)
	return hex.EncodeToString(sum[:])
}

// FeedPublicKey returns a copy of the Ed25519 public key used to verify signed Nginx feeds.
func (c *CA) FeedPublicKey() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), c.feedPub...)
}

// SignFeed signs canonical Nginx feed bytes using Ed25519.
func (c *CA) SignFeed(payload []byte) []byte {
	return ed25519.Sign(c.feedPriv, payload)
}

// VerifyFeedSignature verifies an Ed25519 feed signature against a public key.
func VerifyFeedSignature(pub ed25519.PublicKey, payload, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, payload, sig)
}

// IssueServerCert issues a TLS server certificate for Hive ingress/admin endpoints.
func (c *CA) IssueServerCert(hosts []string) (tls.Certificate, []byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("generate server key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return tls.Certificate{}, nil, nil, err
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "hive.honeypot.internal"},
		NotBefore:    now.Add(-10 * time.Minute),
		NotAfter:     now.Add(defaultServerTTL),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.rootCert, &key.PublicKey, c.rootKey)
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("sign server cert: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("marshal server key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("parse server keypair: %w", err)
	}
	pair.Certificate = append(pair.Certificate, c.rootCert.Raw)
	return pair, certPEM, keyPEM, nil
}

// SignClientCSR verifies a node CSR and signs a client mTLS certificate pinned to a SPIFFE URI SAN.
// NotBefore is backdated by 10m to tolerate minor VPS NTP clock skew.
func (c *CA) SignClientCSR(csrPEM []byte, role, nodeID string, ttl time.Duration) (certPEM []byte, serialHex string, expiresAt time.Time, err error) {
	if role != "sensor" && role != "nginx_guard" {
		return nil, "", time.Time{}, fmt.Errorf("invalid node role %q", role)
	}
	if nodeID == "" {
		return nil, "", time.Time{}, errors.New("empty nodeID")
	}
	if ttl <= 0 {
		ttl = defaultLeafTTL
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, "", time.Time{}, errors.New("invalid CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, "", time.Time{}, fmt.Errorf("parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, "", time.Time{}, fmt.Errorf("invalid CSR signature: %w", err)
	}

	spiffeRole := "node"
	if role == "nginx_guard" {
		spiffeRole = "guard"
	}
	spiffeURL, err := url.Parse(fmt.Sprintf("spiffe://honeypot/%s/%s", spiffeRole, nodeID))
	if err != nil {
		return nil, "", time.Time{}, err
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, "", time.Time{}, err
	}
	now := time.Now().UTC()
	expiresAt = now.Add(ttl)

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   fmt.Sprintf("%s-%s", spiffeRole, nodeID),
			Organization: []string{"Honeypot Mesh"},
		},
		NotBefore:   now.Add(-10 * time.Minute),
		NotAfter:    expiresAt,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:        []*url.URL{spiffeURL},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.rootCert, csr.PublicKey, c.rootKey)
	if err != nil {
		return nil, "", time.Time{}, fmt.Errorf("sign client cert: %w", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return certPEM, strings.ToLower(serial.Text(16)), expiresAt, nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	if serial.Sign() <= 0 {
		serial.SetInt64(1)
	}
	return serial, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
