package pki

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// PeerIdentity represents an authenticated mTLS peer extracted from SPIFFE SAN.
type PeerIdentity struct {
	Role      string // "sensor" | "nginx_guard"
	NodeID    string
	SerialHex string
}

// GenerateJoinToken creates a high-entropy join token and its SHA-256 hash.
func GenerateJoinToken() (raw string, hash []byte, err error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", nil, fmt.Errorf("generate join token: %w", err)
	}
	raw = "hpj_" + base64.RawURLEncoding.EncodeToString(buf)
	return raw, HashJoinToken(raw), nil
}

// HashJoinToken hashes a join token with SHA-256 for storage and constant-time DB lookup.
func HashJoinToken(raw string) []byte {
	sum := sha256.Sum256([]byte(strings.TrimSpace(raw)))
	return sum[:]
}

// GenerateClientKeyAndCSR creates a fresh ECDSA P-256 keypair and CSR for Sensor/nginx-guard enrollment.
// Private key material remains strictly on the edge host.
func GenerateClientKeyAndCSR(commonName string) (keyPEM []byte, csrPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate client key: %w", err)
	}
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: commonName},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create CSR: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal client key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	return keyPEM, csrPEM, nil
}

// BuildHiveIngressTLSConfig builds the TLS 1.3 config for Hive's :9443 ingress port.
//
// Security design:
//   - SNI starting with "enroll." allows TLS without client cert (only for EnrollNode).
//   - Default SNI / empty SNI requires a valid client cert verified against Hive's Root CA,
//     while keeping ClientCAs empty (ClientAuth: tls.RequireAnyClientCert) so scanners
//     cannot fingerprint Hive's Root CA Subject DN in the CertificateRequest frame.
func BuildHiveIngressTLSConfig(ca *CA, serverCert tls.Certificate) *tls.Config {
	rootPool := ca.RootPool()
	base := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCert},
		NextProtos:   []string{"h2", "http/1.1"},
	}

	base.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		sni := strings.ToLower(strings.TrimSpace(hello.ServerName))
		if strings.HasPrefix(sni, "enroll.") {
			return &tls.Config{
				MinVersion:   tls.VersionTLS13,
				Certificates: []tls.Certificate{serverCert},
				NextProtos:   []string{"h2", "http/1.1"},
				ClientAuth:   tls.NoClientCert,
			}, nil
		}

		return &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{serverCert},
			NextProtos:   []string{"h2", "http/1.1"},
			ClientAuth:   tls.RequireAnyClientCert,
			VerifyConnection: func(cs tls.ConnectionState) error {
				if len(cs.PeerCertificates) == 0 {
					return errors.New("missing client mTLS certificate")
				}
				opts := x509.VerifyOptions{
					Roots:     rootPool,
					KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
				}
				if len(cs.PeerCertificates) > 1 {
					inter := x509.NewCertPool()
					for _, ic := range cs.PeerCertificates[1:] {
						inter.AddCert(ic)
					}
					opts.Intermediates = inter
				}
				if _, err := cs.PeerCertificates[0].Verify(opts); err != nil {
					return fmt.Errorf("verify client certificate: %w", err)
				}
				return nil
			},
		}, nil
	}

	return base
}

// ParseCertIdentity extracts the SPIFFE identity and hex serial number from a leaf client certificate.
func ParseCertIdentity(cert *x509.Certificate) (PeerIdentity, bool) {
	if cert == nil {
		return PeerIdentity{}, false
	}
	serialHex := strings.ToLower(cert.SerialNumber.Text(16))
	for _, u := range cert.URIs {
		if u.Scheme != "spiffe" || u.Host != "honeypot" {
			continue
		}
		parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
		if len(parts) != 2 || parts[1] == "" {
			continue
		}
		switch parts[0] {
		case "node":
			return PeerIdentity{Role: "sensor", NodeID: parts[1], SerialHex: serialHex}, true
		case "guard":
			return PeerIdentity{Role: "nginx_guard", NodeID: parts[1], SerialHex: serialHex}, true
		}
	}
	return PeerIdentity{}, false
}

// ExtractGRPCPeerIdentity extracts PeerIdentity from an incoming mTLS gRPC context.
func ExtractGRPCPeerIdentity(ctx context.Context) (PeerIdentity, bool) {
	p, ok := peer.FromContext(ctx)
	if !ok || p.AuthInfo == nil {
		return PeerIdentity{}, false
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(tlsInfo.State.PeerCertificates) == 0 {
		return PeerIdentity{}, false
	}
	return ParseCertIdentity(tlsInfo.State.PeerCertificates[0])
}

// ExtractHTTPPeerIdentity extracts PeerIdentity from an incoming mTLS HTTP request.
func ExtractHTTPPeerIdentity(r *http.Request) (PeerIdentity, bool) {
	if r == nil || r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return PeerIdentity{}, false
	}
	return ParseCertIdentity(r.TLS.PeerCertificates[0])
}
