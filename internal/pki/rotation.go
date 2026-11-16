package pki

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	currentCertFile = "client.crt"
	currentKeyFile  = "client.key"
	nextCertFile    = "next.crt"
	nextKeyFile     = "next.key"
	rootCAPathFile  = "ca.crt"
	nodeMetaFile    = "node_id"
)

// ClientCertStore persists client mTLS credentials with atomic two-phase rotation on Sensors and nginx-guard.
type ClientCertStore struct {
	mu      sync.RWMutex
	dir     string
	rootPEM []byte
	certPEM []byte
	keyPEM  []byte
	pair    tls.Certificate
	leaf    *x509.Certificate
}

// OpenClientCertStore loads an existing enrolled credential bundle from dir if present.
func OpenClientCertStore(dir string) (*ClientCertStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir cert store: %w", err)
	}
	s := &ClientCertStore{dir: dir}
	certPath := filepath.Join(dir, currentCertFile)
	keyPath := filepath.Join(dir, currentKeyFile)
	caPath := filepath.Join(dir, rootCAPathFile)

	if fileExists(certPath) && fileExists(keyPath) && fileExists(caPath) {
		if err := s.load(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// IsEnrolled reports whether valid client mTLS credentials are loaded.
func (s *ClientCertStore) IsEnrolled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.leaf != nil
}

// NodeID reads the enrolled node UUID saved on disk.
func (s *ClientCertStore) NodeID() string {
	b, err := os.ReadFile(filepath.Join(s.dir, nodeMetaFile))
	if err != nil {
		return ""
	}
	return string(b)
}

// SaveInitial writes initial enrollment artifacts atomically to disk.
func (s *ClientCertStore) SaveInitial(nodeID string, rootPEM, certPEM, keyPEM []byte) error {
	if _, err := verifyKeypairAgainstCA(rootPEM, certPEM, keyPEM); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := atomicWriteFile(filepath.Join(s.dir, rootCAPathFile), rootPEM, 0o644); err != nil {
		return err
	}
	if err := atomicWriteFile(filepath.Join(s.dir, currentKeyFile), keyPEM, 0o600); err != nil {
		return err
	}
	if err := atomicWriteFile(filepath.Join(s.dir, currentCertFile), certPEM, 0o644); err != nil {
		return err
	}
	if err := atomicWriteFile(filepath.Join(s.dir, nodeMetaFile), []byte(nodeID), 0o600); err != nil {
		return err
	}
	return s.loadLocked()
}

// StageNextKey writes a candidate rotation private key before requesting RenewNodeCert.
func (s *ClientCertStore) StageNextKey(nextKeyPEM []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return atomicWriteFile(filepath.Join(s.dir, nextKeyFile), nextKeyPEM, 0o600)
}

// CommitRotation validates the signed next.crt against the staged next.key and Root CA before atomically replacing client.crt/client.key.
// If any verification fails, the existing valid credentials remain untouched.
func (s *ClientCertStore) CommitRotation(nextCertPEM []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	nextKeyPath := filepath.Join(s.dir, nextKeyFile)
	nextCertPath := filepath.Join(s.dir, nextCertFile)
	nextKeyPEM, err := os.ReadFile(nextKeyPath)
	if err != nil {
		return fmt.Errorf("read staged next key: %w", err)
	}
	if _, err := verifyKeypairAgainstCA(s.rootPEM, nextCertPEM, nextKeyPEM); err != nil {
		_ = os.Remove(nextCertPath)
		return fmt.Errorf("verify rotated credentials: %w", err)
	}
	if err := atomicWriteFile(nextCertPath, nextCertPEM, 0o644); err != nil {
		return err
	}
	// Commit key then cert atomically via rename so current credentials remain consistent.
	if err := os.Rename(nextKeyPath, filepath.Join(s.dir, currentKeyFile)); err != nil {
		return fmt.Errorf("promote rotated key: %w", err)
	}
	if err := os.Rename(nextCertPath, filepath.Join(s.dir, currentCertFile)); err != nil {
		return fmt.Errorf("promote rotated cert: %w", err)
	}
	return s.loadLocked()
}

// NeedsRotation returns true when the active leaf cert expires within threshold (e.g., 30 days).
func (s *ClientCertStore) NeedsRotation(threshold time.Duration) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.leaf == nil {
		return false
	}
	return time.Until(s.leaf.NotAfter) <= threshold
}

// ExpiresAt returns the active leaf certificate's NotAfter timestamp.
func (s *ClientCertStore) ExpiresAt() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.leaf == nil {
		return time.Time{}
	}
	return s.leaf.NotAfter
}

// ClientTLSConfig builds an mTLS 1.3 client config that dynamically resolves the latest rotated certificate.
func (s *ClientCertStore) ClientTLSConfig(serverName string) (*tls.Config, error) {
	s.mu.RLock()
	rootPEM := append([]byte(nil), s.rootPEM...)
	s.mu.RUnlock()

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(rootPEM) {
		return nil, errors.New("invalid Root CA PEM in store")
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    pool,
		ServerName: serverName,
		GetClientCertificate: func(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			s.mu.RLock()
			defer s.mu.RUnlock()
			if s.leaf == nil {
				return nil, errors.New("client cert store not enrolled")
			}
			cp := s.pair
			return &cp, nil
		},
	}, nil
}

func (s *ClientCertStore) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLocked()
}

func (s *ClientCertStore) loadLocked() error {
	rootPEM, err := os.ReadFile(filepath.Join(s.dir, rootCAPathFile))
	if err != nil {
		return err
	}
	certPEM, err := os.ReadFile(filepath.Join(s.dir, currentCertFile))
	if err != nil {
		return err
	}
	keyPEM, err := os.ReadFile(filepath.Join(s.dir, currentKeyFile))
	if err != nil {
		return err
	}
	leaf, err := verifyKeypairAgainstCA(rootPEM, certPEM, keyPEM)
	if err != nil {
		return err
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}
	s.rootPEM = rootPEM
	s.certPEM = certPEM
	s.keyPEM = keyPEM
	s.pair = pair
	s.leaf = leaf
	return nil
}

func verifyKeypairAgainstCA(rootPEM, certPEM, keyPEM []byte) (*x509.Certificate, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(rootPEM) {
		return nil, errors.New("invalid Root CA PEM")
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("mismatched keypair: %w", err)
	}
	if len(pair.Certificate) == 0 {
		return nil, errors.New("empty certificate chain")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse leaf cert: %w", err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return nil, fmt.Errorf("leaf cert not trusted by Root CA: %w", err)
	}
	return leaf, nil
}

func atomicWriteFile(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
