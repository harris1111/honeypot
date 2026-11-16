package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	"github.com/harris/honeypot/internal/orchestrator"
	honeypotv1 "github.com/harris/honeypot/proto/gen/honeypot/v1"
)

// DesiredTrap records a persistent trap deployment target for reboot reconciliation.
type DesiredTrap struct {
	DeploymentID  string `json:"deployment_id"`
	TrapKind      string `json:"trap_kind"`
	ContainerName string `json:"container_name"`
	Image         string `json:"image"`
	ListenPort    uint32 `json:"listen_port"`
	Protocol      string `json:"protocol"`
	ConfigJSON    string `json:"config_json"`
	DesiredState  string `json:"desired_state"` // running | stopped
}

// SensorBootstrapState persists node allowlist, feed pubkey, canary seeds, and desired traps safely on disk.
type SensorBootstrapState struct {
	mu           sync.Mutex
	path         string
	Allowlist    []string                     `json:"allowlist_cidrs"`
	FeedPubKey   []byte                       `json:"feed_verify_ed25519_pubkey"`
	CanarySeeds  []*honeypotv1.CanaryKeySeed  `json:"canary_seeds"`
	DesiredTraps map[string]DesiredTrap       `json:"desired_traps"`
	CveToggles   map[string]bool              `json:"cve_toggles"`
}

func loadBootstrapState(path string) *SensorBootstrapState {
	st := &SensorBootstrapState{
		path:         path,
		DesiredTraps: make(map[string]DesiredTrap),
		CveToggles:   make(map[string]bool),
	}
	b, err := os.ReadFile(path)
	if err == nil {
		_ = json.Unmarshal(b, st)
	}
	if st.DesiredTraps == nil {
		st.DesiredTraps = make(map[string]DesiredTrap)
	}
	if st.CveToggles == nil {
		st.CveToggles = make(map[string]bool)
	}
	return st
}

func (s *SensorBootstrapState) saveLocked() error {
	_ = os.MkdirAll(filepath.Dir(s.path), 0o700)
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *SensorBootstrapState) SaveInitialEnrollment(resp *honeypotv1.EnrollNodeResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Allowlist = append([]string(nil), resp.GetAllowlistCidrs()...)
	s.FeedPubKey = append([]byte(nil), resp.GetFeedVerifyEd25519Pubkey()...)
	s.CanarySeeds = append([]*honeypotv1.CanaryKeySeed(nil), resp.GetCanaryKeys()...)
	return s.saveLocked()
}

func (s *SensorBootstrapState) UpdateCanarySeeds(seeds []*honeypotv1.CanaryKeySeed) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.CanarySeeds = seeds
	return s.saveLocked()
}

func (s *SensorBootstrapState) UpdateAllowlist(cidrs []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Allowlist = append([]string(nil), cidrs...)
	return s.saveLocked()
}

func (s *SensorBootstrapState) UpsertDesiredTrap(dt DesiredTrap) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.DesiredTraps[dt.DeploymentID] = dt
	return s.saveLocked()
}

func (s *SensorBootstrapState) SetTrapStateByContainer(deploymentID, containerName, desired string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if dt, ok := s.DesiredTraps[deploymentID]; ok {
		dt.DesiredState = desired
		s.DesiredTraps[deploymentID] = dt
		return s.saveLocked()
	}
	for k, dt := range s.DesiredTraps {
		if dt.ContainerName == containerName {
			dt.DesiredState = desired
			s.DesiredTraps[k] = dt
			return s.saveLocked()
		}
	}
	return nil
}

func (s *SensorBootstrapState) SnapshotTraps() []DesiredTrap {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]DesiredTrap, 0, len(s.DesiredTraps))
	for _, dt := range s.DesiredTraps {
		out = append(out, dt)
	}
	return out
}

func (s *SensorBootstrapState) SetCveToggle(cveID string, enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.CveToggles[cveID] = enabled
	return s.saveLocked()
}

func (d DesiredTrap) toDeploySpec(aiGatewayURL string) orchestrator.DeploySpec {
	return orchestrator.DeploySpec{
		DeploymentID:  d.DeploymentID,
		TrapKind:      d.TrapKind,
		ContainerName: d.ContainerName,
		Image:         d.Image,
		ListenPort:    d.ListenPort,
		Protocol:      d.Protocol,
		AIGatewayURL:  aiGatewayURL,
	}
}
