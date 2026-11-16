package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/harris/honeypot/internal/canary"
)

// DeploySpec describes one container trap deployment requested by Hive.
type DeploySpec struct {
	DeploymentID  string
	TrapKind      string
	ContainerName string
	Image         string
	ListenPort    uint32
	Protocol      string
	Env           []string
	AIGatewayURL  string
}

// DockerManager manages hardened trap containers exclusively via docker-guard-proxy.
type DockerManager struct {
	proxyBaseURL string
	trapsRoot    string
	client       *http.Client
	keyPool      *canary.SensorKeyPool
}

// NewDockerManager creates a DockerManager targeting docker-guard-proxy.
func NewDockerManager(proxyBaseURL, trapsRoot string, keyPool *canary.SensorKeyPool) *DockerManager {
	return &DockerManager{
		proxyBaseURL: strings.TrimRight(proxyBaseURL, "/"),
		trapsRoot:    filepath.Clean(trapsRoot),
		client:       &http.Client{Timeout: 30 * time.Second},
		keyPool:      keyPool,
	}
}

// EnsureIsolatedNetwork creates trap_isolated_net with host bridge br-trap and enable_icc=false if missing.
// PortBindings DNAT requires internal=false on Docker bridge; scripts/lockdown-nftables.sh blocks outbound new connections.
func (m *DockerManager) EnsureIsolatedNetwork(ctx context.Context) error {
	body, _ := json.Marshal(map[string]any{
		"Name":     "trap_isolated_net",
		"Internal": false,
		"Options": map[string]string{
			"com.docker.network.bridge.name":       "br-trap",
			"com.docker.network.bridge.enable_icc": "false",
		},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.proxyBaseURL+"/networks/create", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusConflict {
		return nil
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return fmt.Errorf("create isolated network status %d: %s", resp.StatusCode, string(b))
}

// DeployTrap provisions honeyfs/binds, creates the hardened trap container via docker-guard-proxy, and starts it.
func (m *DockerManager) DeployTrap(ctx context.Context, spec DeploySpec) (containerID string, err error) {
	prof, ok := BuiltinProfiles[spec.TrapKind]
	if !ok {
		return "", fmt.Errorf("unsupported container trap kind %q", spec.TrapKind)
	}
	if err := m.EnsureIsolatedNetwork(ctx); err != nil {
		return "", err
	}

	name := spec.ContainerName
	if name == "" {
		name = "hp-trap-" + spec.TrapKind + "-" + spec.DeploymentID
	}
	if !strings.HasPrefix(name, "hp-trap-") {
		name = "hp-trap-" + name
	}
	img := spec.Image
	if img == "" {
		img = prof.Image
	}

	var binds []string
	switch spec.TrapKind {
	case "cowrie":
		dirs, err := SeedCowrieEnvironment(m.trapsRoot, spec.DeploymentID, spec.AIGatewayURL, m.keyPool)
		if err != nil {
			return "", err
		}
		binds = []string{
			dirs.VarDir + ":/cowrie/cowrie-git/var:rw",
			dirs.EtcDir + ":/cowrie/cowrie-git/etc:ro",
			dirs.HoneyfsDir + ":/cowrie/cowrie-git/honeyfs:ro",
			dirs.FsPicklePath + ":/cowrie/cowrie-git/share/cowrie/fs.pickle:ro",
		}
	case "heralding":
		hDirs, err := SeedHeraldingEnvironment(m.trapsRoot, spec.DeploymentID)
		if err != nil {
			return "", err
		}
		binds = []string{
			hDirs.LogDir + ":/var/log/heralding:rw",
			hDirs.WorkDir + ":/tmp/heralding:rw",
			hDirs.ConfigPath + ":/etc/heralding/heralding.yml:ro",
		}
	}

	env := append([]string(nil), spec.Env...)
	if spec.TrapKind == "cowrie" || spec.TrapKind == "heralding" {
		env = append(env, "PYTHONDONTWRITEBYTECODE=1")
	}

	portBindings := map[string][]map[string]string{
		prof.ContainerPort: {{"HostPort": fmt.Sprintf("%d", spec.ListenPort)}},
	}
	if spec.ListenPort == prof.DefaultPort || spec.ListenPort == 0 {
		if spec.ListenPort == 0 && prof.DefaultPort > 0 {
			portBindings[prof.ContainerPort] = []map[string]string{{"HostPort": fmt.Sprintf("%d", prof.DefaultPort)}}
		}
		for cPort, hPort := range prof.ExtraHostPorts {
			portBindings[cPort] = []map[string]string{{"HostPort": fmt.Sprintf("%d", hPort)}}
		}
	}
	exposedPorts := make(map[string]struct{}, len(portBindings))
	for cPort := range portBindings {
		exposedPorts[cPort] = struct{}{}
	}

	createBody, _ := json.Marshal(map[string]any{
		"Image":        img,
		"User":         prof.User,
		"Env":          env,
		"ExposedPorts": exposedPorts,
		"HostConfig": map[string]any{
			"Binds":          binds,
			"NetworkMode":    "trap_isolated_net",
			"Privileged":     false,
			"ReadonlyRootfs": true,
			"Tmpfs": map[string]string{
				"/tmp": "rw,noexec,nosuid,size=64m",
				"/run": "rw,noexec,nosuid,size=16m",
			},
			"CapDrop":     []string{"ALL"},
			"SecurityOpt": []string{"no-new-privileges:true"},
			"PidsLimit":   128,
			"Memory":      256 * 1024 * 1024,
			"NanoCpus":    500_000_000,
			"PortBindings": portBindings,
		},
	})

	u := fmt.Sprintf("%s/containers/create?name=%s", m.proxyBaseURL, url.QueryEscape(name))
	sendCreate := func() (int, []byte, error) {
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(createBody))
		if reqErr != nil {
			return 0, nil, reqErr
		}
		req.Header.Set("Content-Type", "application/json")
		resp, doErr := m.client.Do(req)
		if doErr != nil {
			return 0, nil, doErr
		}
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		_ = resp.Body.Close()
		return resp.StatusCode, bodyBytes, nil
	}

	status, b, err := sendCreate()
	if err != nil {
		return "", err
	}
	if status == http.StatusNotFound {
		if pullErr := m.pullImage(ctx, img); pullErr != nil {
			return "", fmt.Errorf("create container %s missing image and pull failed: %w", name, pullErr)
		}
		status, b, err = sendCreate()
		if err != nil {
			return "", err
		}
	}
	if status == http.StatusConflict {
		_ = m.removeContainer(ctx, name)
		status, b, err = sendCreate()
		if err != nil {
			return "", err
		}
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return "", fmt.Errorf("create container %s failed (%d): %s", name, status, string(b))
	}

	var parsed struct {
		ID string `json:"Id"`
	}
	_ = json.Unmarshal(b, &parsed)

	if err := m.containerAction(ctx, name, "start", http.MethodPost); err != nil {
		return parsed.ID, err
	}
	return parsed.ID, nil
}

// StopTrap stops a managed trap container via docker-guard-proxy.
func (m *DockerManager) StopTrap(ctx context.Context, containerName string) error {
	return m.containerAction(ctx, containerName, "stop", http.MethodPost)
}

// RestartTrap restarts a managed trap container via docker-guard-proxy.
func (m *DockerManager) RestartTrap(ctx context.Context, containerName string) error {
	return m.containerAction(ctx, containerName, "restart", http.MethodPost)
}

// FetchLogs fetches trailing log lines from a managed trap container.
func (m *DockerManager) FetchLogs(ctx context.Context, containerName string, tail uint32) (string, error) {
	if tail == 0 {
		tail = 100
	}
	u := fmt.Sprintf("%s/containers/%s/logs?stdout=1&stderr=1&tail=%d", m.proxyBaseURL, url.PathEscape(containerName), tail)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("fetch logs status %d: %s", resp.StatusCode, string(b))
	}
	return string(b), nil
}

func (m *DockerManager) containerAction(ctx context.Context, containerName, action, method string) error {
	u := fmt.Sprintf("%s/containers/%s/%s", m.proxyBaseURL, url.PathEscape(containerName), action)
	req, err := http.NewRequestWithContext(ctx, method, u, nil)
	if err != nil {
		return err
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNotModified {
		return nil
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return fmt.Errorf("docker action %s on %s failed (%d): %s", action, containerName, resp.StatusCode, string(b))
}

func (m *DockerManager) removeContainer(ctx context.Context, containerName string) error {
	u := fmt.Sprintf("%s/containers/%s?force=1", m.proxyBaseURL, url.PathEscape(containerName))
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, u, nil)
	if err != nil {
		return err
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	return nil
}

func (m *DockerManager) pullImage(ctx context.Context, imageRef string) error {
	repo, tag := splitImageRepoTag(imageRef)
	u := fmt.Sprintf("%s/images/create?fromImage=%s&tag=%s", m.proxyBaseURL, url.QueryEscape(repo), url.QueryEscape(tag))
	pullCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(pullCtx, http.MethodPost, u, nil)
	if err != nil {
		return err
	}
	resp, err := (&http.Client{Timeout: 5 * time.Minute}).Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("pull image %s status %d", imageRef, resp.StatusCode)
	}
	return nil
}

func splitImageRepoTag(ref string) (repo, tag string) {
	if idx := strings.Index(ref, "@"); idx > 0 {
		return ref[:idx], ref[idx+1:]
	}
	lastColon := strings.LastIndex(ref, ":")
	lastSlash := strings.LastIndex(ref, "/")
	if lastColon > lastSlash {
		return ref[:lastColon], ref[lastColon+1:]
	}
	return ref, "latest"
}
