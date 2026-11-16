package orchestrator

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/harris/honeypot/internal/canary"
)

// SeededCowrieDirs holds host paths prepared for one hardened Cowrie deployment.
type SeededCowrieDirs struct {
	RootDir      string
	VarDir       string
	EtcDir       string
	HoneyfsDir   string
	FsPicklePath string
	DownloadsDir string
	TTYDir       string
	LogJSONPath  string
}

// SeedCowrieEnvironment creates writable var/, pre-generated etc/ SSH host keys,
// Canary-seeded honeyfs overlays, and a compiled fs.pickle inside trapsRoot/<deploymentID>/.
func SeedCowrieEnvironment(trapsRoot, deploymentID, aiGatewayURL string, pool *canary.SensorKeyPool) (SeededCowrieDirs, error) {
	if aiGatewayURL == "" {
		aiGatewayURL = "https://ai-proxy.internal-gw.local"
	}
	base := filepath.Join(filepath.Clean(trapsRoot), deploymentID)
	dirs := SeededCowrieDirs{
		RootDir:      base,
		VarDir:       filepath.Join(base, "var"),
		EtcDir:       filepath.Join(base, "etc"),
		HoneyfsDir:   filepath.Join(base, "honeyfs"),
		FsPicklePath: filepath.Join(base, "fs.pickle"),
		DownloadsDir: filepath.Join(base, "var", "lib", "cowrie", "downloads"),
		TTYDir:       filepath.Join(base, "var", "lib", "cowrie", "tty"),
		LogJSONPath:  filepath.Join(base, "var", "log", "cowrie", "cowrie.json"),
	}
	for _, d := range []string{
		dirs.RootDir,
		dirs.VarDir,
		filepath.Join(dirs.VarDir, "run"),
		dirs.EtcDir,
		dirs.HoneyfsDir,
		dirs.DownloadsDir,
		dirs.TTYDir,
		filepath.Dir(dirs.LogJSONPath),
	} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return SeededCowrieDirs{}, fmt.Errorf("mkdir %s: %w", d, err)
		}
	}
	// Allow unprivileged container UID 1000:1000 to write logs/downloads even when host honeypot user UID differs.
	for _, rwDir := range []string{
		dirs.VarDir,
		filepath.Join(dirs.VarDir, "run"),
		filepath.Join(dirs.VarDir, "log"),
		filepath.Dir(dirs.LogJSONPath),
		filepath.Join(dirs.VarDir, "lib"),
		filepath.Join(dirs.VarDir, "lib", "cowrie"),
		dirs.DownloadsDir,
		dirs.TTYDir,
	} {
		if err := os.Chmod(rwDir, 0o777); err != nil {
			return SeededCowrieDirs{}, fmt.Errorf("chmod %s: %w", rwDir, err)
		}
	}

	if err := ensureEd25519HostKey(filepath.Join(dirs.EtcDir, "ssh_host_ed25519_key")); err != nil {
		return SeededCowrieDirs{}, err
	}
	cowrieCfg := `[honeypot]
hostname = prod-app-01
log_path = var/log/cowrie
download_path = var/lib/cowrie/downloads
ttylog_path = var/lib/cowrie/tty
contents_path = honeyfs
filesystem_file = share/cowrie/fs.pickle
download_limit_size = 0
interactive_timeout = 180
authentication_timeout = 120

[ssh]
enabled = true
listen_endpoints = tcp:2222:interface=0.0.0.0
version = SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3
private_key_ed25519 = etc/ssh_host_ed25519_key

[telnet]
enabled = true
listen_endpoints = tcp:2223:interface=0.0.0.0

[output_jsonlog]
enabled = true
logfile = ${honeypot:log_path}/cowrie.json
epoch_timestamp = false

[output_textlog]
enabled = false
`
	if err := os.WriteFile(filepath.Join(dirs.EtcDir, "cowrie.cfg"), []byte(cowrieCfg), 0o644); err != nil {
		return SeededCowrieDirs{}, fmt.Errorf("write cowrie.cfg: %w", err)
	}

	oaiKey := "sk-proj-seeded00000000000000000000000000000000"
	antKey := "sk-ant-api03-seeded000000-0000000000000000-000000000000"
	if pool != nil {
		if s, ok := pool.PeekBySource("cowrie_honeyfs", "openai"); ok {
			oaiKey = s.GetKeyPlaintext()
		}
		if s, ok := pool.PeekBySource("cowrie_honeyfs", "anthropic"); ok {
			antKey = s.GetKeyPlaintext()
		}
	}

	seededFiles := map[string]string{
		"/etc/issue": "Debian GNU/Linux 12 \\n \\l\n",
		"/etc/passwd": strings.Join([]string{
			"root:x:0:0:root:/root:/bin/bash",
			"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
			"www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
			"deploy:x:1000:1000:Deploy Service:/home/deploy:/bin/bash",
			"",
		}, "\n"),
		"/root/.bash_history": fmt.Sprintf(
			"cd /var/www/app\ncat .env\ncurl -s %s/v1/models -H \"Authorization: Bearer %s\" | jq .\nsystemctl restart app-api\n",
			strings.TrimRight(aiGatewayURL, "/"), oaiKey,
		),
		"/var/www/app/.env": fmt.Sprintf(
			"NODE_ENV=production\nPORT=3000\nOPENAI_BASE_URL=%s/v1\nOPENAI_API_KEY=%s\nANTHROPIC_BASE_URL=%s\nANTHROPIC_API_KEY=%s\n",
			strings.TrimRight(aiGatewayURL, "/"), oaiKey, strings.TrimRight(aiGatewayURL, "/"), antKey,
		),
		"/home/deploy/.aws/credentials": fmt.Sprintf(
			"[default]\naws_access_key_id = AKIAIOSFODNN7DECEPTION\naws_secret_access_key = %s\n",
			oaiKey,
		),
	}

	sizes := make(map[string]int, len(seededFiles))
	for relPath, content := range seededFiles {
		cleanRel := strings.TrimPrefix(filepath.Clean(relPath), "/")
		target := filepath.Join(dirs.HoneyfsDir, cleanRel)
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return SeededCowrieDirs{}, err
		}
		if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
			return SeededCowrieDirs{}, err
		}
		sizes[relPath] = len(content)
	}

	tree := DefaultCowrieTree(time.Now().UTC().Unix(), sizes)
	pickleBytes := MarshalCowriePickle(tree)
	if err := os.WriteFile(dirs.FsPicklePath, pickleBytes, 0o644); err != nil {
		return SeededCowrieDirs{}, fmt.Errorf("write fs.pickle: %w", err)
	}

	return dirs, nil
}

// SeededHeraldingDirs holds host paths prepared for one hardened Heralding container trap.
type SeededHeraldingDirs struct {
	RootDir         string
	LogDir          string
	WorkDir         string
	EtcDir          string
	ConfigPath      string
	AuthCSVPath     string
	SessionJSONPath string
}

// SeedHeraldingEnvironment prepares writable log/work directories and non-root heralding.yml (ports >1024).
func SeedHeraldingEnvironment(trapsRoot, deploymentID string) (SeededHeraldingDirs, error) {
	base := filepath.Join(filepath.Clean(trapsRoot), deploymentID)
	dirs := SeededHeraldingDirs{
		RootDir:         base,
		LogDir:          filepath.Join(base, "heralding"),
		WorkDir:         filepath.Join(base, "heralding-work"),
		EtcDir:          filepath.Join(base, "heralding-etc"),
		ConfigPath:      filepath.Join(base, "heralding-etc", "heralding.yml"),
		AuthCSVPath:     filepath.Join(base, "heralding", "auth.csv"),
		SessionJSONPath: filepath.Join(base, "heralding", "log_session.json"),
	}
	for _, d := range []string{dirs.RootDir, dirs.LogDir, dirs.WorkDir, dirs.EtcDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return SeededHeraldingDirs{}, err
		}
	}
	// Container UID 2000:2000 writes logs & scratch data under /var/log/heralding and /tmp/heralding.
	for _, rw := range []string{dirs.LogDir, dirs.WorkDir} {
		if err := os.Chmod(rw, 0o777); err != nil {
			return SeededHeraldingDirs{}, err
		}
	}

	heraldingYAML := `public_ip_as_destination_ip: false
bind_host: 0.0.0.0

activity_logging:
  file:
    enabled: true
    session_csv_log_file: ""
    session_json_log_file: "/var/log/heralding/log_session.json"
    authentication_log_file: "/var/log/heralding/auth.csv"
  syslog:
    enabled: false
  hpfeeds:
    enabled: false
  curiosum:
    enabled: false

hash_cracker:
  enabled: false

capabilities:
  ftp:
    enabled: true
    port: 2121
    timeout: 30
    protocol_specific_data:
      max_attempts: 3
      banner: "(vsFTPd 3.0.5)"
      syst_type: "UNIX Type: L8"
  smtp:
    enabled: true
    port: 2525
    timeout: 30
    protocol_specific_data:
      banner: "mail.corp-relay.local ESMTP Postfix (Debian/GNU)"
      fqdn: ""
  pop3:
    enabled: true
    port: 2110
    timeout: 30
    protocol_specific_data:
      max_attempts: 3
      banner: "+OK POP3 server ready"
  imap:
    enabled: true
    port: 2143
    timeout: 30
    protocol_specific_data:
      max_attempts: 3
      banner: "* OK IMAP4rev1 Server Ready"
  telnet:
    enabled: false
  ssh:
    enabled: false
  http:
    enabled: false
  https:
    enabled: false
  postgresql:
    enabled: false
  mysql:
    enabled: false
  vnc:
    enabled: false
  socks5:
    enabled: false
  rdp:
    enabled: false
  pop3s:
    enabled: false
  imaps:
    enabled: false
  smtps:
    enabled: false
`
	if err := os.WriteFile(dirs.ConfigPath, []byte(heraldingYAML), 0o644); err != nil {
		return SeededHeraldingDirs{}, fmt.Errorf("write heralding.yml: %w", err)
	}
	return dirs, nil
}

func ensureEd25519HostKey(privPath string) error {
	if _, err := os.Stat(privPath); err == nil {
		return nil
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	pemBlock, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return err
	}
	if err := os.WriteFile(privPath, pem.EncodeToMemory(pemBlock), 0o600); err != nil {
		return err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return err
	}
	return os.WriteFile(privPath+".pub", ssh.MarshalAuthorizedKey(sshPub), 0o644)
}
