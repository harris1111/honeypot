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
	TxtcmdsDir   string
	FsPicklePath string
	DownloadsDir string
	TTYDir       string
	LogJSONPath  string
}

// SeedCowrieEnvironment creates writable var/, pre-generated etc/ SSH host keys,
// Canary-seeded honeyfs overlays, realistic txtcmds, and fs.pickle inside trapsRoot/<deploymentID>/.
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
		TxtcmdsDir:   filepath.Join(base, "txtcmds"),
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
		dirs.TxtcmdsDir,
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
hostname = prod-ai-gw-01
log_path = var/log/cowrie
download_path = var/lib/cowrie/downloads
ttylog_path = var/lib/cowrie/tty
contents_path = honeyfs
txtcmds_path = txtcmds
download_limit_size = 0
interactive_timeout = 180
authentication_timeout = 120
ttylog = true

[shell]
filesystem = /tmp/merged-fs.pickle
processes = etc/cmdoutput.json
arch = linux-x64-lsb

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
	cmdOutputJSON := `{
  "command": {
    "ps": [
      {"USER":"root","PID":1,"CPU":0.0,"MEM":0.3,"VSZ":168940,"RSS":11820,"TTY":"?","STAT":"Ss","START":"Nov02","TIME":12.40,"COMMAND":"/lib/systemd/systemd --system --deserialize 20"},
      {"USER":"root","PID":412,"CPU":0.0,"MEM":0.1,"VSZ":15428,"RSS":6210,"TTY":"?","STAT":"Ss","START":"Nov02","TIME":1.85,"COMMAND":"sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups"},
      {"USER":"postgres","PID":688,"CPU":0.2,"MEM":1.8,"VSZ":348920,"RSS":284100,"TTY":"?","STAT":"Ss","START":"Nov02","TIME":44.10,"COMMAND":"/usr/lib/postgresql/16/bin/postgres -D /var/lib/postgresql/16/main"},
      {"USER":"redis","PID":744,"CPU":0.1,"MEM":0.6,"VSZ":68212,"RSS":41200,"TTY":"?","STAT":"Ssl","START":"Nov02","TIME":18.72,"COMMAND":"/usr/bin/redis-server 127.0.0.1:6379"},
      {"USER":"www-data","PID":1104,"CPU":0.8,"MEM":2.4,"VSZ":1124040,"RSS":394200,"TTY":"?","STAT":"Ssl","START":"Nov02","TIME":129.33,"COMMAND":"node /var/www/app/server.js"},
      {"USER":"deploy","PID":1280,"CPU":1.4,"MEM":3.9,"VSZ":1842100,"RSS":624800,"TTY":"?","STAT":"Ssl","START":"Nov02","TIME":214.05,"COMMAND":"/opt/venv/bin/litellm --config /var/www/app/litellm_config.yaml --port 4000"},
      {"USER":"ollama","PID":1412,"CPU":2.1,"MEM":12.4,"VSZ":8420900,"RSS":1984200,"TTY":"?","STAT":"Ssl","START":"Nov02","TIME":512.80,"COMMAND":"/usr/local/bin/ollama serve"}
    ]
  }
}
`
	if err := os.WriteFile(filepath.Join(dirs.EtcDir, "cmdoutput.json"), []byte(cmdOutputJSON), 0o644); err != nil {
		return SeededCowrieDirs{}, fmt.Errorf("write cmdoutput.json: %w", err)
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
	gwBase := strings.TrimRight(aiGatewayURL, "/")

	seededFiles := map[string]string{
		"/etc/issue":    "Debian GNU/Linux 12 \\n \\l\n",
		"/etc/hostname": "prod-ai-gw-01\n",
		"/etc/os-release": strings.Join([]string{
			`PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"`,
			`NAME="Debian GNU/Linux"`,
			`VERSION_ID="12"`,
			`VERSION="12 (bookworm)"`,
			`VERSION_CODENAME=bookworm`,
			`ID=debian`,
			"",
		}, "\n"),
		"/etc/hosts": strings.Join([]string{
			"127.0.0.1\tlocalhost",
			"10.42.8.14\tprod-ai-gw-01 ai-proxy.internal-gw.local",
			"10.42.8.21\tpg-primary.internal",
			"10.42.8.22\tredis-cache.internal",
			"",
		}, "\n"),
		"/etc/crontab": strings.Join([]string{
			"SHELL=/bin/sh",
			"PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin",
			"*/5 * * * * deploy /opt/venv/bin/python3 /var/www/app/scripts/sync_models.py >/dev/null 2>&1",
			"",
		}, "\n"),
		"/etc/passwd": strings.Join([]string{
			"root:x:0:0:root:/root:/bin/bash",
			"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
			"www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
			"postgres:x:108:114:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash",
			"deploy:x:1000:1000:Deploy Service:/home/deploy:/bin/bash",
			"",
		}, "\n"),
		"/proc/version": "Linux version 6.1.0-26-cloud-amd64 (debian-kernel@lists.debian.org) (gcc-12 (Debian 12.2.0-14) 12.2.0, GNU ld (GNU Binutils for Debian) 2.40) #1 SMP PREEMPT_DYNAMIC Debian 6.1.112-1 (2024-09-30)\n",
		"/proc/cpuinfo": strings.Join([]string{
			"processor\t: 0",
			"vendor_id\t: GenuineIntel",
			"cpu family\t: 6",
			"model\t\t: 106",
			"model name\t: Intel(R) Xeon(R) Gold 6338 CPU @ 2.00GHz",
			"cpu MHz\t\t: 2000.000",
			"cache size\t: 49152 KB",
			"cpu cores\t: 8",
			"",
		}, "\n"),
		"/proc/meminfo": strings.Join([]string{
			"MemTotal:       32894208 kB",
			"MemFree:        14281920 kB",
			"MemAvailable:   24610432 kB",
			"Buffers:          412980 kB",
			"Cached:         10840212 kB",
			"SwapTotal:             0 kB",
			"",
		}, "\n"),
		"/root/.bash_history": fmt.Sprintf(
			"cd /var/www/app\ncat .env\nnvidia-smi\ncurl -s %s/v1/models -H \"Authorization: Bearer %s\" | jq .\nsystemctl status litellm-proxy\n",
			gwBase, oaiKey,
		),
		"/var/www/app/.env": fmt.Sprintf(
			"NODE_ENV=production\nPORT=3000\nLITELLM_URL=http://127.0.0.1:4000\nOPENAI_BASE_URL=%s/v1\nOPENAI_API_KEY=%s\nANTHROPIC_BASE_URL=%s\nANTHROPIC_API_KEY=%s\nDATABASE_URL=postgres://app_rw:pr0d_d8_2026@10.42.8.21:5432/inference_prod\n",
			gwBase, oaiKey, gwBase, antKey,
		),
		"/var/www/app/litellm_config.yaml": fmt.Sprintf(
			"model_list:\n  - model_name: gpt-4o\n    litellm_params:\n      model: openai/gpt-4o\n      api_base: %s/v1\n      api_key: %s\n  - model_name: claude-3-5-sonnet\n    litellm_params:\n      model: anthropic/claude-3-5-sonnet\n      api_base: %s\n      api_key: %s\n",
			gwBase, oaiKey, gwBase, antKey,
		),
		"/home/deploy/.aws/credentials": fmt.Sprintf(
			"[default]\naws_access_key_id = AKIAIOSFODNN7DECEPTION\naws_secret_access_key = %s\nregion = us-east-1\n",
			oaiKey,
		),
	}

	txtCmds := map[string]string{
		// Silent exit-0 stubs for Mirai/botnet/rootkit shell & immutable-bit checks observed in live attacks.
		"bin/enable":         "",
		"usr/bin/enable":     "",
		"bin/system":         "",
		"usr/bin/system":     "",
		"bin/shell":          "",
		"usr/bin/shell":      "",
		"bin/linuxshell":     "",
		"usr/bin/linuxshell": "",
		"bin/lockr":          "",
		"usr/bin/lockr":      "",
		"bin/chattr":         "",
		"usr/bin/chattr":     "",

		// Hardware, OS & GPU recon commands commonly run post-compromise.
		"usr/bin/nvidia-smi": strings.Join([]string{
			"+---------------------------------------------------------------------------------------+",
			"| NVIDIA-SMI 535.183.01             Driver Version: 535.183.01   CUDA Version: 12.2     |",
			"|-----------------------------------------+----------------------+----------------------+",
			"| GPU  Name                 Persistence-M | Bus-Id        Disp.A | Volatile Uncorr. ECC |",
			"| Fan  Temp   Perf          Pwr:Usage/Cap |         Memory-Usage | GPU-Util  Compute M. |",
			"|=========================================+======================+======================|",
			"|   0  NVIDIA A10G                    On  | 00000000:00:1E.0 Off |                    0 |",
			"|  0%   42C    P0              71W / 300W |  12840MiB / 24564MiB |     18%      Default |",
			"+-----------------------------------------+----------------------+----------------------+",
			"| Processes:                                                                            |",
			"|  GPU   GI   CI        PID   Type   Process name                            GPU Memory |",
			"|    0   N/A  N/A      1412      C   /usr/local/bin/ollama                      12824MiB |",
			"+---------------------------------------------------------------------------------------+",
			"",
		}, "\n"),
		"usr/bin/lscpu": strings.Join([]string{
			"Architecture:            x86_64",
			"  CPU op-mode(s):        32-bit, 64-bit",
			"  Address sizes:         46 bits physical, 48 bits virtual",
			"  Byte Order:            Little Endian",
			"CPU(s):                  8",
			"  On-line CPU(s) list:   0-7",
			"Vendor ID:               GenuineIntel",
			"  Model name:            Intel(R) Xeon(R) Gold 6338 CPU @ 2.00GHz",
			"Thread(s) per core:      2",
			"Core(s) per socket:      4",
			"Socket(s):               1",
			"L3 cache:                48 MiB",
			"Virtualization:          KVM",
			"",
		}, "\n"),
		"usr/bin/nproc": "8\n",
		"bin/df": strings.Join([]string{
			"Filesystem      Size  Used Avail Use% Mounted on",
			"udev             16G     0   16G   0% /dev",
			"tmpfs           3.2G  1.8M  3.2G   1% /run",
			"/dev/vda1       158G   42G  110G  28% /",
			"/dev/vdb1       492G  138G  330G  30% /var/lib/docker",
			"",
		}, "\n"),
		"usr/bin/df": strings.Join([]string{
			"Filesystem      Size  Used Avail Use% Mounted on",
			"udev             16G     0   16G   0% /dev",
			"tmpfs           3.2G  1.8M  3.2G   1% /run",
			"/dev/vda1       158G   42G  110G  28% /",
			"/dev/vdb1       492G  138G  330G  30% /var/lib/docker",
			"",
		}, "\n"),
		"bin/lsblk": strings.Join([]string{
			"NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINTS",
			"vda    254:0    0  160G  0 disk ",
			"└─vda1 254:1    0  160G  0 part /",
			"vdb    254:16   0  500G  0 disk ",
			"└─vdb1 254:17   0  500G  0 part /var/lib/docker",
			"",
		}, "\n"),
		"usr/bin/lsblk": strings.Join([]string{
			"NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINTS",
			"vda    254:0    0  160G  0 disk ",
			"└─vda1 254:1    0  160G  0 part /",
			"vdb    254:16   0  500G  0 disk ",
			"└─vdb1 254:17   0  500G  0 part /var/lib/docker",
			"",
		}, "\n"),
		"usr/bin/hostnamectl": strings.Join([]string{
			" Static hostname: prod-ai-gw-01",
			"       Icon name: computer-vm",
			"         Chassis: vm",
			"      Machine ID: 8a1f3c9d7e024b119d3c44201f98a71e",
			"  Virtualization: kvm",
			"Operating System: Debian GNU/Linux 12 (bookworm)",
			"          Kernel: Linux 6.1.0-26-cloud-amd64",
			"    Architecture: x86-64",
			"",
		}, "\n"),
		"usr/bin/lsb_release": strings.Join([]string{
			"Distributor ID:\tDebian",
			"Description:\tDebian GNU/Linux 12 (bookworm)",
			"Release:\t12",
			"Codename:\tbookworm",
			"",
		}, "\n"),
		"usr/bin/id":     "uid=0(root) gid=0(root) groups=0(root)\n",
		"usr/bin/whoami": "root\n",
		"usr/bin/w": strings.Join([]string{
			" 14:22:08 up 14 days,  3:11,  1 user,  load average: 0.42, 0.38, 0.31",
			"USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT",
			"root     pts/0    10.42.8.5        14:21    0.00s  0.04s  0.00s -bash",
			"",
		}, "\n"),
		"usr/bin/who": "root     pts/0        2026-11-16 14:21 (10.42.8.5)\n",
		"sbin/ip": strings.Join([]string{
			"1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default",
			"    inet 127.0.0.1/8 scope host lo",
			"2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq state UP group default",
			"    inet 10.42.8.14/24 brd 10.42.8.255 scope global eth0",
			"3: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default",
			"    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0",
			"",
		}, "\n"),
		"usr/sbin/ip": strings.Join([]string{
			"1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default",
			"    inet 127.0.0.1/8 scope host lo",
			"2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq state UP group default",
			"    inet 10.42.8.14/24 brd 10.42.8.255 scope global eth0",
			"3: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default",
			"    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0",
			"",
		}, "\n"),
		"usr/bin/ip": strings.Join([]string{
			"1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default",
			"    inet 127.0.0.1/8 scope host lo",
			"2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq state UP group default",
			"    inet 10.42.8.14/24 brd 10.42.8.255 scope global eth0",
			"3: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default",
			"    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0",
			"",
		}, "\n"),
		"usr/bin/ss": strings.Join([]string{
			"State   Recv-Q  Send-Q   Local Address:Port     Peer Address:Port  Process",
			"LISTEN  0       128      0.0.0.0:22             0.0.0.0:*          users:((\"sshd\",pid=412,fd=3))",
			"LISTEN  0       511      0.0.0.0:3000           0.0.0.0:*          users:((\"node\",pid=1104,fd=19))",
			"LISTEN  0       511      0.0.0.0:4000           0.0.0.0:*          users:((\"litellm\",pid=1280,fd=11))",
			"LISTEN  0       128      127.0.0.1:5432         0.0.0.0:*          users:((\"postgres\",pid=688,fd=6))",
			"LISTEN  0       511      127.0.0.1:6379         0.0.0.0:*          users:((\"redis-server\",pid=744,fd=6))",
			"LISTEN  0       128      0.0.0.0:11434          0.0.0.0:*          users:((\"ollama\",pid=1412,fd=8))",
			"",
		}, "\n"),
		"usr/bin/docker": strings.Join([]string{
			"CONTAINER ID   IMAGE                        COMMAND                  STATUS          PORTS                    NAMES",
			"c84f12e901a2   ghcr.io/berriai/litellm:v1   \"litellm --port 4000\"    Up 14 days      0.0.0.0:4000->4000/tcp   litellm-proxy",
			"91a03be218c4   postgres:16-alpine           \"docker-entrypoint.s…\"   Up 14 days      127.0.0.1:5432->5432/tcp postgres-prod",
			"442d89aa701f   redis:7-alpine               \"redis-server\"           Up 14 days      127.0.0.1:6379->6379/tcp redis-cache",
			"",
		}, "\n"),
		"usr/bin/kubectl": strings.Join([]string{
			"NAME                                  READY   STATUS    RESTARTS   AGE",
			"ai-gateway-7d9c6b4f8-x2kp9            1/1     Running   0          14d",
			"inference-worker-66c8b7f5d-m8n4q      1/1     Running   0          14d",
			"postgres-primary-0                    1/1     Running   0          31d",
			"",
		}, "\n"),
		"usr/bin/systemctl": strings.Join([]string{
			"  UNIT                    LOAD   ACTIVE SUB     DESCRIPTION",
			"  app-api.service         loaded active running Production Node API",
			"  docker.service          loaded active running Docker Application Container Engine",
			"  litellm-proxy.service   loaded active running LiteLLM Multi-Provider Gateway",
			"  ollama.service          loaded active running Ollama Local Model Runtime",
			"  postgresql.service      loaded active running PostgreSQL RDBMS",
			"  redis-server.service    loaded active running Advanced key-value store",
			"",
		}, "\n"),
		"usr/bin/node":      "v20.18.0\n",
		"usr/bin/npm":       "10.8.2\n",
		"usr/bin/php":       "PHP 8.2.24 (cli) (built: Oct 12 2024 14:11:02) (NTS)\nCopyright (c) The PHP Group\nZend Engine v4.2.24, Copyright (c) Zend Technologies\n",
		"usr/bin/psql":      "psql (PostgreSQL) 16.4 (Debian 16.4-1.pgdg120+1)\n",
		"usr/bin/mysql":     "mysql  Ver 8.0.39 for Linux on x86_64 (MySQL Community Server - GPL)\n",
		"usr/bin/redis-cli": "redis-cli 7.2.5\n",
		"usr/bin/git":       "git version 2.39.5\n",
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
	for relPath, content := range txtCmds {
		cleanRel := strings.TrimPrefix(filepath.Clean(relPath), "/")
		target := filepath.Join(dirs.TxtcmdsDir, cleanRel)
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return SeededCowrieDirs{}, err
		}
		if err := os.WriteFile(target, []byte(content), 0o755); err != nil {
			return SeededCowrieDirs{}, err
		}
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
