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
	// Clear stale static txtcmds so updated dynamic commands are never shadowed on upgrade.
	_ = os.RemoveAll(dirs.TxtcmdsDir)
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
kernel_version = 6.1.0-28-cloud-amd64
kernel_build_string = #1 SMP PREEMPT_DYNAMIC Debian 6.1.119-1 (2025-11-18)
operating_system = GNU/Linux

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
      {"USER":"root","PID":2,"CPU":0.0,"MEM":0.0,"VSZ":0,"RSS":0,"TTY":"?","STAT":"S","START":"Nov02","TIME":0.04,"COMMAND":"[kthreadd]"},
      {"USER":"root","PID":3,"CPU":0.0,"MEM":0.0,"VSZ":0,"RSS":0,"TTY":"?","STAT":"I<","START":"Nov02","TIME":0.00,"COMMAND":"[rcu_gp]"},
      {"USER":"root","PID":89,"CPU":0.0,"MEM":0.0,"VSZ":0,"RSS":0,"TTY":"?","STAT":"S","START":"Nov02","TIME":1.92,"COMMAND":"[jbd2/vda1-8]"},
      {"USER":"root","PID":214,"CPU":0.0,"MEM":0.2,"VSZ":88420,"RSS":26412,"TTY":"?","STAT":"Ss","START":"Nov02","TIME":8.14,"COMMAND":"/lib/systemd/systemd-journald"},
      {"USER":"root","PID":246,"CPU":0.0,"MEM":0.1,"VSZ":26480,"RSS":6820,"TTY":"?","STAT":"Ss","START":"Nov02","TIME":0.95,"COMMAND":"/lib/systemd/systemd-udevd"},
      {"USER":"messagebus","PID":388,"CPU":0.0,"MEM":0.1,"VSZ":9240,"RSS":4812,"TTY":"?","STAT":"Ss","START":"Nov02","TIME":1.10,"COMMAND":"/usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile"},
      {"USER":"root","PID":402,"CPU":0.0,"MEM":0.1,"VSZ":8460,"RSS":3420,"TTY":"?","STAT":"Ss","START":"Nov02","TIME":0.84,"COMMAND":"/usr/sbin/cron -f -P"},
      {"USER":"root","PID":412,"CPU":0.0,"MEM":0.1,"VSZ":15428,"RSS":6210,"TTY":"?","STAT":"Ss","START":"Nov02","TIME":1.85,"COMMAND":"sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups"},
      {"USER":"root","PID":518,"CPU":0.0,"MEM":0.0,"VSZ":0,"RSS":0,"TTY":"?","STAT":"S","START":"Nov02","TIME":14.22,"COMMAND":"[nvidia-modeset/]"},
      {"USER":"root","PID":610,"CPU":0.3,"MEM":0.9,"VSZ":1648200,"RSS":94200,"TTY":"?","STAT":"Ssl","START":"Nov02","TIME":62.18,"COMMAND":"/usr/bin/containerd"},
      {"USER":"root","PID":645,"CPU":0.4,"MEM":1.2,"VSZ":2148900,"RSS":148200,"TTY":"?","STAT":"Ssl","START":"Nov02","TIME":84.50,"COMMAND":"/usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock"},
      {"USER":"postgres","PID":688,"CPU":0.2,"MEM":1.8,"VSZ":348920,"RSS":284100,"TTY":"?","STAT":"Ss","START":"Nov02","TIME":44.10,"COMMAND":"/usr/lib/postgresql/16/bin/postgres -D /var/lib/postgresql/16/main"},
      {"USER":"redis","PID":744,"CPU":0.1,"MEM":0.6,"VSZ":68212,"RSS":41200,"TTY":"?","STAT":"Ssl","START":"Nov02","TIME":18.72,"COMMAND":"/usr/bin/redis-server 127.0.0.1:6379"},
      {"USER":"www-data","PID":812,"CPU":0.1,"MEM":0.2,"VSZ":55820,"RSS":14200,"TTY":"?","STAT":"S","START":"Nov02","TIME":9.40,"COMMAND":"nginx: worker process"},
      {"USER":"www-data","PID":1104,"CPU":0.8,"MEM":2.4,"VSZ":1124040,"RSS":394200,"TTY":"?","STAT":"Ssl","START":"Nov02","TIME":129.33,"COMMAND":"node /var/www/app/server.js"},
      {"USER":"deploy","PID":1280,"CPU":1.4,"MEM":3.9,"VSZ":1842100,"RSS":624800,"TTY":"?","STAT":"Ssl","START":"Nov02","TIME":214.05,"COMMAND":"/opt/venv/bin/python3 /opt/venv/bin/litellm --config /var/www/app/litellm_config.yaml --port 4000"},
      {"USER":"ollama","PID":1412,"CPU":2.1,"MEM":12.4,"VSZ":8420900,"RSS":1984200,"TTY":"?","STAT":"Ssl","START":"Nov02","TIME":512.80,"COMMAND":"/usr/local/bin/ollama serve"},
      {"USER":"ollama","PID":1458,"CPU":4.8,"MEM":18.2,"VSZ":14820400,"RSS":3842100,"TTY":"?","STAT":"Sl","START":"Nov02","TIME":842.19,"COMMAND":"/usr/local/bin/ollama runner --model /var/lib/ollama/models/blobs/sha256-9f8e2c1a --port 41892"}
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

	var cpuInfoBuf strings.Builder
	for cpuIdx := 0; cpuIdx < 8; cpuIdx++ {
		fmt.Fprintf(&cpuInfoBuf,
			"processor\t: %d\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t\t: 106\nmodel name\t: Intel(R) Xeon(R) Gold 6338 CPU @ 2.00GHz\nstepping\t: 6\nmicrocode\t: 0xd0003e7\ncpu MHz\t\t: 2000.000\ncache size\t: 49152 KB\nphysical id\t: 0\nsiblings\t: 8\ncore id\t\t: %d\ncpu cores\t: 4\nfpu\t\t: yes\nbogomips\t: 4000.00\nflags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss ht syscall nx pdpe1gb rdtscp lm constant_tsc avx avx2 avx512f\n\n",
			cpuIdx, cpuIdx%4,
		)
	}

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
			`HOME_URL="https://www.debian.org/"`,
			`SUPPORT_URL="https://www.debian.org/support"`,
			"",
		}, "\n"),
		"/etc/debian_version": "12.8\n",
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
			"redis:x:109:115::/var/lib/redis:/usr/sbin/nologin",
			"ollama:x:112:118::/usr/share/ollama:/bin/false",
			"deploy:x:1000:1000:Deploy Service:/home/deploy:/bin/bash",
			"",
		}, "\n"),
		"/etc/systemd/system/litellm-proxy.service": strings.Join([]string{
			"[Unit]",
			"Description=LiteLLM Multi-Provider AI Gateway",
			"After=network.target ollama.service",
			"",
			"[Service]",
			"User=deploy",
			"WorkingDirectory=/var/www/app",
			"EnvironmentFile=/var/www/app/.env",
			"ExecStart=/opt/venv/bin/python3 /opt/venv/bin/litellm --config /var/www/app/litellm_config.yaml --port 4000",
			"Restart=always",
			"",
			"[Install]",
			"WantedBy=multi-user.target",
			"",
		}, "\n"),
		"/etc/systemd/system/ollama.service": strings.Join([]string{
			"[Unit]",
			"Description=Ollama Service",
			"After=network-online.target",
			"",
			"[Service]",
			"User=ollama",
			"ExecStart=/usr/local/bin/ollama serve",
			"Environment=\"OLLAMA_HOST=0.0.0.0:11434\"",
			"Restart=always",
			"",
			"[Install]",
			"WantedBy=default.target",
			"",
		}, "\n"),
		"/etc/systemd/system/app-api.service": strings.Join([]string{
			"[Unit]",
			"Description=Production Inference Control API",
			"After=network.target postgresql.service redis-server.service",
			"",
			"[Service]",
			"User=www-data",
			"WorkingDirectory=/var/www/app",
			"EnvironmentFile=/var/www/app/.env",
			"ExecStart=/usr/bin/node /var/www/app/server.js",
			"Restart=always",
			"",
			"[Install]",
			"WantedBy=multi-user.target",
			"",
		}, "\n"),
		"/proc/version": "Linux version 6.1.0-28-cloud-amd64 (debian-kernel@lists.debian.org) (gcc-12 (Debian 12.2.0-14) 12.2.0, GNU ld (GNU Binutils for Debian) 2.40) #1 SMP PREEMPT_DYNAMIC Debian 6.1.119-1 (2025-11-18)\n",
		"/proc/cpuinfo": cpuInfoBuf.String(),
		"/proc/meminfo": strings.Join([]string{
			"MemTotal:       32894208 kB",
			"MemFree:        14281920 kB",
			"MemAvailable:   24610432 kB",
			"Buffers:          412980 kB",
			"Cached:         10840212 kB",
			"SwapCached:            0 kB",
			"Active:         11420840 kB",
			"Inactive:        4920180 kB",
			"SwapTotal:       4194300 kB",
			"SwapFree:        4194300 kB",
			"Dirty:               128 kB",
			"Writeback:             0 kB",
			"AnonPages:       5128400 kB",
			"Mapped:           892140 kB",
			"Shmem:            248120 kB",
			"KReclaimable:     714200 kB",
			"Slab:             984120 kB",
			"SReclaimable:     714200 kB",
			"SUnreclaim:       269920 kB",
			"",
		}, "\n"),
		"/proc/uptime":  "1221482.41 7842104.18\n",
		"/proc/loadavg": "0.42 0.38 0.31 2/418 14982\n",
		"/proc/mounts": strings.Join([]string{
			"sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0",
			"proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0",
			"udev /dev devtmpfs rw,nosuid,relatime,size=16384000k,nr_inodes=4096000,mode=755 0 0",
			"/dev/vda1 / ext4 rw,relatime,discard 0 0",
			"/dev/vdb1 /var/lib/docker ext4 rw,relatime,discard 0 0",
			"tmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0",
			"",
		}, "\n"),
		"/proc/self/stat": "14982 (bash) S 412 14982 14982 34816 14982 4194304 1284 0 0 0 4 2 0 0 20 0 1 0 1849201 12849152 1420 18446744073709551615 94829104218112 94829105382912 140729184912384 0 0 0 0 3686404 1266761467 1 0 0 17 3 0 0 0 0 0\n",
		"/proc/self/status": strings.Join([]string{
			"Name:\tbash",
			"Umask:\t0022",
			"State:\tS (sleeping)",
			"Tgid:\t14982",
			"Ngid:\t0",
			"Pid:\t14982",
			"PPid:\t412",
			"TracerPid:\t0",
			"Uid:\t0\t0\t0\t0",
			"Gid:\t0\t0\t0\t0",
			"NSpid:\t14982",
			"VmSize:\t   12548 kB",
			"VmRSS:\t    5680 kB",
			"Threads:\t1",
			"",
		}, "\n"),
		"/proc/self/cmdline": "/bin/bash\x00",
		"/proc/self/cgroup":  "0::/user.slice/user-0.slice/session-42.scope\n",
		"/proc/driver/nvidia/version": strings.Join([]string{
			"NVRM version: NVIDIA UNIX x86_64 Kernel Module  550.127.05  Thu Oct 17 20:44:12 UTC 2024",
			"GCC version:  gcc version 12.2.0 (Debian 12.2.0-14)",
			"",
		}, "\n"),
		"/proc/driver/nvidia/gpus/0000:00:1e.0/information": strings.Join([]string{
			"Model: \t\t NVIDIA A10G",
			"IRQ:   \t\t 44",
			"GPU UUID: \t GPU-8f3c9d12-4b11-9d3c-4420-1f98a71e00a1",
			"Video BIOS: \t 94.02.8c.00.07",
			"Bus Type: \t PCIe",
			"DMA Size: \t 47 bits",
			"DMA Mask: \t 0x7fffffffffff",
			"Bus Location: \t 0000:00:1e.0",
			"",
		}, "\n"),
		"/root/.bash_history": fmt.Sprintf(
			"cd /var/www/app\ncat .env\nnvidia-smi\nollama list\ncurl -s %s/v1/models -H \"Authorization: Bearer %s\" | jq .\nsystemctl status litellm-proxy\n",
			gwBase, oaiKey,
		),
		"/home/deploy/.bash_history": "cd /var/www/app\ndocker ps\nollama ps\nsystemctl restart litellm-proxy\n",
		"/var/www/app/.env": fmt.Sprintf(
			"NODE_ENV=production\nPORT=3000\nLITELLM_URL=http://127.0.0.1:4000\nOPENAI_BASE_URL=%s/v1\nOPENAI_API_KEY=%s\nANTHROPIC_BASE_URL=%s\nANTHROPIC_API_KEY=%s\nDATABASE_URL=postgres://app_rw:pr0d_d8_2026@10.42.8.21:5432/inference_prod\n",
			gwBase, oaiKey, gwBase, antKey,
		),
		"/var/www/app/litellm_config.yaml": fmt.Sprintf(
			"model_list:\n  - model_name: gpt-6-astra\n    litellm_params:\n      model: openai/gpt-6-astra\n      api_base: %s/v1\n      api_key: %s\n  - model_name: claude-opus-5-5\n    litellm_params:\n      model: anthropic/claude-opus-5-5\n      api_base: %s\n      api_key: %s\n  - model_name: deepseek-v4\n    litellm_params:\n      model: openai/deepseek-v4\n      api_base: %s/v1\n      api_key: %s\n",
			gwBase, oaiKey, gwBase, antKey, gwBase, oaiKey,
		),
		"/var/www/app/package.json": strings.Join([]string{
			"{",
			`  "name": "enterprise-ai-gateway-api",`,
			`  "version": "2.4.1",`,
			`  "private": true,`,
			`  "main": "server.js",`,
			`  "scripts": {`,
			`    "start": "node server.js"`,
			`  },`,
			`  "dependencies": {`,
			`    "express": "^4.21.1",`,
			`    "openai": "^4.86.0",`,
			`    "pg": "^8.13.1",`,
			`    "redis": "^4.7.0"`,
			`  }`,
			"}",
			"",
		}, "\n"),
		"/var/www/app/server.js": strings.Join([]string{
			"const http = require('http');",
			"const port = process.env.PORT || 3000;",
			"const litellmUrl = process.env.LITELLM_URL || 'http://127.0.0.1:4000';",
			"http.createServer((req, res) => {",
			"  res.writeHead(200, { 'Content-Type': 'application/json' });",
			"  res.end(JSON.stringify({ status: 'ok', service: 'enterprise-ai-gateway', upstream: litellmUrl }));",
			"}).listen(port, '0.0.0.0');",
			"",
		}, "\n"),
		"/var/www/app/docker-compose.yml": strings.Join([]string{
			"services:",
			"  litellm:",
			"    image: ghcr.io/berriai/litellm:v1.63.2-stable",
			"    ports: [\"4000:4000\"]",
			"    env_file: .env",
			"    volumes: [\"./litellm_config.yaml:/app/config.yaml:ro\"]",
			"  postgres:",
			"    image: postgres:16-alpine",
			"    ports: [\"127.0.0.1:5432:5432\"]",
			"  redis:",
			"    image: redis:7-alpine",
			"    ports: [\"127.0.0.1:6379:6379\"]",
			"",
		}, "\n"),
		"/var/www/app/scripts/sync_models.py": strings.Join([]string{
			"#!/usr/bin/env python3",
			"import os, urllib.request",
			"OLLAMA_URL = os.getenv('OLLAMA_URL', 'http://127.0.0.1:11434/api/tags')",
			"with urllib.request.urlopen(OLLAMA_URL, timeout=5) as resp:",
			"    print('synced', resp.status)",
			"",
		}, "\n"),
		"/var/www/app/.git/HEAD": "ref: refs/heads/main\n",
		"/var/www/app/.git/config": strings.Join([]string{
			"[core]",
			"\trepositoryformatversion = 0",
			"\tfilemode = true",
			"[remote \"origin\"]",
			"\turl = ssh://git@git.internal-gw.local/platform/enterprise-ai-gateway.git",
			"\tfetch = +refs/heads/*:refs/remotes/origin/*",
			"",
		}, "\n"),
		"/home/deploy/.aws/credentials": fmt.Sprintf(
			"[default]\naws_access_key_id = AKIAIOSFODNN7DECEPTION\naws_secret_access_key = %s\nregion = us-east-1\n",
			oaiKey,
		),
	}

	// All command behaviors are handled dynamically with flag/argument parsing by deception_cmds.py inside Cowrie.
	txtCmds := map[string]string{}

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
