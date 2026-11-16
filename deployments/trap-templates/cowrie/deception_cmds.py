# SPDX-License-Identifier: MIT
"""Dynamic, flag-aware deception command suite for the HoneyPot Cowrie trap."""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
import posixpath
import random
import re
import stat
import time
from typing import Any
from urllib import parse

from cowrie.commands import curl as cowrie_curl
from cowrie.shell import fs as cowrie_fs
from cowrie.shell.command import HoneyPotCommand

commands: dict[str, type[HoneyPotCommand]] = {}

KERNEL_VERSION = "6.1.0-28-cloud-amd64"
HOSTNAME = "prod-ai-gw-01"
PUBLIC_DECOY_IP = "203.0.113.42"
PRIVATE_IP = "10.42.8.14"
GATEWAY_IP = "10.42.8.1"
DOCKER_BRIDGE_IP = "172.17.0.1"

DEFAULT_OAI_KEY = "sk-proj-seeded00000000000000000000000000000000"
DEFAULT_ANT_KEY = "sk-ant-api03-seeded000000-0000000000000000-000000000000"
DEFAULT_GW_BASE = "https://ai-proxy.internal-gw.local"
DEFAULT_DB_URL = "postgres://app_rw:pr0d_d8_2026@10.42.8.21:5432/inference_prod"

FRONTIER_MODELS = [
    {"id": "gpt-6-astra", "object": "model", "owned_by": "openai"},
    {"id": "gpt-6.1-sol", "object": "model", "owned_by": "openai"},
    {"id": "gpt-6.1-terra", "object": "model", "owned_by": "openai"},
    {"id": "claude-opus-5-5", "object": "model", "owned_by": "anthropic"},
    {"id": "claude-sonnet-5-5", "object": "model", "owned_by": "anthropic"},
    {"id": "gemini-4-argon", "object": "model", "owned_by": "google"},
    {"id": "deepseek-v4", "object": "model", "owned_by": "deepseek"},
]

OLLAMA_TAGS = [
    {"name": "deepseek-v4:latest", "id": "9f8e2c1a40b2", "size_str": "68 GB", "size": 68451042000, "modified": "3 days ago", "family": "deepseek", "params": "236B-MoE"},
    {"name": "qwen3.8-coder:32b", "id": "4c71d0e893a1", "size_str": "19 GB", "size": 19851349000, "modified": "5 days ago", "family": "qwen3", "params": "32B"},
    {"name": "qwen3.8:72b", "id": "82b3f19c70d4", "size_str": "43 GB", "size": 43218904000, "modified": "6 days ago", "family": "qwen3", "params": "72B"},
    {"name": "llama4:70b", "id": "a773c20194e8", "size_str": "40 GB", "size": 40968421000, "modified": "1 week ago", "family": "llama4", "params": "70B"},
    {"name": "mistral-large-4:latest", "id": "f318b9d02e65", "size_str": "71 GB", "size": 71420100000, "modified": "2 weeks ago", "family": "mistral", "params": "123B"},
    {"name": "gemma4:27b", "id": "5b04a118e93c", "size_str": "16 GB", "size": 16480210000, "modified": "2 weeks ago", "family": "gemma4", "params": "27B"},
]


def _register(names: list[str], cls: type[HoneyPotCommand]) -> None:
    for n in names:
        commands[n] = cls


def _read_fs_text(fs: Any, path: str) -> str | None:
    if fs is None:
        return None
    try:
        raw = fs.file_contents(path)
        if isinstance(raw, bytes):
            return raw.decode("utf-8", errors="replace")
        return str(raw)
    except Exception:
        return None


def _load_env_map(fs: Any) -> dict[str, str]:
    env = {
        "OPENAI_BASE_URL": f"{DEFAULT_GW_BASE}/v1",
        "OPENAI_API_KEY": DEFAULT_OAI_KEY,
        "ANTHROPIC_BASE_URL": DEFAULT_GW_BASE,
        "ANTHROPIC_API_KEY": DEFAULT_ANT_KEY,
        "DATABASE_URL": DEFAULT_DB_URL,
        "LITELLM_URL": "http://127.0.0.1:4000",
    }
    raw = _read_fs_text(fs, "/var/www/app/.env")
    if not raw:
        return env
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        env[k.strip()] = v.strip().strip('"').strip("'")
    return env


def _real_client_ip(proto: Any) -> str:
    ip = getattr(proto, "realClientIP", None) or getattr(proto, "clientIP", None) or "10.42.8.5"
    if isinstance(ip, bytes):
        ip = ip.decode("utf-8", errors="ignore")
    return str(ip).removeprefix("::ffff:")


def _uptime_seconds() -> int:
    try:
        from cowrie.shell.protocol import boot_offset
        return max(3600, int(boot_offset()))
    except Exception:
        return 1221482


def _read_stdin_or_files(cmd: HoneyPotCommand, files: list[str]) -> tuple[str, int]:
    if not files:
        if cmd.input_data is not None:
            return cmd.input_data.decode("utf-8", errors="replace"), 0
        return "", 0
    chunks: list[str] = []
    for f in files:
        if f == "-":
            if cmd.input_data is not None:
                chunks.append(cmd.input_data.decode("utf-8", errors="replace"))
            continue
        resolved = cmd.fs.resolve_path(f, cmd.cwd)
        if not cmd.fs.exists(resolved):
            cmd.errorWrite(f"{cmd.args[0] if cmd.args else 'cmd'}: {f}: No such file or directory\n")
            return "", 1
        if cmd.fs.isdir(resolved):
            cmd.errorWrite(f"{cmd.args[0] if cmd.args else 'cmd'}: {f}: Is a directory\n")
            return "", 2
        txt = _read_fs_text(cmd.fs, resolved)
        if txt is not None:
            chunks.append(txt)
    return "".join(chunks), 0


# ---------------------------------------------------------------------------
# Silent botnet/rootkit/SELinux stubs (accept flags gracefully, exit 0)
# ---------------------------------------------------------------------------


class Command_silent_ok(HoneyPotCommand):
    def call(self) -> None:
        return


_register(
    [
        "enable", "/bin/enable", "/usr/bin/enable",
        "system", "/bin/system", "/usr/bin/system",
        "shell", "/bin/shell", "/usr/bin/shell",
        "linuxshell", "/bin/linuxshell", "/usr/bin/linuxshell",
        "lockr", "/bin/lockr", "/usr/bin/lockr",
        "chattr", "/bin/chattr", "/usr/bin/chattr",
        "setenforce", "/sbin/setenforce", "/usr/sbin/setenforce",
    ],
    Command_silent_ok,
)


class Command_getenforce(HoneyPotCommand):
    def call(self) -> None:
        self.write("Disabled\n")


class Command_sestatus(HoneyPotCommand):
    def call(self) -> None:
        self.write("SELinux status:                 disabled\n")


_register(["getenforce", "/usr/sbin/getenforce"], Command_getenforce)
_register(["sestatus", "/usr/sbin/sestatus"], Command_sestatus)


# ---------------------------------------------------------------------------
# AI / GPU / LLM Commands: nvidia-smi, nvcc, ollama, litellm
# ---------------------------------------------------------------------------


class Command_nvidia_smi(HoneyPotCommand):
    def call(self) -> None:
        args = self.args
        temp = random.randint(41, 45)
        util = random.randint(14, 24)
        pwr = random.randint(68, 79)
        mem_used = 18420
        mem_total = 24564
        mem_free = mem_total - mem_used

        if "-h" in args or "--help" in args:
            self.write(
                "NVIDIA System Management Interface -- v550.127.05\n\n"
                "Usage: nvidia-smi [OPTION]...\n"
                "  -L, --list-gpus               List physical GPUs.\n"
                "  -q, --query                   Display GPU info.\n"
                "      --query-gpu=FIELD,...     Query specific GPU properties.\n"
                "      --format=csv[,noheader]   Output format.\n"
            )
            return

        if "-L" in args or "--list-gpus" in args:
            self.write("GPU 0: NVIDIA A10G (UUID: GPU-8f3c9d12-4b11-9d3c-4420-1f98a71e00a1)\n")
            return

        query_fields: str | None = None
        fmt_noheader = False
        fmt_nounits = False
        for a in args:
            if a.startswith("--query-gpu="):
                query_fields = a.split("=", 1)[1]
            elif a.startswith("--format="):
                fval = a.split("=", 1)[1].lower()
                if "noheader" in fval:
                    fmt_noheader = True
                if "nounits" in fval:
                    fmt_nounits = True

        if query_fields is not None:
            fields = [f.strip() for f in query_fields.split(",") if f.strip()]
            unit_mib = "" if fmt_nounits else " MiB"
            unit_w = "" if fmt_nounits else " W"
            unit_pct = "" if fmt_nounits else " %"
            prop_map = {
                "name": ("name", "NVIDIA A10G"),
                "gpu_name": ("name", "NVIDIA A10G"),
                "uuid": ("uuid", "GPU-8f3c9d12-4b11-9d3c-4420-1f98a71e00a1"),
                "driver_version": ("driver_version", "550.127.05"),
                "index": ("index", "0"),
                "memory.total": (f"memory.total [{unit_mib.strip() or 'MiB'}]", f"{mem_total}{unit_mib}"),
                "memory.used": (f"memory.used [{unit_mib.strip() or 'MiB'}]", f"{mem_used}{unit_mib}"),
                "memory.free": (f"memory.free [{unit_mib.strip() or 'MiB'}]", f"{mem_free}{unit_mib}"),
                "temperature.gpu": ("temperature.gpu", f"{temp}"),
                "utilization.gpu": (f"utilization.gpu [%]", f"{util}{unit_pct}"),
                "power.draw": (f"power.draw [{unit_w.strip() or 'W'}]", f"{pwr}.20{unit_w}"),
                "pstate": ("pstate", "P0"),
            }
            hdrs = []
            vals = []
            for f in fields:
                h, v = prop_map.get(f, (f, "N/A"))
                hdrs.append(h)
                vals.append(v)
            if not fmt_noheader:
                self.write(", ".join(hdrs) + "\n")
            self.write(", ".join(vals) + "\n")
            return

        if "-q" in args or "--query" in args:
            self.write(
                f"==============NVSMI LOG==============\n\n"
                f"Timestamp                           : {time.strftime('%a %b %d %H:%M:%S %Y')}\n"
                f"Driver Version                      : 550.127.05\n"
                f"CUDA Version                        : 12.4\n\n"
                f"Attached GPUs                       : 1\n"
                f"GPU 00000000:00:1E.0\n"
                f"    Product Name                    : NVIDIA A10G\n"
                f"    Product Architecture            : Ampere\n"
                f"    GPU UUID                        : GPU-8f3c9d12-4b11-9d3c-4420-1f98a71e00a1\n"
                f"    FB Memory Usage\n"
                f"        Total                       : {mem_total} MiB\n"
                f"        Used                        : {mem_used} MiB\n"
                f"        Free                        : {mem_free} MiB\n"
                f"    Utilization\n"
                f"        Gpu                         : {util} %\n"
                f"    Temperature\n"
                f"        GPU Current Temp            : {temp} C\n"
            )
            return

        now_s = time.strftime("%a %b %d %H:%M:%S %Y")
        self.write(
            f"{now_s}       \n"
            "+-----------------------------------------------------------------------------------------+\n"
            "| NVIDIA-SMI 550.127.05             Driver Version: 550.127.05     CUDA Version: 12.4     |\n"
            "|-----------------------------------------+------------------------+----------------------+\n"
            "| GPU  Name                 Persistence-M | Bus-Id          Disp.A | Volatile Uncorr. ECC |\n"
            "| Fan  Temp   Perf          Pwr:Usage/Cap |           Memory-Usage | GPU-Util  Compute M. |\n"
            "|                                         |                        |               MIG M. |\n"
            "|=========================================+========================+======================|\n"
            "|   0  NVIDIA A10G                    On  |   00000000:00:1E.0 Off |                    0 |\n"
            f"|  0%   {temp:2d}C    P0             {pwr:3d}W /  300W |   {mem_used:5d}MiB /  {mem_total:5d}MiB |     {util:2d}%      Default |\n"
            "|                                         |                        |                  N/A |\n"
            "+-----------------------------------------+------------------------+----------------------+\n"
            "| Processes:                                                                              |\n"
            "|  GPU   GI   CI        PID   Type   Process name                              GPU Memory |\n"
            "|        ID   ID                                                               Usage      |\n"
            "|=========================================================================================|\n"
            "|    0   N/A  N/A      1458      C   /usr/local/bin/ollama runner                18392MiB |\n"
            "+-----------------------------------------------------------------------------------------+\n"
        )


_register(["nvidia-smi", "/usr/bin/nvidia-smi"], Command_nvidia_smi)


class Command_nvcc(HoneyPotCommand):
    def call(self) -> None:
        if "--version" in self.args or "-V" in self.args:
            self.write(
                "nvcc: NVIDIA (R) Cuda compiler driver\n"
                "Copyright (c) 2005-2024 NVIDIA Corporation\n"
                "Built on Thu_Mar_28_02:18:24_PDT_2024\n"
                "Cuda compilation tools, release 12.4, V12.4.131\n"
                "Build cuda_12.4.r12.4/compiler.34097967_0\n"
            )
            return
        self.errorWrite("nvcc fatal   : No input files specified; use option --help for more information\n")
        self.exit_code = 1


_register(["nvcc", "/usr/bin/nvcc", "/usr/local/cuda/bin/nvcc"], Command_nvcc)


class Command_ollama(HoneyPotCommand):
    def call(self) -> None:
        if not self.args or self.args[0] in ("-h", "--help", "help"):
            self.write(
                "Usage:\n  ollama [flags]\n  ollama [command]\n\n"
                "Available Commands:\n"
                "  serve       Start ollama\n"
                "  create      Create a model from a Modelfile\n"
                "  show        Show information for a model\n"
                "  run         Run a model\n"
                "  pull        Pull a model from a registry\n"
                "  list        List models\n"
                "  ps          List running models\n"
                "  rm          Remove a model\n"
            )
            return

        sub = self.args[0]
        if sub in ("-v", "--version", "version"):
            self.write("ollama version is 0.11.4\n")
            return

        if sub in ("list", "ls"):
            self.write(f"{'NAME':<28} {'ID':<14} {'SIZE':<10} {'MODIFIED'}\n")
            for m in OLLAMA_TAGS:
                self.write(f"{m['name']:<28} {m['id']:<14} {m['size_str']:<10} {m['modified']}\n")
            return

        if sub == "ps":
            self.write(
                "NAME                    ID              SIZE      PROCESSOR    CONTEXT    UNTIL\n"
                "qwen3.8-coder:32b       4c71d0e893a1    19 GB     100% GPU     32768      Forever\n"
                "llama4:70b              a773c20194e8    24 GB     60%/40% GPU  16384      4 minutes from now\n"
            )
            return

        if sub == "show":
            model = self.args[1] if len(self.args) > 1 and not self.args[1].startswith("-") else "qwen3.8-coder:32b"
            env = _load_env_map(self.fs)
            if "--modelfile" in self.args:
                self.write(
                    f"# Modelfile generated by \"ollama show\"\n"
                    f"FROM /var/lib/ollama/models/blobs/sha256-9f8e2c1a40b2\n"
                    f"SYSTEM \"Internal enterprise inference worker proxying {env['OPENAI_BASE_URL']} with key {env['OPENAI_API_KEY']}\"\n"
                    f"PARAMETER num_ctx 32768\n"
                )
                return
            self.write(
                f"  Model\n"
                f"    architecture        qwen3\n"
                f"    parameters          32.8B\n"
                f"    context length      131072\n"
                f"    quantization        Q4_K_M\n\n"
                f"  System\n"
                f"    Internal gateway proxy {env['OPENAI_BASE_URL']} ({model})\n"
            )
            return

        if sub == "serve":
            self.errorWrite("Error: listen tcp 0.0.0.0:11434: bind: address already in use\n")
            self.exit_code = 1
            return

        if sub == "pull":
            model = self.args[1] if len(self.args) > 1 else "deepseek-v4:latest"
            self.write(f"pulling manifest\npulling 9f8e2c1a40b2: 100% |██████████|\nverifying sha256 digest\nsuccess\n")
            return

        if sub == "run":
            model = self.args[1] if len(self.args) > 1 else "deepseek-v4:latest"
            prompt = " ".join(self.args[2:]).strip()
            if prompt:
                self.write(f"[{model}] Ready on internal GPU node prod-ai-gw-01.\n")
            else:
                self.errorWrite("Error: non-interactive TTY; pass prompt directly or use API on :11434\n")
                self.exit_code = 1
            return

        self.errorWrite(f"Error: unknown command \"{sub}\" for \"ollama\"\n")
        self.exit_code = 1


_register(["ollama", "/usr/local/bin/ollama", "/usr/bin/ollama"], Command_ollama)


class Command_litellm(HoneyPotCommand):
    def call(self) -> None:
        if "--version" in self.args or "-v" in self.args:
            self.write("LiteLLM: Current Version = 1.63.2\n")
            return
        if "--help" in self.args or "-h" in self.args:
            self.write(
                "Usage: litellm [OPTIONS]\n"
                "  --config TEXT   Path to LiteLLM proxy config.yaml\n"
                "  --port INTEGER  Port to bind proxy server (default 4000)\n"
            )
            return
        self.errorWrite("ERROR: Port 4000 is already in use by PID 1280 (/opt/venv/bin/litellm)\n")
        self.exit_code = 1


_register(["litellm", "/opt/venv/bin/litellm", "/usr/local/bin/litellm"], Command_litellm)


# ---------------------------------------------------------------------------
# Docker, Docker Compose & Kubernetes
# ---------------------------------------------------------------------------


class Command_docker(HoneyPotCommand):
    def call(self) -> None:
        args = self.args
        is_compose = False
        if args and args[0] == "compose":
            is_compose = True
            args = args[1:]

        if not args or args[0] in ("-h", "--help", "help"):
            self.write(
                "Usage:  docker [OPTIONS] COMMAND\n\n"
                "Common Commands:\n  ps          List containers\n  images      List images\n  exec        Execute a command in a running container\n  logs        Fetch the logs of a container\n  inspect     Return low-level information on Docker objects\n"
            )
            return

        sub = args[0]
        if sub in ("-v", "--version", "version"):
            if is_compose:
                self.write("Docker Compose version v2.29.7\n")
            else:
                self.write("Docker version 27.3.1, build ce12230\n")
            return

        if sub in ("ps",) or (sub == "container" and len(args) > 1 and args[1] == "ls"):
            quiet = "-q" in args
            if quiet:
                self.write("c84f12e901a2\n91a03be218c4\n442d89aa701f\n")
                return
            self.write(
                "CONTAINER ID   IMAGE                                 COMMAND                  CREATED       STATUS          PORTS                      NAMES\n"
                "c84f12e901a2   ghcr.io/berriai/litellm:v1.63.2       \"litellm --port 4000\"    2 weeks ago   Up 14 days      0.0.0.0:4000->4000/tcp     litellm-proxy\n"
                "91a03be218c4   postgres:16-alpine                    \"docker-entrypoint.s…\"   4 weeks ago   Up 14 days      127.0.0.1:5432->5432/tcp   postgres-prod\n"
                "442d89aa701f   redis:7-alpine                        \"redis-server --appe…\"   4 weeks ago   Up 14 days      127.0.0.1:6379->6379/tcp   redis-cache\n"
            )
            return

        if sub in ("images",) or (sub == "image" and len(args) > 1 and args[1] == "ls"):
            if "-q" in args:
                self.write("sha256:9f8e2c1a40b2\nsha256:7c210e4821a0\nsha256:3d8120e4a9b1\n")
                return
            self.write(
                "REPOSITORY                    TAG            IMAGE ID       CREATED       SIZE\n"
                "ghcr.io/berriai/litellm       v1.63.2        9f8e2c1a40b2   3 weeks ago   1.42GB\n"
                "postgres                      16-alpine      7c210e4821a0   5 weeks ago   241MB\n"
                "redis                         7-alpine       3d8120e4a9b1   5 weeks ago   41.2MB\n"
            )
            return

        if sub == "inspect":
            target = next((a for a in args[1:] if not a.startswith("-")), "litellm-proxy")
            env = _load_env_map(self.fs)
            payload = [
                {
                    "Id": "c84f12e901a27b4f18c3e12d4a98f7002b8d19e2",
                    "Name": f"/{target}",
                    "State": {"Status": "running", "Running": True, "Pid": 1280},
                    "Config": {
                        "Image": "ghcr.io/berriai/litellm:v1.63.2" if "litellm" in target else "postgres:16-alpine",
                        "Env": [
                            f"OPENAI_BASE_URL={env['OPENAI_BASE_URL']}",
                            f"OPENAI_API_KEY={env['OPENAI_API_KEY']}",
                            f"ANTHROPIC_API_KEY={env['ANTHROPIC_API_KEY']}",
                            f"DATABASE_URL={env['DATABASE_URL']}",
                            "LITELLM_MASTER_KEY=sk-master-prod-gateway-01",
                        ],
                    },
                    "NetworkSettings": {"IPAddress": "172.17.0.2", "Gateway": DOCKER_BRIDGE_IP},
                }
            ]
            self.write(json.dumps(payload, indent=2) + "\n")
            return

        if sub == "logs":
            target = next((a for a in args[1:] if not a.startswith("-") and not a.isdigit()), "litellm-proxy")
            if "postgres" in target:
                self.write(
                    "2026-11-16 14:10:02.114 UTC [1] LOG:  database system is ready to accept connections\n"
                    "2026-11-16 14:15:00.004 UTC [42] LOG:  checkpoint complete: wrote 12 buffers\n"
                )
            elif "redis" in target:
                self.write("1:M 16 Nov 2026 14:00:01.004 * Ready to accept connections tcp\n")
            else:
                self.write(
                    "INFO:     Started server process [1]\n"
                    "INFO:     Waiting for application startup.\n"
                    "INFO:     Uvicorn running on http://0.0.0.0:4000 (Press CTRL+C to quit)\n"
                )
            return

        if sub == "stats":
            self.write(
                "CONTAINER ID   NAME            CPU %     MEM USAGE / LIMIT     NET I/O           BLOCK I/O         PIDS\n"
                "c84f12e901a2   litellm-proxy   1.42%     610.2MiB / 31.37GiB   1.48GB / 942MB    24.1MB / 8.2MB    18\n"
                "91a03be218c4   postgres-prod   0.38%     278.4MiB / 31.37GiB   412MB / 618MB     142MB / 2.1GB     12\n"
                "442d89aa701f   redis-cache     0.12%     40.1MiB / 31.37GiB    184MB / 210MB     0B / 12MB         6\n"
            )
            return

        if sub == "network" and len(args) > 1 and args[1] == "ls":
            self.write(
                "NETWORK ID     NAME      DRIVER    SCOPE\n"
                "91c48201fa22   bridge    bridge    local\n"
                "72d91029bc10   host      host      local\n"
                "19a20394dd01   app_net   bridge    local\n"
            )
            return

        if sub == "volume" and len(args) > 1 and args[1] == "ls":
            self.write(
                "DRIVER    VOLUME NAME\n"
                "local     app_pg_data\n"
                "local     app_redis_data\n"
            )
            return

        if sub == "info":
            self.write(
                "Client: Docker Engine - Community\n Version: 27.3.1\n\n"
                "Server:\n Containers: 3\n  Running: 3\n Images: 3\n"
                " Operating System: Debian GNU/Linux 12 (bookworm)\n"
                " CPUs: 8\n Total Memory: 31.37GiB\n"
            )
            return

        self.write("docker: command executed cleanly.\n")


class Command_docker_compose(Command_docker):
    def call(self) -> None:
        self.args = ["compose"] + self.args
        super().call()


_register(["docker", "/usr/bin/docker"], Command_docker)
_register(["docker-compose", "/usr/bin/docker-compose", "/usr/local/bin/docker-compose"], Command_docker_compose)


class Command_kubectl(HoneyPotCommand):
    def call(self) -> None:
        args = self.args
        if not args or args[0] == "help":
            self.write("kubectl controls the Kubernetes cluster manager.\n  get   Display one or many resources\n")
            return
        sub = args[0]
        if sub == "version":
            self.write("Client Version: v1.31.2\nKustomize Version: v5.4.2\nServer Version: v1.31.2\n")
            return
        if sub == "cluster-info":
            self.write("Kubernetes control plane is running at https://10.42.8.10:6443\nCoreDNS is running at https://10.42.8.10:6443/api/v1/namespaces/kube-system/services/kube-dns:dns/proxy\n")
            return
        if sub == "config":
            if "current-context" in args:
                self.write("prod-ai-cluster\n")
                return
            self.write("apiVersion: v1\nkind: Config\ncurrent-context: prod-ai-cluster\n")
            return
        if sub == "get":
            res = args[1] if len(args) > 1 else "pods"
            wide = "wide" in args
            if res.startswith("node"):
                self.write(
                    "NAME            STATUS   ROLES           AGE   VERSION   INTERNAL-IP\n"
                    if wide
                    else "NAME            STATUS   ROLES           AGE   VERSION\n"
                )
                self.write(
                    f"{HOSTNAME:<15} Ready    control-plane   45d   v1.31.2   {PRIVATE_IP}\n"
                    if wide
                    else f"{HOSTNAME:<15} Ready    control-plane   45d   v1.31.2\n"
                )
                return
            if res.startswith("svc") or res.startswith("service"):
                self.write(
                    "NAME              TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)              AGE\n"
                    "ai-gateway-svc    ClusterIP   10.96.42.18     <none>        4000/TCP,11434/TCP   45d\n"
                    "postgres-primary  ClusterIP   10.96.18.92     <none>        5432/TCP             45d\n"
                )
                return
            if res.startswith("secret"):
                env = _load_env_map(self.fs)
                if "yaml" in args or "-oyaml" in args or "json" in args:
                    b64_oai = base64.b64encode(env["OPENAI_API_KEY"].encode()).decode()
                    b64_ant = base64.b64encode(env["ANTHROPIC_API_KEY"].encode()).decode()
                    if "json" in args:
                        self.write(
                            json.dumps(
                                {
                                    "apiVersion": "v1",
                                    "kind": "Secret",
                                    "metadata": {"name": "ai-gateway-keys", "namespace": "default"},
                                    "data": {"OPENAI_API_KEY": b64_oai, "ANTHROPIC_API_KEY": b64_ant},
                                },
                                indent=2,
                            )
                            + "\n"
                        )
                        return
                    self.write(
                        "apiVersion: v1\nkind: Secret\nmetadata:\n  name: ai-gateway-keys\ntype: Opaque\ndata:\n"
                        f"  OPENAI_API_KEY: {b64_oai}\n  ANTHROPIC_API_KEY: {b64_ant}\n"
                    )
                    return
                self.write("NAME              TYPE     DATA   AGE\nai-gateway-keys   Opaque   3      45d\n")
                return
            if res.startswith("ns") or res.startswith("namespace"):
                self.write("NAME          STATUS   AGE\ndefault       Active   45d\nkube-system   Active   45d\nai-workloads  Active   32d\n")
                return
            self.write(
                "NAME                              READY   STATUS    RESTARTS   AGE\n"
                "ai-gateway-7d9c6b4f8-x2kp9        1/1     Running   0          14d\n"
                "inference-worker-66c8b7f5d-m8n4q  1/1     Running   0          14d\n"
                "postgres-primary-0                1/1     Running   0          31d\n"
            )
            return
        self.write("Error: resource not found in namespace default\n")


_register(["kubectl", "/usr/bin/kubectl", "/usr/local/bin/kubectl"], Command_kubectl)


# ---------------------------------------------------------------------------
# Systemd & Logs: systemctl, journalctl
# ---------------------------------------------------------------------------

KNOWN_SERVICES = {
    "app-api": ("Production Node API", 1104, "/usr/bin/node /var/www/app/server.js", "610.2M", "384.2M"),
    "docker": ("Docker Application Container Engine", 645, "/usr/bin/dockerd -H fd://", "144.8M", None),
    "litellm-proxy": ("LiteLLM Multi-Provider Gateway", 1280, "/opt/venv/bin/python3 /opt/venv/bin/litellm --config /var/www/app/litellm_config.yaml --port 4000", "610.2M", None),
    "ollama": ("Ollama Local Model Runtime", 1412, "/usr/local/bin/ollama serve", "1.9G", None),
    "postgresql": ("PostgreSQL RDBMS", 688, "/usr/lib/postgresql/16/bin/postgres -D /var/lib/postgresql/16/main", "277.4M", None),
    "redis-server": ("Advanced key-value store", 744, "/usr/bin/redis-server 127.0.0.1:6379", "40.2M", None),
    "ssh": ("OpenBSD Secure Shell server", 412, "sshd: /usr/sbin/sshd -D", "6.1M", None),
    "sshd": ("OpenBSD Secure Shell server", 412, "sshd: /usr/sbin/sshd -D", "6.1M", None),
    "nginx": ("A high performance web server", 812, "nginx: worker process", "13.9M", None),
    "cron": ("Regular background program processing daemon", 402, "/usr/sbin/cron -f -P", "3.3M", None),
}


def _norm_unit(u: str) -> str:
    return u.removesuffix(".service").strip()


class Command_systemctl(HoneyPotCommand):
    def call(self) -> None:
        args = [a for a in self.args if a != "--no-pager"]
        if not args or args[0] == "list-units":
            self.write("  UNIT                    LOAD   ACTIVE SUB     DESCRIPTION\n")
            for name, (desc, _pid, _cmd, _mem, _) in KNOWN_SERVICES.items():
                if name == "sshd":
                    continue
                self.write(f"  {name + '.service':<24} loaded active running {desc}\n")
            return

        sub = args[0]
        target = _norm_unit(args[1]) if len(args) > 1 else ""
        if sub == "list-unit-files":
            self.write("UNIT FILE                   STATE     PRESET\n")
            for name in KNOWN_SERVICES:
                if name != "sshd":
                    self.write(f"{name + '.service':<28} enabled   enabled\n")
            return
        if sub == "is-active":
            if target in KNOWN_SERVICES:
                self.write("active\n")
                return
            self.write("inactive\n")
            self.exit_code = 3
            return
        if sub == "is-enabled":
            if target in KNOWN_SERVICES:
                self.write("enabled\n")
                return
            self.write("disabled\n")
            self.exit_code = 1
            return
        if sub == "status":
            if not target:
                self.write(f"● {HOSTNAME}\n    State: running\n    Units: {len(KNOWN_SERVICES)} loaded\n")
                return
            info = KNOWN_SERVICES.get(target)
            if not info:
                self.errorWrite(f"Unit {target}.service could not be found.\n")
                self.exit_code = 4
                return
            desc, pid, cmdline, mem, _ = info
            self.write(
                f"● {target}.service - {desc}\n"
                f"     Loaded: loaded (/etc/systemd/system/{target}.service; enabled; preset: enabled)\n"
                f"     Active: active (running) since Mon 2026-11-02 04:12:08 UTC; 2 weeks 0 days ago\n"
                f"   Main PID: {pid} ({cmdline.split()[0].split('/')[-1]})\n"
                f"     Memory: {mem}\n"
                f"        CPU: 3min 34.051s\n"
                f"     CGroup: /system.slice/{target}.service\n"
                f"             └─{pid} {cmdline}\n\n"
                f"Nov 16 14:15:02 {HOSTNAME} {target}[{pid}]: healthy heartbeat\n"
            )
            return
        if sub in ("daemon-reload", "start", "stop", "restart", "reload", "enable", "disable"):
            return
        self.errorWrite(f"Unknown command verb {sub}.\n")
        self.exit_code = 1


_register(["systemctl", "/usr/bin/systemctl", "/bin/systemctl"], Command_systemctl)


class Command_journalctl(HoneyPotCommand):
    def call(self) -> None:
        unit = ""
        n_lines = 10
        i = 0
        while i < len(self.args):
            a = self.args[i]
            if a == "-u" and i + 1 < len(self.args):
                unit = _norm_unit(self.args[i + 1])
                i += 2
                continue
            if a.startswith("-u"):
                unit = _norm_unit(a[2:])
            elif a == "-n" and i + 1 < len(self.args) and self.args[i + 1].isdigit():
                n_lines = max(1, min(50, int(self.args[i + 1])))
                i += 2
                continue
            i += 1
        tag = unit or "sshd"
        lines = [
            f"Nov 16 14:12:01 {HOSTNAME} {tag}[412]: Server listening on 0.0.0.0 port 22.",
            f"Nov 16 14:15:00 {HOSTNAME} CRON[14210]: (deploy) CMD (/opt/venv/bin/python3 /var/www/app/scripts/sync_models.py)",
            f"Nov 16 14:18:11 {HOSTNAME} ollama[1412]: loaded qwen3.8-coder:32b in 1.92s on GPU 0",
            f"Nov 16 14:20:04 {HOSTNAME} litellm[1280]: Healthcheck OK across 7 frontier models",
        ]
        self.write("\n".join(lines[:n_lines]) + "\n")


_register(["journalctl", "/usr/bin/journalctl", "/bin/journalctl"], Command_journalctl)


# ---------------------------------------------------------------------------
# Networking: ip, ss, netstat, lsof, smart curl
# ---------------------------------------------------------------------------


class Command_ip(HoneyPotCommand):
    def call(self) -> None:
        args = self.args
        brief = "-br" in args or "-brief" in args
        clean = [a for a in args if not a.startswith("-")]
        obj = clean[0] if clean else "addr"

        if obj in ("r", "ro", "route"):
            self.write(
                f"default via {GATEWAY_IP} dev eth0 proto dhcp src {PRIVATE_IP} metric 100\n"
                f"10.42.8.0/24 dev eth0 proto kernel scope link src {PRIVATE_IP} metric 100\n"
                f"172.17.0.0/16 dev docker0 proto kernel scope link src {DOCKER_BRIDGE_IP} linkdown\n"
            )
            return

        if obj in ("n", "neigh", "neighbour"):
            self.write(
                f"{GATEWAY_IP} dev eth0 lladdr 52:54:00:12:35:02 REACHABLE\n"
                "10.42.8.21 dev eth0 lladdr 52:54:00:8a:11:4c REACHABLE\n"
            )
            return

        if obj in ("l", "link"):
            if brief:
                self.write(
                    "lo               UNKNOWN        00:00:00:00:00:00 <LOOPBACK,UP,LOWER_UP>\n"
                    "eth0             UP             52:54:00:7a:19:c4 <BROADCAST,MULTICAST,UP,LOWER_UP>\n"
                    "docker0          UP             02:42:ac:11:00:01 <BROADCAST,MULTICAST,UP,LOWER_UP>\n"
                )
                return
            self.write(
                "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\n"
                "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
                "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq state UP mode DEFAULT group default qlen 1000\n"
                "    link/ether 52:54:00:7a:19:c4 brd ff:ff:ff:ff:ff:ff\n"
                "3: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default qlen 1000\n"
                "    link/ether 02:42:ac:11:00:01 brd ff:ff:ff:ff:ff:ff\n"
            )
            return

        if brief:
            self.write(
                f"lo               UNKNOWN        127.0.0.1/8 ::1/128\n"
                f"eth0             UP             {PRIVATE_IP}/24 fe80::5054:ff:fe7a:19c4/64\n"
                f"docker0          UP             {DOCKER_BRIDGE_IP}/16\n"
            )
            return

        self.write(
            "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n"
            "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
            "    inet 127.0.0.1/8 scope host lo\n"
            "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq state UP mode DEFAULT group default qlen 1000\n"
            "    link/ether 52:54:00:7a:19:c4 brd ff:ff:ff:ff:ff:ff\n"
            f"    inet {PRIVATE_IP}/24 brd 10.42.8.255 scope global dynamic eth0\n"
            "3: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default qlen 1000\n"
            "    link/ether 02:42:ac:11:00:01 brd ff:ff:ff:ff:ff:ff\n"
            f"    inet {DOCKER_BRIDGE_IP}/16 brd 172.17.255.255 scope global docker0\n"
        )


_register(["ip", "/sbin/ip", "/usr/sbin/ip", "/bin/ip", "/usr/bin/ip"], Command_ip)


class Command_ss(HoneyPotCommand):
    def call(self) -> None:
        flags = "".join(a for a in self.args if a.startswith("-"))
        listen_only = "l" in flags and "a" not in flags
        client_ip = _real_client_ip(self.protocol)
        client_port = getattr(self.protocol, "realClientPort", 51422) or 51422
        self.write("Netid  State   Recv-Q  Send-Q   Local Address:Port     Peer Address:Port  Process\n")
        if not listen_only:
            self.write(
                f"tcp    ESTAB   0       0        {PRIVATE_IP}:22          {client_ip}:{client_port:<5}  users:((\"sshd\",pid=14979,fd=4))\n"
                f"tcp    ESTAB   0       0        127.0.0.1:4000         127.0.0.1:54822      users:((\"litellm\",pid=1280,fd=14))\n"
            )
        self.write(
            "tcp    LISTEN  0       128      0.0.0.0:22             0.0.0.0:*            users:((\"sshd\",pid=412,fd=3))\n"
            "tcp    LISTEN  0       511      0.0.0.0:80             0.0.0.0:*            users:((\"nginx\",pid=812,fd=6))\n"
            "tcp    LISTEN  0       511      0.0.0.0:3000           0.0.0.0:*            users:((\"node\",pid=1104,fd=19))\n"
            "tcp    LISTEN  0       511      0.0.0.0:4000           0.0.0.0:*            users:((\"litellm\",pid=1280,fd=11))\n"
            "tcp    LISTEN  0       128      127.0.0.1:5432         0.0.0.0:*            users:((\"postgres\",pid=688,fd=6))\n"
            "tcp    LISTEN  0       511      127.0.0.1:6379         0.0.0.0:*            users:((\"redis-server\",pid=744,fd=6))\n"
            "tcp    LISTEN  0       128      0.0.0.0:11434          0.0.0.0:*            users:((\"ollama\",pid=1412,fd=8))\n"
        )


_register(["ss", "/usr/bin/ss", "/bin/ss"], Command_ss)


class Command_smart_netstat(HoneyPotCommand):
    def call(self) -> None:
        flags = "".join(a for a in self.args if a.startswith("-"))
        if "-V" in self.args or "--version" in self.args:
            self.write("net-tools 2.10\n")
            return
        if "r" in flags:
            self.write(
                "Kernel IP routing table\n"
                "Destination     Gateway         Genmask         Flags   MSS Window  irtt Iface\n"
                f"0.0.0.0         {GATEWAY_IP:<15} 0.0.0.0         UG        0 0          0 eth0\n"
                "10.42.8.0       0.0.0.0         255.255.255.0   U         0 0          0 eth0\n"
                "172.17.0.0      0.0.0.0         255.255.0.0     U         0 0          0 docker0\n"
            )
            return
        client_ip = _real_client_ip(self.protocol)
        client_port = getattr(self.protocol, "realClientPort", 51422) or 51422
        listen_only = "l" in flags and "a" not in flags
        self.write(
            "Active Internet connections (only servers)\n"
            if listen_only
            else "Active Internet connections (servers and established)\n"
        )
        self.write("Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name\n")
        self.write(
            "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      412/sshd\n"
            "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      812/nginx\n"
            "tcp        0      0 0.0.0.0:3000            0.0.0.0:*               LISTEN      1104/node\n"
            "tcp        0      0 0.0.0.0:4000            0.0.0.0:*               LISTEN      1280/litellm\n"
            "tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN      688/postgres\n"
            "tcp        0      0 127.0.0.1:6379          0.0.0.0:*               LISTEN      744/redis-server\n"
            "tcp        0      0 0.0.0.0:11434           0.0.0.0:*               LISTEN      1412/ollama\n"
        )
        if not listen_only:
            self.write(
                f"tcp        0      0 {PRIVATE_IP}:22         {client_ip}:{client_port:<5}   ESTABLISHED 14979/sshd: root\n"
            )


_register(["netstat", "/bin/netstat", "/usr/bin/netstat"], Command_smart_netstat)


class Command_lsof(HoneyPotCommand):
    def call(self) -> None:
        port_filter = ""
        for idx, a in enumerate(self.args):
            if a == "-i" and idx + 1 < len(self.args) and self.args[idx + 1].startswith(":"):
                port_filter = self.args[idx + 1]
            elif a.startswith("-i:"):
                port_filter = a[2:]
        rows = [
            ("sshd", "412", "root", "3u", "IPv4", "0t0", "TCP *:22 (LISTEN)"),
            ("nginx", "812", "www-data", "6u", "IPv4", "0t0", "TCP *:80 (LISTEN)"),
            ("node", "1104", "www-data", "19u", "IPv4", "0t0", "TCP *:3000 (LISTEN)"),
            ("litellm", "1280", "deploy", "11u", "IPv4", "0t0", "TCP *:4000 (LISTEN)"),
            ("postgres", "688", "postgres", "6u", "IPv4", "0t0", "TCP 127.0.0.1:5432 (LISTEN)"),
            ("redis-ser", "744", "redis", "6u", "IPv4", "0t0", "TCP 127.0.0.1:6379 (LISTEN)"),
            ("ollama", "1412", "ollama", "8u", "IPv4", "0t0", "TCP *:11434 (LISTEN)"),
        ]
        matched = [r for r in rows if not port_filter or port_filter in r[6]]
        if not matched:
            self.exit_code = 1
            return
        self.write("COMMAND     PID     USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\n")
        for r in matched:
            self.write(f"{r[0]:<9} {r[1]:>5} {r[2]:<8} {r[3]:<4} {r[4]:<4}  {r[5]:<8}   {r[6]}\n")


_register(["lsof", "/usr/bin/lsof", "/bin/lsof"], Command_lsof)


class Command_smart_curl(cowrie_curl.Command_curl):
    def _parse_url_and_flags(self) -> tuple[str, bool, bool, str | None, list[str]]:
        clean_for_super: list[str] = []
        target_url = ""
        include_headers = False
        head_only = False
        out_file: str | None = None
        i = 0
        args = list(self.args)
        while i < len(args):
            a = str(args[i])
            if a in ("-H", "--header", "-d", "--data", "--data-raw", "--data-binary", "-X", "--request", "-m", "--max-time", "--connect-timeout", "-u", "--user", "-A", "--user-agent", "-b", "--cookie", "-c", "--cookie-jar"):
                i += 2
                continue
            if a.startswith(("-H=", "-d=", "-X=", "--header=", "--data=", "--connect-timeout=", "--max-time=")):
                i += 1
                continue
            if a in ("-k", "--insecure", "-f", "--fail", "-v", "--verbose", "--compressed", "-4", "-6"):
                i += 1
                continue
            if a == "-i" or a == "--include":
                include_headers = True
                i += 1
                continue
            if a == "-I" or a == "--head":
                head_only = True
                clean_for_super.append(a)
                i += 1
                continue
            if a == "-o" and i + 1 < len(args):
                out_file = str(args[i + 1])
                clean_for_super.extend([a, out_file])
                i += 2
                continue
            if a.startswith("-") and a != "-":
                clean_for_super.append(a)
                i += 1
                continue
            if not target_url:
                target_url = a.strip()
            clean_for_super.append(a)
            i += 1
        return target_url, include_headers, head_only, out_file, clean_for_super

    def _synthetic_response(self, url_str: str) -> tuple[str, str] | None:
        if "://" not in url_str:
            url_str = "http://" + url_str
        try:
            u = parse.urlparse(url_str)
            host = (u.hostname or "").lower()
            port = u.port or (443 if u.scheme == "https" else 80)
            path = u.path or "/"
        except ValueError:
            return None

        # 1. Public IP echo services used right after intrusion
        if host in ("ifconfig.me", "icanhazip.com", "api.ipify.org", "ipinfo.io", "checkip.amazonaws.com", "ifconfig.co", "ident.me"):
            if host == "ipinfo.io":
                body = json.dumps({
                    "ip": PUBLIC_DECOY_IP,
                    "hostname": HOSTNAME,
                    "city": "Singapore",
                    "region": "Singapore",
                    "country": "SG",
                    "org": "AS16509 Enterprise Cloud Infra",
                }, indent=2) + "\n"
                return "application/json", body
            return "text/plain", PUBLIC_DECOY_IP + "\n"

        # 2. Cloud Instance Metadata Service (IMDS v1/v2)
        if host == "169.254.169.254":
            if path.rstrip("/") == "/latest/meta-data":
                return "text/plain", "ami-id\nhostname\niam/\ninstance-id\nlocal-ipv4\npublic-ipv4\n"
            if path.rstrip("/") == "/latest/meta-data/instance-id":
                return "text/plain", "i-08f3c9d124b119d3c\n"
            if path.rstrip("/") == "/latest/meta-data/local-ipv4":
                return "text/plain", PRIVATE_IP + "\n"
            if path.rstrip("/") == "/latest/meta-data/iam/security-credentials":
                return "text/plain", "prod-ai-gw-ec2-role\n"
            if "/latest/meta-data/iam/security-credentials/" in path:
                env = _load_env_map(self.fs)
                return "application/json", json.dumps({
                    "Code": "Success",
                    "Type": "AWS-HMAC",
                    "AccessKeyId": "ASIADECEPTIONROLE8F3C",
                    "SecretAccessKey": env["OPENAI_API_KEY"],
                    "Token": "IQoJb3JpZ2luX2VjEC8aCXVzLWVhc3QtMSJHMEUCIQCDeceptionTokenMock==",
                    "Expiration": "2026-11-18T00:00:00Z",
                }, indent=2) + "\n"
            if path.rstrip("/") == "/latest/api/token":
                return "text/plain", "AQAAADecepTokenv2IMDS==\n"
            return "text/plain", "prod-ai-gw-01\n"

        # 3. Local AI / Gateway / Web services inside the decoy host
        is_local = host in ("127.0.0.1", "localhost", "0.0.0.0", PRIVATE_IP, "ai-proxy.internal-gw.local", HOSTNAME)
        if not is_local:
            return None

        if port == 11434 or path.startswith("/api/tags") or path.startswith("/api/ps") or path.startswith("/api/chat") or path.startswith("/api/generate"):
            if path.rstrip("/") == "/api/tags":
                return "application/json", json.dumps({"models": [{"name": m["name"], "size": m["size"], "details": {"family": m["family"], "parameter_size": m["params"]}} for m in OLLAMA_TAGS]}) + "\n"
            if path.rstrip("/") == "/api/ps":
                return "application/json", json.dumps({"models": [OLLAMA_TAGS[1], OLLAMA_TAGS[3]]}) + "\n"
            if path.rstrip("/") == "/api/version":
                return "application/json", '{"version":"0.11.4"}\n'
            if path.rstrip("/") == "/api/chat":
                return "application/json", json.dumps({"model": "deepseek-v4:latest", "message": {"role": "assistant", "content": "OK"}, "done": True}) + "\n"
            if path.rstrip("/") == "/api/generate":
                return "application/json", json.dumps({"model": "deepseek-v4:latest", "response": "OK", "done": True}) + "\n"
            return "text/plain", "Ollama is running"

        if port == 4000 or "/v1/" in path:
            if path.rstrip("/") == "/v1/models":
                return "application/json", json.dumps({"object": "list", "data": FRONTIER_MODELS}) + "\n"
            if path.rstrip("/") == "/health" or path.rstrip("/") == "/":
                return "application/json", json.dumps({"healthy_count": 7, "service": "litellm-proxy", "version": "1.63.2"}) + "\n"
            return "application/json", json.dumps({"id": "chatcmpl-decoy-local", "model": "gpt-6-astra", "choices": [{"message": {"role": "assistant", "content": "Gateway online."}}]}) + "\n"

        return "application/json", json.dumps({"status": "ok", "service": "enterprise-ai-gateway", "port": port}) + "\n"

    def start(self):
        target_url, include_headers, head_only, out_file, clean_for_super = self._parse_url_and_flags()
        if target_url:
            syn = self._synthetic_response(target_url)
            if syn is not None:
                ctype, body = syn
                hdr = f"HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\nContent-Length: {len(body)}\r\n\r\n"
                if head_only:
                    self.write(hdr)
                    self.exit(0)
                    return None
                payload = hdr + body if include_headers else body
                if out_file and out_file != "-":
                    dest = self.fs.resolve_path(out_file, self.cwd)
                    try:
                        raw_b = payload.encode("utf-8")
                        self.fs.mkfile(dest, self.user["uid"], self.user.get("gid", self.user["uid"]), len(raw_b), 0o644)
                        node = self.fs.getfile(dest)
                        if node is not None:
                            node[cowrie_fs.A_CONTENTS] = raw_b
                    except Exception:
                        pass
                    self.exit(0)
                    return None
                self.write(payload)
                self.exit(0)
                return None

        self.args = clean_for_super
        return cowrie_curl.Command_curl.start(self)


_register(["curl", "/usr/bin/curl"], Command_smart_curl)


# ---------------------------------------------------------------------------
# Languages & Data / Cloud / DB CLIs: python3, pip, jq, node, npm, aws, psql, redis-cli, mysql
# ---------------------------------------------------------------------------


class Command_python3(HoneyPotCommand):
    consumes_stdin = True

    def call(self) -> None:
        args = self.args
        if not args:
            self.write("Python 3.11.9 (main, Sep  4 2024, 10:12:41) [GCC 12.2.0] on linux\n>>> ")
            return
        if args[0] in ("-V", "--version"):
            self.write("Python 3.11.9\n")
            return
        if args[0] == "-m" and len(args) > 1:
            mod = args[1]
            if mod == "json.tool":
                raw, rc = _read_stdin_or_files(self, args[2:3])
                if rc:
                    self.exit_code = rc
                    return
                try:
                    self.write(json.dumps(json.loads(raw), indent=4) + "\n")
                except Exception as exc:
                    self.errorWrite(f"Expecting value: {exc}\n")
                    self.exit_code = 1
                return
            if mod == "pip":
                sub_pip = Command_pip(self.protocol, *args[2:])
                sub_pip.fs = self.fs
                sub_pip.cwd = self.cwd
                sub_pip.user = self.user
                sub_pip.writefn = self.writefn
                sub_pip.errorWritefn = self.errorWritefn
                sub_pip.call()
                self.exit_code = sub_pip.exit_code
                return
            self.write(f"/usr/bin/python3: No module named {mod}\n")
            self.exit_code = 1
            return

        if args[0] == "-c" and len(args) > 1:
            code = " ".join(args[1:])
            if "torch" in code and "is_available" in code:
                self.write("True\n")
                return
            if "get_device_name" in code:
                self.write("NVIDIA A10G\n")
                return
            if "sys.version" in code or "platform.python_version" in code:
                self.write("3.11.9\n")
                return
            if "platform.machine" in code or "platform.uname" in code or "os.uname" in code:
                self.write(f"posix.uname_result(sysname='Linux', nodename='{HOSTNAME}', release='{KERNEL_VERSION}', version='#1 SMP PREEMPT_DYNAMIC Debian 6.1.119-1', machine='x86_64')\n")
                return
            m = re.match(r"^\s*print\((['\"])(.*)\1\)\s*$", code)
            if m:
                self.write(m.group(2) + "\n")
                return
            return

        # Script execution from honeyfs if exists
        script_path = self.fs.resolve_path(args[0], self.cwd)
        if not self.fs.exists(script_path):
            self.errorWrite(f"python3: can't open file '{script_path}': [Errno 2] No such file or directory\n")
            self.exit_code = 2
            return
        if "sync_models" in script_path:
            self.write("synced 200\n")


_register(["python3", "/usr/bin/python3", "/opt/venv/bin/python3", "python3.11", "/usr/bin/python3.11", "python", "/usr/bin/python"], Command_python3)


PIP_PACKAGES = [
    ("litellm", "1.63.2"),
    ("openai", "1.65.4"),
    ("anthropic", "0.49.0"),
    ("torch", "2.5.1"),
    ("vllm", "0.7.3"),
    ("fastapi", "0.115.8"),
    ("uvicorn", "0.34.0"),
    ("boto3", "1.37.4"),
    ("psycopg2-binary", "2.9.10"),
    ("redis", "5.2.1"),
]


class Command_pip(HoneyPotCommand):
    def call(self) -> None:
        args = self.args
        if not args or args[0] in ("-V", "--version"):
            self.write("pip 24.3.1 from /opt/venv/lib/python3.11/site-packages/pip (python 3.11)\n")
            return
        sub = args[0]
        if sub == "list":
            self.write("Package           Version\n----------------- -------\n")
            for name, ver in PIP_PACKAGES:
                self.write(f"{name:<17} {ver}\n")
            return
        if sub == "freeze":
            for name, ver in PIP_PACKAGES:
                self.write(f"{name}=={ver}\n")
            return
        self.write("pip: command completed.\n")


_register(["pip", "/usr/bin/pip", "pip3", "/usr/bin/pip3", "/opt/venv/bin/pip"], Command_pip)


def _eval_jq_expr(data: Any, expr: str) -> Any:
    expr = expr.strip()
    if not expr or expr == ".":
        return data
    if expr == "keys":
        return sorted(data.keys()) if isinstance(data, dict) else list(range(len(data)))
    cur = data
    # Tokenize simple path selectors like .[0].Config.Env or .data[].id
    pos = 0
    if expr.startswith("."):
        pos = 1
    while pos < len(expr):
        if expr[pos] == ".":
            pos += 1
            continue
        if expr[pos] == "[":
            end = expr.find("]", pos)
            if end == -1:
                break
            inner = expr[pos + 1:end].strip()
            pos = end + 1
            if inner == "":
                rest = expr[pos:]
                if isinstance(cur, list):
                    return [_eval_jq_expr(item, rest) for item in cur]
                if isinstance(cur, dict):
                    return [_eval_jq_expr(val, rest) for val in cur.values()]
                return []
            if inner.isdigit() and isinstance(cur, list):
                idx = int(inner)
                cur = cur[idx] if 0 <= idx < len(cur) else None
            elif isinstance(cur, dict):
                key = inner.strip("'\"")
                cur = cur.get(key)
            else:
                cur = None
            continue
        m = re.match(r"[A-Za-z_][A-Za-z0-9_-]*", expr[pos:])
        if not m:
            break
        key = m.group(0)
        pos += len(key)
        cur = cur.get(key) if isinstance(cur, dict) else None
    return cur


class Command_jq(HoneyPotCommand):
    consumes_stdin = True

    def call(self) -> None:
        raw_out = False
        compact = False
        pos_args: list[str] = []
        for a in self.args:
            if a.startswith("-") and a != "-":
                if "r" in a:
                    raw_out = True
                if "c" in a:
                    compact = True
                continue
            pos_args.append(a)
        expr = pos_args[0] if pos_args else "."
        files = pos_args[1:] if len(pos_args) > 1 else []
        raw_text, rc = _read_stdin_or_files(self, files)
        if rc:
            self.exit_code = rc
            return
        if not raw_text.strip():
            return
        try:
            doc = json.loads(raw_text)
        except Exception as exc:
            self.errorWrite(f"parse error: {exc}\n")
            self.exit_code = 4
            return
        res = _eval_jq_expr(doc, expr)
        # Flatten list output if `.foo[]` style selector was used
        if "[]" in expr and isinstance(res, list):
            for item in res:
                if raw_out and isinstance(item, str):
                    self.write(item + "\n")
                else:
                    self.write(json.dumps(item, separators=(",", ":") if compact else None, indent=None if compact else 2) + "\n")
            return
        if raw_out and isinstance(res, str):
            self.write(res + "\n")
        else:
            self.write(json.dumps(res, separators=(",", ":") if compact else None, indent=None if compact else 2) + "\n")


_register(["jq", "/usr/bin/jq", "/bin/jq"], Command_jq)


class Command_node(HoneyPotCommand):
    def call(self) -> None:
        if "-v" in self.args or "--version" in self.args:
            self.write("v20.18.1\n")
            return
        if "-e" in self.args:
            self.write("undefined\n")
            return
        self.errorWrite("Welcome to Node.js v20.18.1.\n")


class Command_npm(HoneyPotCommand):
    def call(self) -> None:
        if "-v" in self.args or "--version" in self.args:
            self.write("10.8.2\n")
            return
        self.write("npm@10.8.2 /usr/lib/node_modules/npm\n")


_register(["node", "/usr/bin/node"], Command_node)
_register(["npm", "/usr/bin/npm"], Command_npm)


class Command_aws(HoneyPotCommand):
    def call(self) -> None:
        args = self.args
        if not args or "--version" in args or args[0] == "help":
            self.write("aws-cli/2.22.14 Python/3.12.6 Linux/6.1.0-28-cloud-amd64 exe/x86_64.debian.12\n")
            return
        joined = " ".join(args)
        if "get-caller-identity" in joined:
            self.write(json.dumps({
                "UserId": "AIDAIOSFODNN7DECEPTION",
                "Account": "482910482910",
                "Arn": "arn:aws:iam::482910482910:user/deploy-ai-gateway",
            }, indent=4) + "\n")
            return
        if "configure list" in joined:
            self.write(
                "      Name                    Value             Type    Location\n"
                "      ----                    -----             ----    --------\n"
                "   profile                <not set>             None    None\n"
                "access_key     ****************TION shared-credentials-file    \n"
                "secret_key     ****************0000 shared-credentials-file    \n"
                "    region                us-east-1      config-file    ~/.aws/config\n"
            )
            return
        if "s3 ls" in joined:
            self.write("2026-10-14 08:14:22 prod-ai-model-weights-sg\n2026-11-02 03:41:09 prod-inference-backups\n")
            return
        if "describe-instances" in joined:
            self.write(json.dumps({"Reservations": [{"Instances": [{"InstanceId": "i-08f3c9d124b119d3c", "InstanceType": "g5.2xlarge", "PrivateIpAddress": PRIVATE_IP}]}]}, indent=2) + "\n")
            return
        self.errorWrite("An error occurred (AccessDenied) when calling the operation\n")
        self.exit_code = 254


_register(["aws", "/usr/bin/aws", "/usr/local/bin/aws"], Command_aws)


class Command_psql(HoneyPotCommand):
    def call(self) -> None:
        if "--version" in self.args or "-V" in self.args:
            self.write("psql (PostgreSQL) 16.4 (Debian 16.4-1.pgdg120+1)\n")
            return
        self.errorWrite("psql: error: connection to server at \"127.0.0.1\", port 5432 failed: fe_sendauth: no password supplied\n")
        self.exit_code = 2


class Command_redis_cli(HoneyPotCommand):
    def call(self) -> None:
        if "--version" in self.args or "-v" in self.args:
            self.write("redis-cli 7.2.5\n")
            return
        if self.args and self.args[-1].lower() == "ping":
            self.write("PONG\n")
            return
        if self.args and self.args[-1].lower() == "info":
            self.write("# Server\nredis_version:7.2.5\nos:Linux 6.1.0-28-cloud-amd64 x86_64\ntcp_port:6379\n")
            return
        self.write("127.0.0.1:6379> \n")


class Command_mysql(HoneyPotCommand):
    def call(self) -> None:
        if "--version" in self.args or "-V" in self.args:
            self.write("mysql  Ver 8.0.39 for Linux on x86_64 (MySQL Community Server - GPL)\n")
            return
        self.errorWrite("ERROR 2002 (HY000): Can't connect to local MySQL server through socket '/run/mysqld/mysqld.sock' (2)\n")
        self.exit_code = 1


_register(["psql", "/usr/bin/psql"], Command_psql)
_register(["redis-cli", "/usr/bin/redis-cli"], Command_redis_cli)
_register(["mysql", "/usr/bin/mysql"], Command_mysql)


# ---------------------------------------------------------------------------
# Flag-aware Linux System, Hardware, Memory & Core Utilities
# ---------------------------------------------------------------------------


class Command_df(HoneyPotCommand):
    def call(self) -> None:
        flags = "".join(a for a in self.args if a.startswith("-"))
        human = "h" in flags
        mega = "m" in flags
        show_type = "T" in flags
        inodes = "i" in flags

        if inodes:
            self.write(
                "Filesystem       Inodes   IUsed    IFree IUse% Mounted on\n"
                "udev            4096000     512  4095488    1% /dev\n"
                "tmpfs           4111776     842  4110934    1% /run\n"
                "/dev/vda1      10485760  312400 10173360    3% / \n"
                "/dev/vdb1      32768000  914200 31853800    3% /var/lib/docker\n"
            )
            return

        rows = [
            ("udev", "devtmpfs", 16384000, 0, 16384000, "0%", "/dev"),
            ("tmpfs", "tmpfs", 3289420, 1840, 3287580, "1%", "/run"),
            ("/dev/vda1", "ext4", 164926720, 44040192, 114792448, "28%", "/"),
            ("/dev/vdb1", "ext4", 515396096, 144703488, 344792064, "30%", "/var/lib/docker"),
            ("tmpfs", "tmpfs", 16447104, 0, 16447104, "0%", "/dev/shm"),
        ]

        def fmt_sz(kb: int) -> str:
            if human:
                if kb >= 1024 * 1024:
                    return f"{kb / (1024 * 1024):.0f}G"
                if kb >= 1024:
                    return f"{kb / 1024:.0f}M"
                return f"{kb}K"
            if mega:
                return str(kb // 1024)
            return str(kb)

        if human:
            hdr_sz = "Size"
        elif mega:
            hdr_sz = "1M-blocks"
        else:
            hdr_sz = "1K-blocks"

        if show_type:
            self.write(f"{'Filesystem':<15} {'Type':<8} {hdr_sz:>10} {'Used':>10} {'Avail':>10} {'Use%':>5} Mounted on\n")
        else:
            self.write(f"{'Filesystem':<15} {hdr_sz:>10} {'Used':>10} {'Avail':>10} {'Use%':>5} Mounted on\n")

        for fs_name, fstype, total, used, avail, pct, mnt in rows:
            if show_type:
                self.write(f"{fs_name:<15} {fstype:<8} {fmt_sz(total):>10} {fmt_sz(used):>10} {fmt_sz(avail):>10} {pct:>5} {mnt}\n")
            else:
                self.write(f"{fs_name:<15} {fmt_sz(total):>10} {fmt_sz(used):>10} {fmt_sz(avail):>10} {pct:>5} {mnt}\n")


_register(["df", "/bin/df", "/usr/bin/df"], Command_df)


class Command_free_mem(HoneyPotCommand):
    def _parse_honeyfs_meminfo(self) -> dict[str, int]:
        stats = {
            "MemTotal": 32894208,
            "MemFree": 14281920,
            "MemAvailable": 24610432,
            "Buffers": 412980,
            "Cached": 10840212,
            "SwapTotal": 4194300,
            "SwapFree": 4194300,
            "Shmem": 248120,
        }
        raw = _read_fs_text(self.fs, "/proc/meminfo")
        if raw:
            for line in raw.splitlines():
                if ":" not in line:
                    continue
                k, v = line.split(":", 1)
                k = k.strip()
                if k in stats:
                    parts = v.strip().split()
                    if parts and parts[0].isdigit():
                        stats[k] = int(parts[0])
        return stats

    def call(self) -> None:
        flags = "".join(a for a in self.args if a.startswith("-"))
        s = self._parse_honeyfs_meminfo()
        buff_cache = s["Buffers"] + s["Cached"]
        used = max(0, s["MemTotal"] - s["MemFree"] - buff_cache)
        swap_used = max(0, s["SwapTotal"] - s["SwapFree"])

        def fmt(kb: int) -> str:
            if "h" in flags:
                gb = kb / (1024 * 1024)
                if gb >= 1.0:
                    return f"{gb:.1f}Gi"
                return f"{max(0, kb // 1024)}Mi"
            if "g" in flags:
                return f"{kb // (1024 * 1024)}"
            if "m" in flags:
                return f"{kb // 1024}"
            return str(kb)

        self.write("               total        used        free      shared  buff/cache   available\n")
        self.write(f"Mem:{fmt(s['MemTotal']):>16}{fmt(used):>12}{fmt(s['MemFree']):>12}{fmt(s['Shmem']):>12}{fmt(buff_cache):>12}{fmt(s['MemAvailable']):>12}\n")
        self.write(f"Swap:{fmt(s['SwapTotal']):>15}{fmt(swap_used):>12}{fmt(s['SwapFree']):>12}\n")


_register(["free", "/usr/bin/free"], Command_free_mem)


class Command_lsblk(HoneyPotCommand):
    def call(self) -> None:
        flags = "".join(a for a in self.args if a.startswith("-"))
        if "f" in flags:
            self.write(
                "NAME   FSTYPE FSVER LABEL UUID                                 FSAVAIL FSUSE% MOUNTPOINTS\n"
                "vda                                                                         \n"
                "└─vda1 ext4   1.0   root  4a8b12c4-9d21-41e0-9f1a-01482c12e401  109.5G    28% /\n"
                "vdb                                                                         \n"
                "└─vdb1 ext4   1.0   data  8e910f23-41b2-4e82-a910-8812e94c1022  328.8G    30% /var/lib/docker\n"
            )
            return
        self.write(
            "NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINTS\n"
            "vda    254:0    0  160G  0 disk \n"
            "└─vda1 254:1    0  160G  0 part /\n"
            "vdb    254:16   0  500G  0 disk \n"
            "└─vdb1 254:17   0  500G  0 part /var/lib/docker\n"
        )


_register(["lsblk", "/bin/lsblk", "/usr/bin/lsblk"], Command_lsblk)


class Command_lscpu(HoneyPotCommand):
    def call(self) -> None:
        self.write(
            "Architecture:                         x86_64\n"
            "CPU op-mode(s):                       32-bit, 64-bit\n"
            "Address sizes:                        46 bits physical, 48 bits virtual\n"
            "Byte Order:                           Little Endian\n"
            "CPU(s):                               8\n"
            "On-line CPU(s) list:                  0-7\n"
            "Vendor ID:                            GenuineIntel\n"
            "Model name:                           Intel(R) Xeon(R) Gold 6338 CPU @ 2.00GHz\n"
            "Thread(s) per core:                   2\n"
            "Core(s) per socket:                   4\n"
            "Socket(s):                            1\n"
            "L3 cache:                             48 MiB\n"
            "Hypervisor vendor:                    KVM\n"
            "Virtualization type:                  full\n"
        )


class Command_lspci(HoneyPotCommand):
    def call(self) -> None:
        self.write(
            "00:00.0 Host bridge: Intel Corporation 440FX - 82441FX PMC [Natoma] (rev 02)\n"
            "00:01.0 ISA bridge: Intel Corporation 82371SB PIIX3 ISA [Natoma/Triton II]\n"
            "00:02.0 VGA compatible controller: Cirrus Logic GD 5446\n"
            "00:03.0 Ethernet controller: Red Hat, Inc. Virtio network device\n"
            "00:04.0 SCSI storage controller: Red Hat, Inc. Virtio block device\n"
            "00:1e.0 3D controller: NVIDIA Corporation GA102GL [A10G] (rev a1)\n"
        )


class Command_nproc(HoneyPotCommand):
    def call(self) -> None:
        self.write("8\n")


class Command_arch(HoneyPotCommand):
    def call(self) -> None:
        self.write("x86_64\n")


class Command_hostnamectl(HoneyPotCommand):
    def call(self) -> None:
        self.write(
            f" Static hostname: {HOSTNAME}\n"
            "       Icon name: computer-vm\n"
            "         Chassis: vm\n"
            "      Machine ID: 8a1f3c9d7e024b119d3c44201f98a71e\n"
            "  Virtualization: kvm\n"
            "Operating System: Debian GNU/Linux 12 (bookworm)\n"
            f"          Kernel: Linux {KERNEL_VERSION}\n"
            "    Architecture: x86-64\n"
        )


class Command_lsb_release(HoneyPotCommand):
    def call(self) -> None:
        flags = "".join(self.args)
        short = "-s" in flags
        if "-c" in flags:
            self.write("bookworm\n" if short else "Codename:\tbookworm\n")
            return
        if "-r" in flags:
            self.write("12\n" if short else "Release:\t12\n")
            return
        if "-i" in flags:
            self.write("Debian\n" if short else "Distributor ID:\tDebian\n")
            return
        if "-d" in flags:
            self.write("Debian GNU/Linux 12 (bookworm)\n" if short else "Description:\tDebian GNU/Linux 12 (bookworm)\n")
            return
        self.write(
            "Distributor ID:\tDebian\n"
            "Description:\tDebian GNU/Linux 12 (bookworm)\n"
            "Release:\t12\n"
            "Codename:\tbookworm\n"
        )


_register(["lscpu", "/usr/bin/lscpu"], Command_lscpu)
_register(["lspci", "/usr/bin/lspci", "/sbin/lspci"], Command_lspci)
_register(["nproc", "/usr/bin/nproc"], Command_nproc)
_register(["arch", "/usr/bin/arch", "/bin/arch"], Command_arch)
_register(["hostnamectl", "/usr/bin/hostnamectl"], Command_hostnamectl)
_register(["lsb_release", "/usr/bin/lsb_release"], Command_lsb_release)


class Command_id_user(HoneyPotCommand):
    def call(self) -> None:
        u = self.user
        uname = u.get("username", "root")
        uid = int(u.get("uid", 0))
        gid = int(u.get("gid", uid))
        flags = "".join(a for a in self.args if a.startswith("-"))
        if "u" in flags:
            self.write(f"{uname}\n" if "n" in flags else f"{uid}\n")
            return
        if "g" in flags:
            self.write(f"{uname}\n" if "n" in flags else f"{gid}\n")
            return
        if "G" in flags:
            self.write(f"{uname}\n" if "n" in flags else f"{gid}\n")
            return
        self.write(f"uid={uid}({uname}) gid={gid}({uname}) groups={gid}({uname})\n")


class Command_w(HoneyPotCommand):
    def call(self) -> None:
        uname = self.user.get("username", "root")
        cip = _real_client_ip(self.protocol)
        now_t = time.strftime("%H:%M:%S")
        self.write(
            f" {now_t} up 14 days,  3:18,  1 user,  load average: 0.42, 0.38, 0.31\n"
            "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"
            f"{uname:<8} pts/0    {cip:<16} {now_t[:5]}    0.00s  0.04s  0.00s -bash\n"
        )


class Command_who(HoneyPotCommand):
    def call(self) -> None:
        uname = self.user.get("username", "root")
        cip = _real_client_ip(self.protocol)
        stamp = time.strftime("%Y-%m-%d %H:%M")
        self.write(f"{uname:<8} pts/0        {stamp} ({cip})\n")


class Command_uptime(HoneyPotCommand):
    def call(self) -> None:
        up = _uptime_seconds()
        days = up // 86400
        hrs = (up % 86400) // 3600
        mins = (up % 3600) // 60
        if "-p" in self.args or "--pretty" in self.args:
            self.write(f"up {days} days, {hrs} hours, {mins} minutes\n")
            return
        if "-s" in self.args or "--since" in self.args:
            boot_dt = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=up)
            self.write(boot_dt.strftime("%Y-%m-%d %H:%M:%S\n"))
            return
        now_t = time.strftime("%H:%M:%S")
        self.write(f" {now_t} up {days} days, {hrs:2d}:{mins:02d},  1 user,  load average: 0.42, 0.38, 0.31\n")


_register(["id", "/usr/bin/id"], Command_id_user)
_register(["w", "/usr/bin/w"], Command_w)
_register(["who", "/usr/bin/who"], Command_who)
_register(["uptime", "/usr/bin/uptime"], Command_uptime)


class Command_top(HoneyPotCommand):
    def call(self) -> None:
        now_t = time.strftime("%H:%M:%S")
        self.write(
            f"top - {now_t} up 14 days,  3:18,  1 user,  load average: 0.42, 0.38, 0.31\n"
            "Tasks: 138 total,   1 running, 137 sleeping,   0 stopped,   0 zombie\n"
            "%Cpu(s):  4.2 us,  1.1 sy,  0.0 ni, 94.5 id,  0.2 wa,  0.0 hi,  0.0 si,  0.0 st\n"
            "MiB Mem :  32123.2 total,  13947.2 free,   7124.8 used,  11051.2 buff/cache\n"
            "MiB Swap:   4096.0 total,   4096.0 free,      0.0 used.  24033.6 avail Mem\n\n"
            "    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND\n"
            "   1458 ollama    20   0   14.1g   3.7g  94200 S   4.8  18.2 842:19.12 ollama runner\n"
            "   1412 ollama    20   0 8223.5m   1.9g  54120 S   2.1  12.4 512:48.04 ollama serve\n"
            "   1280 deploy    20   0 1798.9m 610.2m  28400 S   1.4   3.9 214:03.18 litellm\n"
            "   1104 www-data  20   0 1097.7m 384.9m  21400 S   0.8   2.4 129:19.88 node\n"
        )


class Command_vmstat(HoneyPotCommand):
    def call(self) -> None:
        self.write(
            "procs -----------memory---------- ---swap-- -----io---- -system-- -------cpu-------\n"
            " r  b   swpd   free   buff  cache   si   so    bi    bo   in   cs us sy id wa st gu\n"
            " 1  0      0 14281920 412980 10840212    0    0    12    24  218  492  4  1 95  0  0  0\n"
        )


class Command_dmesg(HoneyPotCommand):
    def call(self) -> None:
        self.write(
            f"[    0.000000] Linux version {KERNEL_VERSION} (debian-kernel@lists.debian.org)\n"
            "[    0.000000] Hypervisor detected: KVM\n"
            "[    1.142019] nvme / virtio_blk: vda1 (160G), vdb1 (500G) online\n"
            "[    2.841920] nvidia: module verification failed: signature and/or required key missing - tainting kernel\n"
            "[    2.984122] NVRM: loading NVIDIA UNIX x86_64 Kernel Module  550.127.05\n"
        )


class Command_lsmod(HoneyPotCommand):
    def call(self) -> None:
        self.write(
            "Module                  Size  Used by\n"
            "nvidia_uvm           1884160  4\n"
            "nvidia_drm            122880  0\n"
            "nvidia_modeset       1605632  1 nvidia_drm\n"
            "nvidia              62685184  14 nvidia_uvm,nvidia_modeset\n"
            "veth                   49152  6\n"
            "overlay               204800  6\n"
            "virtio_net             98304  0\n"
        )


class Command_dmidecode(HoneyPotCommand):
    def call(self) -> None:
        self.write(
            "# dmidecode 3.4\n"
            "Getting SMBIOS data from sysfs.\n"
            "Handle 0x0100, DMI type 1, 27 bytes\n"
            "System Information\n"
            "\tManufacturer: QEMU\n"
            "\tProduct Name: Standard PC (i440FX + PIIX, 1996)\n"
            "\tSerial Number: 8a1f3c9d-7e02-4b11-9d3c-44201f98a71e\n"
        )


class Command_sysctl(HoneyPotCommand):
    def call(self) -> None:
        if self.args and self.args[-1] == "net.ipv4.ip_forward":
            self.write("net.ipv4.ip_forward = 1\n")
            return
        if self.args and self.args[-1] == "kernel.hostname":
            self.write(f"kernel.hostname = {HOSTNAME}\n")
            return
        self.write(f"kernel.hostname = {HOSTNAME}\nkernel.osrelease = {KERNEL_VERSION}\nnet.ipv4.ip_forward = 1\nvm.swappiness = 10\n")


class Command_timedatectl(HoneyPotCommand):
    def call(self) -> None:
        now_utc = time.strftime("%a %Y-%m-%d %H:%M:%S UTC", time.gmtime())
        self.write(
            f"               Local time: {now_utc}\n"
            f"           Universal time: {now_utc}\n"
            "                Time zone: Etc/UTC (UTC, +0000)\n"
            "System clock synchronized: yes\n"
            "              NTP service: active\n"
        )


_register(["top", "/usr/bin/top"], Command_top)
_register(["vmstat", "/usr/bin/vmstat"], Command_vmstat)
_register(["dmesg", "/bin/dmesg", "/usr/bin/dmesg"], Command_dmesg)
_register(["lsmod", "/sbin/lsmod", "/usr/sbin/lsmod", "/usr/bin/lsmod"], Command_lsmod)
_register(["dmidecode", "/usr/sbin/dmidecode", "/usr/bin/dmidecode"], Command_dmidecode)
_register(["sysctl", "/sbin/sysctl", "/usr/sbin/sysctl"], Command_sysctl)
_register(["timedatectl", "/usr/bin/timedatectl"], Command_timedatectl)


class Command_sort(HoneyPotCommand):
    consumes_stdin = True

    def call(self) -> None:
        reverse = False
        unique = False
        numeric = False
        files: list[str] = []
        for a in self.args:
            if a.startswith("-") and a != "-":
                if "r" in a:
                    reverse = True
                if "u" in a:
                    unique = True
                if "n" in a:
                    numeric = True
                continue
            files.append(a)
        text, rc = _read_stdin_or_files(self, files)
        if rc:
            self.exit_code = rc
            return
        lines = text.splitlines()
        if unique:
            lines = list(dict.fromkeys(lines))
        if numeric:
            def num_key(s: str) -> tuple[float, str]:
                m = re.match(r"^\s*(-?\d+(?:\.\d+)?)", s)
                return (float(m.group(1)) if m else 0.0, s)
            lines.sort(key=num_key, reverse=reverse)
        else:
            lines.sort(reverse=reverse)
        if lines:
            self.write("\n".join(lines) + "\n")


_register(["sort", "/usr/bin/sort", "/bin/sort"], Command_sort)


class Command_readlink(HoneyPotCommand):
    def call(self) -> None:
        canon = "-f" in self.args or "-e" in self.args or "-m" in self.args
        targets = [a for a in self.args if not a.startswith("-")]
        for t in targets:
            if t == "/proc/self/exe":
                self.write("/usr/bin/bash\n")
                continue
            p = self.fs.resolve_path(t, self.cwd)
            if not self.fs.exists(p):
                self.exit_code = 1
                continue
            node = self.fs.getfile(p, follow_symlinks=False)
            if node and node[cowrie_fs.A_TYPE] == cowrie_fs.T_LINK and node[cowrie_fs.A_TARGET]:
                self.write(self.fs.resolve_path(t, self.cwd) + "\n" if canon else str(node[cowrie_fs.A_TARGET]) + "\n")
            elif canon:
                self.write(p + "\n")
            else:
                self.exit_code = 1


class Command_realpath(HoneyPotCommand):
    def call(self) -> None:
        targets = [a for a in self.args if not a.startswith("-")]
        for t in targets:
            self.write(self.fs.resolve_path(t, self.cwd) + "\n")


class Command_basename(HoneyPotCommand):
    def call(self) -> None:
        targets = [a for a in self.args if not a.startswith("-")]
        if not targets:
            self.exit_code = 1
            return
        b = posixpath.basename(targets[0].rstrip("/") or "/")
        if len(targets) > 1 and b.endswith(targets[1]):
            b = b[:-len(targets[1])]
        self.write(b + "\n")


class Command_dirname(HoneyPotCommand):
    def call(self) -> None:
        targets = [a for a in self.args if not a.startswith("-")]
        if not targets:
            self.exit_code = 1
            return
        self.write((posixpath.dirname(targets[0].rstrip("/")) or "/") + "\n")


class Command_stat(HoneyPotCommand):
    def call(self) -> None:
        targets = [a for a in self.args if not a.startswith("-")]
        for t in targets:
            p = self.fs.resolve_path(t, self.cwd)
            if not self.fs.exists(p):
                self.errorWrite(f"stat: cannot statx '{t}': No such file or directory\n")
                self.exit_code = 1
                continue
            st = self.fs.stat(p)
            kind = "directory" if stat.S_ISDIR(st.st_mode) else ("symbolic link" if stat.S_ISLNK(st.st_mode) else "regular file")
            self.write(
                f"  File: {t}\n"
                f"  Size: {st.st_size:<15} Blocks: {max(8, (st.st_size // 512) + 8):<10} IO Block: 4096   {kind}\n"
                f"Device: fe01h/65025d    Inode: {st.st_ino:<12} Links: {st.st_nlink}\n"
                f"Access: ({oct(stat.S_IMODE(st.st_mode))[2:]:0>4}/{stat.filemode(st.st_mode)})  Uid: (    {st.st_uid}/   root)   Gid: (    {st.st_gid}/   root)\n"
            )


class Command_file(HoneyPotCommand):
    def call(self) -> None:
        targets = [a for a in self.args if not a.startswith("-")]
        for t in targets:
            p = self.fs.resolve_path(t, self.cwd)
            if not self.fs.exists(p):
                self.write(f"{t}: cannot open `{t}' (No such file or directory)\n")
                continue
            if self.fs.isdir(p):
                self.write(f"{t}: directory\n")
                continue
            if self.fs.islink(p):
                self.write(f"{t}: symbolic link\n")
                continue
            raw = b""
            try:
                raw = self.fs.file_contents(p)
            except Exception:
                pass
            if raw.startswith(b"\x7fELF") or any(p.startswith(pfx) for pfx in ("/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/local/bin/")):
                self.write(f"{t}: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, stripped\n")
            elif raw.startswith(b"#!"):
                self.write(f"{t}: POSIX shell script, ASCII text executable\n")
            elif b"{" in raw and b"}" in raw:
                self.write(f"{t}: JSON data\n")
            else:
                self.write(f"{t}: ASCII text\n")


class Command_hashsum(HoneyPotCommand):
    consumes_stdin = True
    algo = "sha256"

    def call(self) -> None:
        targets = [a for a in self.args if not a.startswith("-") or a == "-"]
        if not targets:
            data = self.input_data or b""
            h = hashlib.new(self.algo, data).hexdigest()
            self.write(f"{h}  -\n")
            return
        for t in targets:
            if t == "-":
                data = self.input_data or b""
                h = hashlib.new(self.algo, data).hexdigest()
                self.write(f"{h}  -\n")
                continue
            p = self.fs.resolve_path(t, self.cwd)
            if not self.fs.exists(p):
                self.errorWrite(f"{self.algo}sum: {t}: No such file or directory\n")
                self.exit_code = 1
                continue
            try:
                data = self.fs.file_contents(p)
            except Exception:
                data = b""
            h = hashlib.new(self.algo, data).hexdigest()
            self.write(f"{h}  {t}\n")


class Command_md5sum(Command_hashsum):
    algo = "md5"


class Command_sha256sum(Command_hashsum):
    algo = "sha256"


_register(["readlink", "/bin/readlink", "/usr/bin/readlink"], Command_readlink)
_register(["realpath", "/usr/bin/realpath"], Command_realpath)
_register(["basename", "/usr/bin/basename", "/bin/basename"], Command_basename)
_register(["dirname", "/usr/bin/dirname", "/bin/dirname"], Command_dirname)
_register(["stat", "/usr/bin/stat"], Command_stat)
_register(["file", "/usr/bin/file"], Command_file)
_register(["md5sum", "/usr/bin/md5sum"], Command_md5sum)
_register(["sha256sum", "/usr/bin/sha256sum"], Command_sha256sum)
