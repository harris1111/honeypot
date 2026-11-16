#!/usr/bin/env python3
"""Boot wrapper for Cowrie: merges custom honeyfs & txtcmds onto bundled fs.pickle."""

from __future__ import annotations

import os
import pickle
import posixpath
import stat
import time
from typing import Any

from cowrie.core.resources import open_data_binary

(
    A_NAME,
    A_TYPE,
    A_UID,
    A_GID,
    A_SIZE,
    A_MODE,
    A_CTIME,
    A_CONTENTS,
    A_TARGET,
    A_REALFILE,
) = range(10)
T_LINK, T_DIR, T_FILE = 0, 1, 2

HONEYFS_DIR = "/cowrie/cowrie-git/honeyfs"
TXTCMDS_DIR = "/cowrie/cowrie-git/txtcmds"
MERGED_PICKLE_PATH = "/tmp/merged-fs.pickle"

# Minimal valid ELF64 LSB x86-64 magic header so `file`, `hexdump`, and `/proc/self/exe` checks look authentic.
ELF64_STUB = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8 + b"\x03\x00\x3e\x00\x01\x00\x00\x00" + b"\x00" * 40

REALISTIC_BINARIES: list[tuple[str, int]] = [
    ("bin/bash", 1396520),
    ("usr/bin/bash", 1396520),
    ("bin/sh", 125688),
    ("bin/busybox", 2148912),
    ("bin/df", 96448),
    ("usr/bin/df", 96448),
    ("bin/lsblk", 174208),
    ("usr/bin/lsblk", 174208),
    ("bin/readlink", 51848),
    ("usr/bin/readlink", 51848),
    ("bin/sort", 118424),
    ("usr/bin/sort", 118424),
    ("sbin/ip", 642880),
    ("usr/sbin/ip", 642880),
    ("bin/ip", 642880),
    ("usr/bin/ip", 642880),
    ("sbin/sysctl", 43816),
    ("usr/sbin/sysctl", 43816),
    ("usr/sbin/dmidecode", 114624),
    ("sbin/lsmod", 55416),
    ("usr/sbin/lsmod", 55416),
    ("usr/local/bin/ollama", 28419200),
    ("usr/local/bin/litellm", 8420),
    ("opt/venv/bin/litellm", 8420),
    ("opt/venv/bin/python3", 5948216),
    ("opt/venv/bin/pip", 1240),
    ("usr/bin/python3", 5948216),
    ("usr/bin/python3.11", 5948216),
    ("usr/bin/pip", 1240),
    ("usr/bin/pip3", 1240),
    ("usr/bin/nvidia-smi", 984128),
    ("usr/bin/nvcc", 14289100),
    ("usr/local/cuda/bin/nvcc", 14289100),
    ("usr/bin/docker", 54120800),
    ("usr/bin/docker-compose", 48210400),
    ("usr/local/bin/docker-compose", 48210400),
    ("usr/bin/kubectl", 57492100),
    ("usr/bin/aws", 64812900),
    ("usr/local/bin/aws", 64812900),
    ("usr/bin/jq", 294812),
    ("usr/bin/curl", 284920),
    ("usr/bin/systemctl", 312840),
    ("usr/bin/journalctl", 264120),
    ("usr/bin/ss", 168420),
    ("usr/bin/netstat", 158420),
    ("usr/bin/lsof", 184290),
    ("usr/bin/node", 98421000),
    ("usr/bin/npm", 4820),
    ("usr/bin/psql", 684120),
    ("usr/bin/redis-cli", 428912),
    ("usr/bin/mysql", 7128400),
    ("usr/bin/free", 48120),
    ("usr/bin/lscpu", 98412),
    ("usr/bin/lspci", 84210),
    ("usr/bin/nproc", 43616),
    ("usr/bin/arch", 43616),
    ("usr/bin/hostnamectl", 88420),
    ("usr/bin/lsb_release", 16420),
    ("usr/bin/top", 128420),
    ("usr/bin/vmstat", 51420),
    ("bin/dmesg", 98420),
    ("usr/bin/dmesg", 98420),
    ("usr/bin/timedatectl", 78420),
    ("usr/bin/realpath", 51848),
    ("usr/bin/basename", 43616),
    ("usr/bin/dirname", 43616),
    ("usr/bin/stat", 84210),
    ("usr/bin/file", 39840),
    ("usr/bin/md5sum", 55416),
    ("usr/bin/sha256sum", 55416),
    ("usr/bin/id", 47840),
    ("usr/bin/w", 35416),
    ("usr/bin/who", 55416),
    ("usr/bin/uptime", 26416),
    ("usr/bin/lockr", 18420),
    ("bin/lockr", 18420),
    ("usr/bin/chattr", 22416),
    ("bin/chattr", 22416),
]

WRITABLE_BOT_DIRS: list[tuple[str, int]] = [
    ("boot", 0o040755),
    ("mnt", 0o040755),
    ("data", 0o040755),
    ("dev/shm", 0o041777),
    ("var/tmp", 0o041777),
    ("var/run", 0o040755),
    ("opt/venv/bin", 0o040755),
    ("usr/local/bin", 0o040755),
    ("usr/local/cuda/bin", 0o040755),
    ("usr/share/ollama", 0o040755),
]


def _load_base_tree() -> list[Any]:
    with open_data_binary("fs.pickle") as f:
        try:
            return pickle.load(f)
        except UnicodeDecodeError:
            f.seek(0)
            return pickle.load(f, encoding="utf8")


def _follow_node(tree: list[Any], cur_dir_parts: list[str], node: list[Any], depth: int = 0) -> list[Any] | None:
    if depth > 16:
        return None
    if node[A_TYPE] != T_LINK:
        return node
    target = node[A_TARGET] or ""
    if not target:
        return None
    if target.startswith("/"):
        joined = posixpath.normpath(target)
    else:
        base = "/" + "/".join(cur_dir_parts)
        joined = posixpath.normpath(posixpath.join(base, target))
    return _find_node(tree, [p for p in joined.split("/") if p], depth + 1)


def _find_node(tree: list[Any], parts: list[str], depth: int = 0) -> list[Any] | None:
    if depth > 16:
        return None
    node = tree
    for idx, part in enumerate(parts):
        if node[A_TYPE] == T_LINK:
            node = _follow_node(tree, parts[:idx], node, depth + 1)
            if node is None:
                return None
        children = node[A_CONTENTS]
        if not isinstance(children, list):
            return None
        match = next((c for c in children if c[A_NAME] == part), None)
        if match is None:
            return None
        if match[A_TYPE] == T_LINK:
            resolved = _follow_node(tree, parts[:idx], match, depth + 1)
            if resolved is None:
                return None
            match = resolved
        node = match
    return node


def _ensure_dir(tree: list[Any], dir_parts: list[str], now: int) -> list[Any]:
    node = tree
    cur_parts: list[str] = []
    for part in dir_parts:
        if node[A_TYPE] == T_LINK:
            resolved = _follow_node(tree, cur_parts, node)
            if resolved is not None and resolved[A_TYPE] == T_DIR:
                node = resolved
        children = node[A_CONTENTS]
        if not isinstance(children, list):
            node[A_TYPE] = T_DIR
            node[A_CONTENTS] = []
            children = node[A_CONTENTS]
        match = next((c for c in children if c[A_NAME] == part), None)
        if match is None:
            match = [part, T_DIR, 0, 0, 4096, 0o040755, now, [], None, None]
            children.append(match)
        elif match[A_TYPE] == T_LINK:
            resolved = _follow_node(tree, cur_parts, match)
            if resolved is not None and resolved[A_TYPE] == T_DIR:
                match = resolved
        elif match[A_TYPE] != T_DIR:
            match[A_TYPE] = T_DIR
            match[A_CONTENTS] = []
        cur_parts.append(part)
        node = match
    return node


def _upsert_file(
    tree: list[Any],
    relpath: str,
    data: bytes,
    mode: int,
    realfile: str | None,
    uid: int = 0,
    gid: int = 0,
) -> None:
    parts = [p for p in relpath.replace("\\", "/").split("/") if p]
    if not parts:
        return
    now = int(time.time())
    parent = _ensure_dir(tree, parts[:-1], now)
    children: list[Any] = parent[A_CONTENTS]
    name = parts[-1]
    existing = next((c for c in children if c[A_NAME] == name), None)
    if existing is not None:
        existing[A_TYPE] = T_FILE
        existing[A_UID] = uid
        existing[A_GID] = gid
        existing[A_SIZE] = len(data)
        existing[A_MODE] = stat.S_IFREG | mode
        existing[A_CTIME] = now
        existing[A_CONTENTS] = data
        existing[A_TARGET] = None
        existing[A_REALFILE] = realfile
        return
    children.append(
        [name, T_FILE, uid, gid, len(data), stat.S_IFREG | mode, now, data, None, realfile]
    )


def _walk_and_merge(tree: list[Any], root_dir: str, default_mode: int) -> None:
    if not os.path.isdir(root_dir):
        return
    for cur_root, _dirs, files in os.walk(root_dir):
        for fname in sorted(files):
            full_path = os.path.join(cur_root, fname)
            relpath = os.path.relpath(full_path, root_dir)
            try:
                with open(full_path, "rb") as f:
                    raw = f.read()
            except OSError:
                continue
            mode = default_mode
            uid, gid = 0, 0
            if relpath in ("root/.bash_history", "home/deploy/.aws/credentials"):
                mode = 0o600
            elif relpath == "var/www/app/.env":
                mode = 0o640
                uid, gid = 33, 33
            if relpath.startswith("home/deploy/"):
                uid, gid = 1000, 1000
            _upsert_file(tree, relpath, raw, mode, full_path, uid=uid, gid=gid)


def _seed_binaries_and_dirs(tree: list[Any]) -> None:
    now = int(time.time())
    for rel_dir, dmode in WRITABLE_BOT_DIRS:
        node = _ensure_dir(tree, [p for p in rel_dir.split("/") if p], now)
        node[A_MODE] = dmode

    for relpath, fsize in REALISTIC_BINARIES:
        parts = [p for p in relpath.split("/") if p]
        parent = _ensure_dir(tree, parts[:-1], now)
        children: list[Any] = parent[A_CONTENTS]
        name = parts[-1]
        existing = next((c for c in children if c[A_NAME] == name), None)
        if existing is not None:
            if existing[A_TYPE] == T_FILE:
                if not existing[A_CONTENTS]:
                    existing[A_CONTENTS] = ELF64_STUB
                existing[A_SIZE] = fsize
                existing[A_MODE] = stat.S_IFREG | 0o755
            continue
        children.append(
            [name, T_FILE, 0, 0, fsize, stat.S_IFREG | 0o755, now, ELF64_STUB, None, None]
        )

    # Ensure /proc/self/exe resolves cleanly like Linux kernel symlink -> /usr/bin/bash
    proc_self = _ensure_dir(tree, ["proc", "self"], now)
    ps_children: list[Any] = proc_self[A_CONTENTS]
    if not any(c[A_NAME] == "exe" for c in ps_children):
        ps_children.append(
            ["exe", T_LINK, 0, 0, 13, stat.S_IFLNK | 0o777, now, b"", "/usr/bin/bash", None]
        )


def main() -> None:
    tree = _load_base_tree()
    _seed_binaries_and_dirs(tree)
    _walk_and_merge(tree, HONEYFS_DIR, 0o644)
    _walk_and_merge(tree, TXTCMDS_DIR, 0o755)
    tmp_out = MERGED_PICKLE_PATH + ".tmp"
    with open(tmp_out, "wb") as f:
        pickle.dump(tree, f, protocol=2)
    os.replace(tmp_out, MERGED_PICKLE_PATH)

    twistd_argv = [
        "/cowrie/cowrie-env/bin/python3",
        "/cowrie/cowrie-env/bin/twistd",
        "-n",
        "--umask=0022",
        "--pidfile=",
        "--logger",
        "cowrie.python.logfile.stdoutLogger",
        "cowrie",
    ]
    os.execv("/cowrie/cowrie-env/bin/python3", twistd_argv)


if __name__ == "__main__":
    main()
