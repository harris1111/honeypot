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


def main() -> None:
    tree = _load_base_tree()
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
