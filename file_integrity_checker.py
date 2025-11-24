#!/usr/bin/env python3
"""
file_integrity_checker.py

Simple File Integrity Checker using hashlib (SHA-256).
Usage:
  python file_integrity_checker.py init   /path/to/dir   [--baseline baseline.json] [--exclude '*.tmp']
  python file_integrity_checker.py scan   /path/to/dir   [--baseline baseline.json] [--report report.json]
  python file_integrity_checker.py monitor /path/to/dir  [--baseline baseline.json] [--interval 10]
  python file_integrity_checker.py update-baseline /path/to/dir [--baseline baseline.json]
  python file_integrity_checker.py verify-file /path/to/file --hash <hex>
"""

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path
from fnmatch import fnmatch
from typing import Dict, Tuple

CHUNK_SIZE = 8 * 1024 * 1024  # 8 MB


def compute_sha256(path: Path) -> str:
    """Compute SHA256 for file at path in streaming manner."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def make_snapshot(root: Path, recursive=True, exclude_patterns=None) -> Dict[str, dict]:
    """
    Walk directory and create snapshot dict:
      { relative_path_str: { "hash": str, "size": int, "mtime": float } }
    """
    if exclude_patterns is None:
        exclude_patterns = []

    snapshot = {}
    root = root.resolve()
    if root.is_file():
        files = [root]
    else:
        files = []
        if recursive:
            for p in root.rglob("*"):
                if p.is_file():
                    files.append(p)
        else:
            for p in root.iterdir():
                if p.is_file():
                    files.append(p)

    for f in files:
        rel = str(f.relative_to(root))
        # check exclude patterns against relative path and name
        excluded = False
        for pat in exclude_patterns:
            if fnmatch(rel, pat) or fnmatch(f.name, pat):
                excluded = True
                break
        if excluded:
            continue
        try:
            file_hash = compute_sha256(f)
            stat = f.stat()
            snapshot[rel] = {"hash": file_hash, "size": stat.st_size, "mtime": stat.st_mtime}
        except (PermissionError, OSError) as e:
            print(f"[WARN] Could not read {f}: {e}", file=sys.stderr)
    return snapshot


def load_baseline(path: Path) -> Dict[str, dict]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def save_baseline(snapshot: Dict[str, dict], path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump({"created": time.time(), "entries": snapshot}, fh, indent=2)


def compare_snapshots(old: Dict[str, dict], new: Dict[str, dict]) -> dict:
    """
    Return a dict with keys: added, removed, modified.
    - added: in new but not old
    - removed: in old but not new
    - modified: in both but hash differs (or size differs as fast check)
    """
    added = []
    removed = []
    modified = []

    old_keys = set(old.keys())
    new_keys = set(new.keys())

    for p in sorted(new_keys - old_keys):
        added.append(p)
    for p in sorted(old_keys - new_keys):
        removed.append(p)
    for p in sorted(old_keys & new_keys):
        old_e = old[p]
        new_e = new[p]
        if old_e.get("hash") != new_e.get("hash"):
            modified.append({"path": p, "old_hash": old_e.get("hash"), "new_hash": new_e.get("hash"),
                             "old_size": old_e.get("size"), "new_size": new_e.get("size")})
    return {"added": added, "removed": removed, "modified": modified}


def pretty_report(report: dict, root: Path):
    print("Integrity Scan Report")
    print("=====================")
    if report["added"]:
        print(f"\nAdded files ({len(report['added'])}):")
        for a in report["added"]:
            print(f"  + {a}")
    if report["removed"]:
        print(f"\nRemoved files ({len(report['removed'])}):")
        for r in report["removed"]:
            print(f"  - {r}")
    if report["modified"]:
        print(f"\nModified files ({len(report['modified'])}):")
        for m in report["modified"]:
            print(f"  * {m['path']}")
            print(f"      old: {m['old_hash']}  size={m['old_size']}")
            print(f"      new: {m['new_hash']}  size={m['new_size']}")
    if not (report["added"] or report["removed"] or report["modified"]):
        print("\nNo changes detected. All files match baseline.")


def action_init(args):
    root = Path(args.path).resolve()
    baseline = Path(args.baseline).resolve()
    print(f"[INFO] Building baseline for {root} ...")
    snapshot = make_snapshot(root, recursive=not args.no_recursive, exclude_patterns=args.exclude or [])
    save_baseline(snapshot, baseline)
    print(f"[OK] Baseline saved to {baseline} ({len(snapshot)} files).")


def action_scan(args):
    root = Path(args.path).resolve()
    baseline_path = Path(args.baseline).resolve()
    baseline_data = load_baseline(baseline_path)
    old_entries = baseline_data.get("entries", {}) if baseline_data else {}
    if not old_entries:
        print(f"[WARN] Baseline {baseline_path} is empty or missing. Consider running 'init' first.")
    print(f"[INFO] Scanning {root} ...")
    snapshot = make_snapshot(root, recursive=not args.no_recursive, exclude_patterns=args.exclude or [])
    report = compare_snapshots(old_entries, snapshot)
    pretty_report(report, root)
    if args.report:
        report_path = Path(args.report).resolve()
        out = {"scanned_at": time.time(), "root": str(root), "report": report}
        with report_path.open("w", encoding="utf-8") as fh:
            json.dump(out, fh, indent=2)
        print(f"[OK] Report written to {report_path}")


def action_update_baseline(args):
    root = Path(args.path).resolve()
    baseline = Path(args.baseline).resolve()
    print(f"[INFO] Updating baseline for {root} ...")
    snapshot = make_snapshot(root, recursive=not args.no_recursive, exclude_patterns=args.exclude or [])
    save_baseline(snapshot, baseline)
    print(f"[OK] Baseline updated at {baseline} ({len(snapshot)} files).")


def action_monitor(args):
    root = Path(args.path).resolve()
    baseline_path = Path(args.baseline).resolve()
    interval = max(1, args.interval)
    print(f"[INFO] Starting monitor on {root} with interval {interval}s, baseline={baseline_path}")
    baseline_data = load_baseline(baseline_path)
    old_entries = baseline_data.get("entries", {}) if baseline_data else {}
    if not old_entries:
        print(f"[WARN] Baseline {baseline_path} is empty. The first run will act like 'init' and create baseline in memory.")
    try:
        while True:
            snapshot = make_snapshot(root, recursive=not args.no_recursive, exclude_patterns=args.exclude or [])
            report = compare_snapshots(old_entries, snapshot)
            if report["added"] or report["removed"] or report["modified"]:
                print(f"\n[ALERT] Changes detected at {time.strftime('%Y-%m-%d %H:%M:%S')}:")
                pretty_report(report, root)
                # keep baseline unchanged unless user wants to auto-update
                if args.autoupdate:
                    print("[INFO] Autoupdate enabled: updating baseline file.")
                    save_baseline(snapshot, baseline_path)
                    old_entries = snapshot
                else:
                    # If not autoupdating, just update in-memory baseline to avoid repeated alerts for same change.
                    old_entries = snapshot
            else:
                print(f"[OK] {time.strftime('%Y-%m-%d %H:%M:%S')} - no change.")
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[INFO] Monitor stopped by user.")


def action_verify_file(args):
    path = Path(args.path).resolve()
    if not path.exists() or not path.is_file():
        print(f"[ERROR] File not found: {path}")
        return
    actual = compute_sha256(path)
    print(f"File: {path}")
    print(f"SHA256: {actual}")
    if args.hash:
        match = actual.lower() == args.hash.strip().lower()
        print(f"Matches provided hash? {'YES' if match else 'NO'}")


def build_parser():
    p = argparse.ArgumentParser(description="Simple File Integrity Checker (SHA-256)")
    sub = p.add_subparsers(dest="cmd", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--baseline", "-b", default="baseline.json", help="Path to baseline JSON")
    common.add_argument("--no-recursive", action="store_true", help="Don't recurse into subdirectories")
    common.add_argument("--exclude", "-e", action="append", help="Exclude glob pattern (can be used multiple times)")

    p_init = sub.add_parser("init", parents=[common], help="Create baseline snapshot")
    p_init.add_argument("path", help="Directory or file to snapshot")
    p_init.set_defaults(func=action_init)

    p_scan = sub.add_parser("scan", parents=[common], help="Scan and compare with baseline")
    p_scan.add_argument("path", help="Directory or file to scan")
    p_scan.add_argument("--report", "-r", help="Write report JSON to this file")
    p_scan.set_defaults(func=action_scan)

    p_update = sub.add_parser("update-baseline", parents=[common], help="Rebuild baseline (overwrite)")
    p_update.add_argument("path", help="Directory or file to snapshot")
    p_update.set_defaults(func=action_update_baseline)

    p_monitor = sub.add_parser("monitor", parents=[common], help="Continuously monitor (polling)")
    p_monitor.add_argument("path", help="Directory or file to monitor")
    p_monitor.add_argument("--interval", "-i", type=int, default=30, help="Seconds between checks")
    p_monitor.add_argument("--autoupdate", action="store_true", help="Update baseline file automatically on change")
    p_monitor.set_defaults(func=action_monitor)

    p_verify = sub.add_parser("verify-file", help="Compute SHA256 for a single file and optionally compare to provided hash")
    p_verify.add_argument("path", help="File to verify")
    p_verify.add_argument("--hash", help="Hex hash to compare against")
    p_verify.set_defaults(func=action_verify_file)

    return p


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
