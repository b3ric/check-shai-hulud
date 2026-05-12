#!/usr/bin/env python3
"""
check_shai_hulud.py
Checks package-lock.json, yarn.lock, and node_modules for known Shai-Hulud compromised package versions.
Usage:
  python3 check_shai_hulud.py --lock package-lock.json
  python3 check_shai_hulud.py --yarn yarn.lock
  python3 check_shai_hulud.py --node-modules   # slow, inspects installed packages for postinstall scripts
"""

import json
import argparse
import re
from pathlib import Path

def load_compromised(path="shai_hulud_compromised.json"):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    # normalize to dict: package -> set(versions)
    d = {}
    for entry in data.get("shai_hulud_compromised", []):
        pkg = entry["package"]
        versions = set(entry.get("versions", []))
        d[pkg] = versions
    return d

def check_package_lock(lock_path, compromised):
    with open(lock_path, "r", encoding="utf-8") as f:
        lock = json.load(f)
    found = []
    # package-lock v2 uses "packages" with paths OR "dependencies"
    # check both places
    def check_dep_object(dep_obj):
        for name, info in dep_obj.items():
            version = info.get("version")
            if not version:
                continue
            if name in compromised and version in compromised[name]:
                found.append((name, version, "package-lock"))
    if "packages" in lock:
        # packages keys are like "" or "node_modules/pkg"
        for key, info in lock["packages"].items():
            name = info.get("name")
            version = info.get("version")
            if name and version and name in compromised and version in compromised[name]:
                found.append((name, version, "package-lock/packages"))
    if "dependencies" in lock:
        check_dep_object(lock["dependencies"])
    return found

def parse_yarn_lock(yarnlock_path):
    """
    Simple yarn.lock parser for Yarn classic (v1) style.
    We'll match lines like:
      package-name@^1.2.3, package-name@~1.2.0:
        version "1.2.3"
    This is a lightweight parser; for production use prefer 'yarn.lock' parsers.
    """
    text = Path(yarnlock_path).read_text(encoding="utf-8")
    entries = {}
    # split on lines that end with ':' and are package key lines
    # naive approach: find 'version "x.y.z"' following a key
    key_re = re.compile(r'^([^:\n]+):\n(?:[ \t]+.+\n)*?[ \t]+version ["\']([^"\']+)["\']', re.MULTILINE)
    for m in key_re.finditer(text):
        key = m.group(1).strip()
        version = m.group(2).strip()
        # key might contain multiple names, extract actual package name before @
        # Take first token before the first @ that isn't part of a scoped name
        # handle scoped names like @scope/name@^1.2.3
        # best heuristic: find the last occurrence of '@' after the first char for non-scoped, but for scoped, split at second '@'
        pkgname = None
        if key.startswith('@'):
            # scoped name: @scope/name@range -> package is @scope/name
            parts = key.split('@')
            # parts e.g. ['', 'scope/name', '^1.2.3,', ...]
            if len(parts) >= 2:
                pkgname = '@' + parts[1].split()[0]
        else:
            pkgname = key.split('@')[0]
        if pkgname:
            entries.setdefault(pkgname, set()).add(version)
    return entries

def check_yarn_lock(yarnlock_path, compromised):
    yarn_entries = parse_yarn_lock(yarnlock_path)
    found = []
    for pkg, versions in yarn_entries.items():
        if pkg in compromised:
            bad_versions = versions.intersection(compromised[pkg])
            for v in bad_versions:
                found.append((pkg, v, "yarn.lock"))
    return found

def check_node_modules(node_modules_dir, compromised):
    found = []
    nm = Path(node_modules_dir)
    if not nm.exists():
        return found
    # iterate through node_modules/**/package.json
    for pkg_json in nm.rglob("package.json"):
        try:
            pj = json.loads(pkg_json.read_text(encoding="utf-8"))
        except Exception:
            continue
        name = pj.get("name")
        version = pj.get("version")
        scripts = pj.get("scripts", {})
        postinstall = scripts.get("postinstall") or scripts.get("install")
        if name and version:
            if name in compromised and version in compromised[name]:
                found.append((name, version, str(pkg_json), "installed_compromised"))
            # also flag suspicious postinstall scripts (heuristic)
            if postinstall:
                # flag if postinstall invokes node/bundle.js or downloads remote content
                if "bundle.js" in postinstall or "curl" in postinstall or "wget" in postinstall or "node ./bundle" in postinstall:
                    found.append((name, version, str(pkg_json), "suspicious_postinstall", postinstall))
    return found

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--lock", help="path to package-lock.json", default="package-lock.json")
    ap.add_argument("--yarn", help="path to yarn.lock", default="yarn.lock")
    ap.add_argument("--node-modules", help="path to node_modules (optional)", default="node_modules")
    ap.add_argument("--data", help="path to shai_hulud_compromised.json", default="shai_hulud_compromised.json")
    args = ap.parse_args()

    compromised = load_compromised(args.data)
    results = []

    lock_path = Path(args.lock)
    if lock_path.exists():
        results += check_package_lock(str(lock_path), compromised)
    else:
        print(f"[info] package-lock.json not found at {lock_path}")

    yarn_path = Path(args.yarn)
    if yarn_path.exists():
        results += check_yarn_lock(str(yarn_path), compromised)
    else:
        print(f"[info] yarn.lock not found at {yarn_path}")

    nm = Path(args.node_modules)
    if nm.exists():
        nm_results = check_node_modules(nm, compromised)
        results += nm_results
    else:
        print(f"[info] node_modules not found at {nm} (skipping installed-package checks)")

    if not results:
        print("No known compromised package versions found in scanned files.")
    else:
        print("Potential matches / suspicious findings:")
        for r in results:
            print(" -", r)

if __name__ == "__main__":
    main()
