#!/usr/bin/env python3
"""FraudVault Container Security Scanner — runs inside sandbox jail."""
import json, os, re, sys, hashlib, stat, tarfile

def _is_private_ip(ip_str):
    if ip_str.startswith(("127.", "10.", "192.168.", "0.")):
        return True
    if ip_str.startswith("172."):
        parts = ip_str.split(".")
        if len(parts) >= 2:
            try:
                second = int(parts[1])
                if 16 <= second <= 31:
                    return True
            except ValueError:
                pass
    return False

rootfs = "/tmp/scanboy-container/rootfs"
container_dir = "/tmp/scanboy-container"

result = {
    "os": None, "packages": [], "secrets": [], "setuid": [], "suspicious": [],
    "supplyChain": [], "forgedKeys": [], "unofficialSources": [],
    "unsignedPackages": False, "layers": 0, "manifest": None,
    "symlinkEscapes": [], "trojanLayers": [],
    # New P1/P2/P3 fields
    "layerDiffs": [], "elfBinaries": [], "userAnalysis": {},
    "entrypointAnalysis": {}, "sensitiveFiles": [], "networkConfig": {},
    "volumeMounts": [], "configAudit": [], "cisBenchmark": [],
    "certificates": [], "capBinaries": [], "nestedArchives": [],
    "multiStageLeak": [], "buildArtifacts": [], "dockerfile": [],
    "baseImage": None, "cronJobs": [], "provenance": {},
    "writablePaths": [],
}

# ── OS Detection ──
for p in [os.path.join(rootfs, "etc/os-release"), os.path.join(rootfs, "etc/alpine-release")]:
    try:
        with open(p) as f:
            result["os"] = f.read().strip()[:200]
            break
    except: pass

# ── APK packages ──
apk_db = os.path.join(rootfs, "lib/apk/db/installed")
if os.path.isfile(apk_db):
    with open(apk_db) as f:
        name, ver = None, None
        for line in f:
            if line.startswith("P:"): name = line[2:].strip()
            elif line.startswith("V:"): ver = line[2:].strip()
            elif line.strip() == "" and name:
                result["packages"].append({"name": name, "version": ver or "?", "type": "apk"})
                name, ver = None, None

# ── DPKG packages ──
dpkg_status = os.path.join(rootfs, "var/lib/dpkg/status")
if os.path.isfile(dpkg_status):
    with open(dpkg_status) as f:
        name, ver = None, None
        for line in f:
            if line.startswith("Package: "): name = line.split(": ",1)[1].strip()
            elif line.startswith("Version: "): ver = line.split(": ",1)[1].strip()
            elif line.strip() == "" and name:
                result["packages"].append({"name": name, "version": ver or "?", "type": "dpkg"})
                name, ver = None, None

# ── Secrets scan ──
secret_patterns = [
    r"password\s*[=:]\s*\S+", r"api[_-]?key\s*[=:]\s*\S+",
    r"AKIA[A-Z0-9]{16}", r"-----BEGIN (?:RSA |EC )?PRIVATE KEY",
    r"ghp_[A-Za-z0-9]{36}", r"sk-[A-Za-z0-9]{48}",
]
# Config templates with example passwords — not real secrets
secrets_exclude_files = {"openssl.cnf", "openssl.cnf.dist", "openssl.cnf.default",
    "krb5.conf", "ldap.conf", "sssd.conf", "pam_ldap.conf", "login.defs",
    "nsswitch.conf", "my.cnf.sample", "pg_hba.conf.sample"}
sensitive_file_names = {
    ".bash_history", ".sh_history", ".zsh_history", ".python_history",
    ".mysql_history", ".psql_history", ".env", ".env.local", ".env.production",
    ".npmrc", ".pypirc", ".docker/config.json", ".kube/config",
    ".aws/credentials", ".aws/config", "id_rsa", "id_ed25519",
}
for search_dir in [os.path.join(rootfs, d) for d in ["etc", "root", "home", "app", "opt", "var"]]:
    if not os.path.isdir(search_dir): continue
    for dirpath, _, filenames in os.walk(search_dir):
        for fn in filenames[:200]:
            fp = os.path.join(dirpath, fn)
            rel = fp.replace(rootfs, "")
            # P1-5: Sensitive file detection
            if fn in sensitive_file_names or any(fp.endswith(s) for s in sensitive_file_names):
                result["sensitiveFiles"].append({"file": rel, "type": fn})
            if fn not in secrets_exclude_files:
                try:
                    with open(fp, errors="ignore") as fh:
                        content = fh.read(10000)
                        for pattern in secret_patterns:
                            for m in re.finditer(pattern, content, re.IGNORECASE):
                                result["secrets"].append({"file": rel, "match": m.group()[:100]})
                except: pass

# ── Setuid binaries ──
normal_setuid = {"/usr/bin/su", "/usr/bin/passwd", "/usr/bin/chfn", "/usr/bin/chsh",
                 "/usr/bin/newgrp", "/bin/mount", "/bin/umount", "/usr/bin/mount", "/usr/bin/umount"}
for dirpath, _, filenames in os.walk(rootfs):
    for fn in filenames[:500]:
        fp = os.path.join(dirpath, fn)
        try:
            st = os.stat(fp)
            if st.st_mode & 0o4000:
                rel = fp.replace(rootfs, "")
                result["setuid"].append(rel)
        except: pass

# ── P1-2: ELF binary analysis ──
import subprocess
for dirpath, _, filenames in os.walk(rootfs):
    for fn in filenames[:300]:
        fp = os.path.join(dirpath, fn)
        rel = fp.replace(rootfs, "")
        try:
            with open(fp, "rb") as bf:
                magic = bf.read(4)
            if magic == b"\x7fELF":
                info = {"path": rel, "size": os.path.getsize(fp)}
                try:
                    out = subprocess.run(["readelf", "-d", fp], capture_output=True, text=True, timeout=5)
                    needed = re.findall(r"NEEDED.*\[(.+?)\]", out.stdout)
                    info["libraries"] = needed[:20]
                    rpath = re.findall(r"RPATH.*\[(.+?)\]", out.stdout)
                    if rpath:
                        info["rpath"] = rpath[0]
                        if "/tmp" in rpath[0] or "/home" in rpath[0]:
                            result["suspicious"].append({"file": rel, "type": "rpath_injection", "evidence": rpath[0]})
                except: pass
                # Check for suspicious imports
                try:
                    out = subprocess.run(["readelf", "-s", fp], capture_output=True, text=True, timeout=5)
                    susp_syms = [s for s in ["ptrace", "execve", "connect", "socket", "dlopen", "mprotect"]
                                 if s in out.stdout]
                    if susp_syms:
                        info["suspiciousSymbols"] = susp_syms
                except: pass
                result["elfBinaries"].append(info)
                if len(result["elfBinaries"]) >= 50: break
        except: pass
    if len(result["elfBinaries"]) >= 50: break

# ── P1-3: User/permission analysis ──
passwd_path = os.path.join(rootfs, "etc/passwd")
shadow_path = os.path.join(rootfs, "etc/shadow")
if os.path.isfile(passwd_path):
    with open(passwd_path) as f:
        for line in f:
            parts = line.strip().split(":")
            if len(parts) >= 7:
                if parts[2] == "0" and parts[0] != "root":
                    result["userAnalysis"]["uid0Aliases"] = result["userAnalysis"].get("uid0Aliases", []) + [parts[0]]
                if parts[6] in ("/bin/bash", "/bin/sh", "/bin/zsh"):
                    result["userAnalysis"].setdefault("loginUsers", []).append(parts[0])
if os.path.isfile(shadow_path):
    try:
        with open(shadow_path) as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 2 and parts[1] in ("", "!!", "*"):
                    pass  # normal locked accounts
                elif len(parts) >= 2 and len(parts[1]) < 3:
                    result["userAnalysis"].setdefault("emptyPasswords", []).append(parts[0])
    except: pass

# ── P1-6: Network config ──
hosts_path = os.path.join(rootfs, "etc/hosts")
if os.path.isfile(hosts_path):
    with open(hosts_path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and not line.startswith("127.") and not line.startswith("::1"):
                result["networkConfig"].setdefault("customHosts", []).append(line)

# Check for LD_PRELOAD
for env_file in [os.path.join(rootfs, "etc/environment"), os.path.join(rootfs, "etc/profile")]:
    try:
        with open(env_file) as f:
            content = f.read()
            if "LD_PRELOAD" in content:
                result["networkConfig"]["ldPreload"] = True
                result["suspicious"].append({"file": env_file.replace(rootfs, ""), "type": "ld_preload", "evidence": "LD_PRELOAD set"})
    except: pass

# ── P1-4: Entrypoint analysis (from image config) ──
try:
    manifest_path = os.path.join(container_dir, "manifest.json")
    if os.path.isfile(manifest_path):
        with open(manifest_path) as mf:
            manifest = json.load(mf)
        if isinstance(manifest, list) and manifest:
            config_file = manifest[0].get("Config", "")
            config_path = os.path.join(container_dir, config_file)
            if os.path.isfile(config_path):
                with open(config_path) as cf:
                    config = json.load(cf)
                cc = config.get("config", {}) or {}
                result["entrypointAnalysis"] = {
                    "entrypoint": cc.get("Entrypoint"),
                    "cmd": cc.get("Cmd"),
                    "user": cc.get("User", "root"),
                    "exposedPorts": list((cc.get("ExposedPorts") or {}).keys()),
                    "env": [e for e in (cc.get("Env") or []) if not e.startswith("PATH=")],
                    "workingDir": cc.get("WorkingDir"),
                    "labels": cc.get("Labels") or {},
                }
                # P1-7: Volume mount analysis
                volumes = cc.get("Volumes") or {}
                dangerous_vols = {"/var/run/docker.sock": "container escape", "/": "full host",
                                  "/proc": "process info", "/sys": "kernel access", "/dev": "device access"}
                for vol in volumes:
                    severity = "critical" if vol in dangerous_vols else "low"
                    result["volumeMounts"].append({"path": vol, "severity": severity,
                        "risk": dangerous_vols.get(vol, "application data")})
                # P3-4: Provenance
                labels = cc.get("Labels") or {}
                provenance_keys = ["org.opencontainers.image.source", "org.opencontainers.image.revision",
                    "org.opencontainers.image.created", "org.opencontainers.image.authors",
                    "org.opencontainers.image.vendor", "org.opencontainers.image.version"]
                result["provenance"] = {k: labels.get(k) for k in provenance_keys if k in labels}
                result["provenance"]["missing"] = [k.split(".")[-1] for k in provenance_keys if k not in labels]
                # P1-3: Running as root check
                if not cc.get("User") or cc.get("User") in ("root", "0"):
                    result["userAnalysis"]["runsAsRoot"] = True
                # P3-1: Dockerfile reconstruction from history
                history = config.get("history", [])
                for entry in history:
                    cmd = entry.get("created_by", "")
                    empty = entry.get("empty_layer", False)
                    for prefix in ["/bin/sh -c #(nop)  ", "/bin/sh -c #(nop) ", "/bin/sh -c "]:
                        if cmd.startswith(prefix): cmd = cmd[len(prefix):]; break
                    result["dockerfile"].append({"cmd": cmd[:200], "empty": empty})
                    # P2-2: CIS checks from history
                    if re.search(r"(?:ARG|ENV)\s+\w*(?:PASSWORD|SECRET|KEY|TOKEN)\w*\s*=", cmd, re.I):
                        result["cisBenchmark"].append({"id": "4.10", "status": "FAIL", "desc": f"Secret in build: {cmd[:80]}"})
                    if "ADD " in cmd and ("http" in cmd or "ftp" in cmd):
                        result["cisBenchmark"].append({"id": "4.9", "status": "WARN", "desc": f"ADD from URL: {cmd[:80]}"})
                # CIS 4.1: User check
                if result["userAnalysis"].get("runsAsRoot"):
                    result["cisBenchmark"].append({"id": "4.1", "status": "FAIL", "desc": "Container runs as root"})
                # CIS 4.6: HEALTHCHECK
                if not any("HEALTHCHECK" in (e.get("created_by","")) for e in history):
                    result["cisBenchmark"].append({"id": "4.6", "status": "WARN", "desc": "No HEALTHCHECK instruction"})
                # P3-2: Base image identification
                result["baseImage"] = {
                    "repoTags": manifest[0].get("RepoTags", []),
                    "layerCount": len(manifest[0].get("Layers", [])),
                    "dockerVersion": config.get("docker_version"),
                    "created": config.get("created"),
                    "architecture": config.get("architecture"),
                }
except Exception as e:
    result["entrypointAnalysis"]["error"] = str(e)

# ── Suspicious files (crypto/backdoor/beacon) ──
for dirpath, _, filenames in os.walk(rootfs):
    for fn in filenames[:300]:
        fp = os.path.join(dirpath, fn)
        rel = fp.replace(rootfs, "")
        try:
            with open(fp, "rb") as fh:
                head = fh.read(2000)
                if b"stratum" in head or b"xmrig" in head or b"cryptonight" in head:
                    result["suspicious"].append({"file": rel, "type": "crypto_miner"})
                if b"/dev/tcp" in head:
                    result["suspicious"].append({"file": rel, "type": "backdoor"})
                elif head[:4] in (b"\x7fELF", b"#!") and b"reverse" in head.lower() and b"shell" in head.lower():
                    result["suspicious"].append({"file": rel, "type": "backdoor"})
                if b"mkfifo" in head and b"nc " in head:
                    result["suspicious"].append({"file": rel, "type": "reverse_shell"})
        except: pass
        # Beacon detection in scripts
        if fn.endswith((".sh", ".bash", ".py", ".rb", ".php")):
            try:
                with open(fp, errors="ignore") as fh:
                    content = fh.read(10000)
                    c2_hits = re.findall(r'(?:curl|wget|fetch|nc|ncat)\s+["\']?(?:https?://)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[^\s"\']*)', content)
                    for c2 in c2_hits:
                        ip = c2.split("/")[0].split(":")[0]
                        if not _is_private_ip(ip):
                            result["suspicious"].append({"file": rel, "type": "beacon", "evidence": c2[:100]})
                    if re.search(r'/dev/tcp/|mkfifo.*nc|bash -i.*>&.*/dev/tcp|socat.*exec|ncat.*-e', content):
                        result["suspicious"].append({"file": rel, "type": "reverse_shell"})
                    # P2-1: Config file auditing
                    if "--no-check-certificate" in content or "--allow-unauthenticated" in content or "--force-yes" in content:
                        result["unsignedPackages"] = True
                        result["supplyChain"].append({"file": rel, "issue": "unsigned package install"})
            except: pass

# ── P2-1: Service config auditing ──
config_checks = {
    "etc/nginx/nginx.conf": [("server_tokens on", "nginx_info_leak", "high")],
    "etc/ssh/sshd_config": [("PermitRootLogin yes", "ssh_root_login", "high"), ("PasswordAuthentication yes", "ssh_password", "medium")],
    "etc/redis/redis.conf": [("# requirepass", "redis_no_auth", "critical")],
    "etc/redis.conf": [("# requirepass", "redis_no_auth", "critical")],
    "etc/php/": [("allow_url_include = On", "php_rce", "critical"), ("display_errors = On", "php_info_leak", "medium")],
}
for config_rel, checks in config_checks.items():
    config_fp = os.path.join(rootfs, config_rel)
    if os.path.isfile(config_fp):
        try:
            with open(config_fp) as f:
                content = f.read(20000)
                for pattern, check_type, severity in checks:
                    if pattern in content:
                        result["configAudit"].append({"file": "/" + config_rel, "check": check_type, "severity": severity})
        except: pass
    elif os.path.isdir(config_fp):
        for fn in os.listdir(config_fp)[:10]:
            fp = os.path.join(config_fp, fn)
            try:
                with open(fp) as f:
                    content = f.read(20000)
                    for pattern, check_type, severity in checks:
                        if pattern in content:
                            result["configAudit"].append({"file": "/" + config_rel + fn, "check": check_type, "severity": severity})
            except: pass

# pg_hba.conf trust check
for pg_path in ["var/lib/postgresql/data/pg_hba.conf", "etc/postgresql/pg_hba.conf"]:
    fp = os.path.join(rootfs, pg_path)
    if os.path.isfile(fp):
        try:
            with open(fp) as f:
                for line in f:
                    if "trust" in line and "0.0.0.0" in line:
                        result["configAudit"].append({"file": "/" + pg_path, "check": "pg_trust_all", "severity": "critical"})
        except: pass

# ── P2-4: Capability-dependent binaries ──
cap_binaries = {"nsenter": "SYS_ADMIN+SYS_PTRACE", "strace": "SYS_PTRACE", "tcpdump": "NET_RAW",
                "iptables": "NET_ADMIN", "ip": "NET_ADMIN", "gdb": "SYS_PTRACE"}
for dirpath, _, filenames in os.walk(rootfs):
    for fn in filenames:
        if fn in cap_binaries:
            result["capBinaries"].append({"binary": fn, "path": os.path.join(dirpath, fn).replace(rootfs, ""),
                                          "requiredCaps": cap_binaries[fn]})

# ── P2-5: Nested archive detection ──
for dirpath, _, filenames in os.walk(rootfs):
    for fn in filenames[:200]:
        if fn.endswith((".tar", ".tar.gz", ".tgz", ".zip", ".7z", ".rar", ".iso", ".img", ".qcow2")):
            fp = os.path.join(dirpath, fn)
            try:
                sz = os.path.getsize(fp)
                result["nestedArchives"].append({"file": fp.replace(rootfs, ""), "size": sz, "type": fn.split(".")[-1]})
            except: pass

# ── P2-7: Build artifacts/cache ──
bloat_patterns = [
    ("var/cache/apt/archives", "apt_cache"), ("root/.cache/pip", "pip_cache"),
    ("root/.npm", "npm_cache"), ("root/.cache/go-build", "go_cache"),
    ("usr/share/man", "man_pages"), ("usr/share/doc", "docs"),
]
for pattern, artifact_type in bloat_patterns:
    fp = os.path.join(rootfs, pattern)
    if os.path.isdir(fp):
        total = sum(os.path.getsize(os.path.join(dp, f)) for dp, _, fns in os.walk(fp) for f in fns[:100])
        if total > 1024 * 100:  # > 100KB
            result["buildArtifacts"].append({"path": "/" + pattern, "type": artifact_type, "sizeBytes": total})

# Check for compilers/build tools (P2-6: multi-stage leak)
for tool in ["gcc", "g++", "make", "cmake", "go", "rustc", "javac"]:
    for search_dir in ["usr/bin", "usr/local/bin"]:
        if os.path.isfile(os.path.join(rootfs, search_dir, tool)):
            result["multiStageLeak"].append({"tool": tool, "path": f"/{search_dir}/{tool}"})

# Check for .git directories
for dirpath, dirnames, _ in os.walk(rootfs):
    if ".git" in dirnames:
        result["multiStageLeak"].append({"tool": ".git", "path": dirpath.replace(rootfs, "") + "/.git"})
    if len(result["multiStageLeak"]) >= 20: break

# ── P3-3: Cron analysis ──
for cron_path in ["etc/crontab", "etc/cron.d", "var/spool/cron/crontabs", "var/spool/cron"]:
    fp = os.path.join(rootfs, cron_path)
    if os.path.isfile(fp):
        try:
            with open(fp, errors="ignore") as f:
                content = f.read(5000)
                if re.search(r"curl|wget|nc |python|perl|ruby|/dev/tcp|bash -c", content):
                    result["cronJobs"].append({"file": "/" + cron_path, "suspicious": True, "preview": content[:200]})
                else:
                    result["cronJobs"].append({"file": "/" + cron_path, "suspicious": False})
        except: pass
    elif os.path.isdir(fp):
        for fn in os.listdir(fp)[:20]:
            cfp = os.path.join(fp, fn)
            try:
                with open(cfp, errors="ignore") as f:
                    content = f.read(5000)
                    suspicious = bool(re.search(r"curl|wget|nc |python|perl|ruby|/dev/tcp", content))
                    result["cronJobs"].append({"file": f"/{cron_path}/{fn}", "suspicious": suspicious})
            except: pass

# ── P3-6: Writable paths ──
for check_dir in ["usr/bin", "usr/sbin", "usr/local/bin", "etc", "bin", "sbin"]:
    fp = os.path.join(rootfs, check_dir)
    if os.path.isdir(fp):
        try:
            st = os.stat(fp)
            if st.st_mode & stat.S_IWOTH:
                result["writablePaths"].append({"path": "/" + check_dir, "mode": oct(st.st_mode)})
        except: pass

# ── P2-3: Certificate analysis ──
for dirpath, _, filenames in os.walk(rootfs):
    for fn in filenames[:200]:
        if fn.endswith((".pem", ".crt", ".cert", ".key", ".p12", ".pfx")):
            fp = os.path.join(dirpath, fn)
            rel = fp.replace(rootfs, "")
            info = {"file": rel, "type": fn.split(".")[-1]}
            try:
                with open(fp, "rb") as f:
                    content = f.read(5000)
                    if b"PRIVATE KEY" in content:
                        info["hasPrivateKey"] = True
                        result["secrets"].append({"file": rel, "match": "Private key bundled with certificate"})
                    if b"-----BEGIN CERTIFICATE" in content:
                        info["hasCert"] = True
            except: pass
            result["certificates"].append(info)

# ── Supply chain: forged keys / unofficial sources ──
apk_keys_dir = os.path.join(rootfs, "etc/apk/keys")
if os.path.isdir(apk_keys_dir):
    for kf in os.listdir(apk_keys_dir):
        if not kf.startswith("alpine-devel@"):
            result["forgedKeys"].append({"type": "apk", "file": f"/etc/apk/keys/{kf}"})

apk_repos = os.path.join(rootfs, "etc/apk/repositories")
if os.path.isfile(apk_repos):
    with open(apk_repos) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "alpine" not in line.lower():
                result["unofficialSources"].append({"type": "apk", "source": line})

apt_sources = os.path.join(rootfs, "etc/apt/sources.list")
if os.path.isfile(apt_sources):
    official = ["deb.debian.org", "archive.ubuntu.com", "security.debian.org", "security.ubuntu.com"]
    with open(apt_sources) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and not any(h in line for h in official):
                result["unofficialSources"].append({"type": "apt", "source": line})

# ── Layer analysis (symlinks, trojans, diffs) ──
try:
    manifest_path = os.path.join(container_dir, "manifest.json")
    if os.path.isfile(manifest_path):
        with open(manifest_path) as mf:
            manifest = json.load(mf)
        if isinstance(manifest, list) and manifest:
            layers = manifest[0].get("Layers", [])
            result["layers"] = len(layers)
            file_versions = {}

            for idx, layer_rel in enumerate(layers):
                layer_path = os.path.join(container_dir, layer_rel)
                if not os.path.isfile(layer_path): continue
                layer_diff = {"index": idx, "added": 0, "deleted": 0, "modified": 0, "whiteouts": []}
                try:
                    with tarfile.open(layer_path) as ltf:
                        for member in ltf.getmembers():
                            basename = os.path.basename(member.name)
                            # Symlink escape detection
                            if member.issym():
                                target = member.linkname
                                if target.startswith("/proc/self") or target.startswith("/proc/1"):
                                    result["symlinkEscapes"].append({"path": member.name, "target": target, "type": "proc_escape", "layer": idx})
                                norm = os.path.normpath(os.path.join(os.path.dirname(member.name), target))
                                if norm.startswith("../../../"):
                                    result["symlinkEscapes"].append({"path": member.name, "target": target, "type": "traversal", "layer": idx})
                            if member.islnk() and member.linkname.startswith(".."):
                                result["symlinkEscapes"].append({"path": member.name, "target": member.linkname, "type": "hardlink_traversal", "layer": idx})
                            # Whiteout detection
                            if basename.startswith(".wh."):
                                layer_diff["deleted"] += 1
                                layer_diff["whiteouts"].append(member.name)
                            elif member.name in file_versions:
                                layer_diff["modified"] += 1
                            else:
                                layer_diff["added"] += 1
                            # Track binary versions for trojan detection
                            if member.isfile() and member.name.startswith(("usr/bin/", "usr/sbin/", "usr/local/bin/", "bin/", "sbin/")):
                                file_versions.setdefault(member.name, []).append((idx, member.size))
                except: pass
                layer_diff["whiteouts"] = layer_diff["whiteouts"][:10]
                result["layerDiffs"].append(layer_diff)

            # Trojan detection: binaries modified across layers
            for path, versions in file_versions.items():
                if len(versions) > 1 and len(set(v[1] for v in versions)) > 1:
                    result["trojanLayers"].append({"path": path,
                        "versions": [{"layer": v[0], "size": v[1]} for v in versions]})
except: pass

# ── Truncate all arrays ──
for key in ["packages", "secrets", "setuid", "suspicious", "supplyChain",
            "forgedKeys", "unofficialSources", "symlinkEscapes", "trojanLayers",
            "layerDiffs", "elfBinaries", "sensitiveFiles", "configAudit",
            "cisBenchmark", "certificates", "capBinaries", "nestedArchives",
            "multiStageLeak", "buildArtifacts", "dockerfile", "cronJobs", "writablePaths"]:
    if isinstance(result.get(key), list):
        result[key] = result[key][:100]

print(json.dumps(result))
