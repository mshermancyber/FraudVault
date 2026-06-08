// ── Container Image Scanning + SBOM ─────────────────────────────────────────
//
// Analyzes Docker/OCI container images: extracts layers, generates SBOM,
// scans for vulnerabilities, and detects secrets/suspicious patterns.

// ── Result Types ────────────────────────────────────────────────────────────

export interface ContainerAnalysisResult {
  imageId: string;
  baseImage: string;
  layers: LayerInfo[];
  sbom: SbomEntry[];
  vulnerabilities: VulnerabilityFinding[];
  suspiciousLayers: SuspiciousLayer[];
  exposedPorts: number[];
  entrypoint: string[];
  env: Record<string, string>;
  secrets: string[];
}

export interface LayerInfo {
  digest: string;
  size: number;
  createdBy: string;
}

export interface SbomEntry {
  name: string;
  version: string;
  type: PackageType;
  license: string | null;
}

export type PackageType = 'deb' | 'rpm' | 'apk' | 'pip' | 'npm' | 'gem' | 'go';

export interface VulnerabilityFinding {
  package: string;
  version: string;
  cve: string;
  severity: VulnSeverity;
  fixedVersion: string | null;
}

export type VulnSeverity = 'critical' | 'high' | 'medium' | 'low' | 'unknown';

export interface SuspiciousLayer {
  index: number;
  reason: string;
  command: string;
}

// ── Secret Detection Patterns ───────────────────────────────────────────────

export const SECRET_PATTERNS: ReadonlyArray<{ name: string; pattern: string }> = [
  { name: 'AWS Access Key', pattern: 'AKIA[0-9A-Z]{16}' },
  { name: 'AWS Secret Key', pattern: '[0-9a-zA-Z/+]{40}' },
  { name: 'Private Key', pattern: '-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----' },
  { name: 'GitHub Token', pattern: 'gh[ps]_[0-9a-zA-Z]{36}' },
  { name: 'Generic Password', pattern: '(?i)(?:password|passwd|pwd)\\s*[=:]\\s*[^\\s]{8,}' },
  { name: 'Generic API Key', pattern: '(?i)(?:api[_-]?key|apikey)\\s*[=:]\\s*[0-9a-zA-Z_\\-]{20,}' },
  { name: 'Generic Secret', pattern: '(?i)(?:secret|token)\\s*[=:]\\s*[0-9a-zA-Z_\\-]{20,}' },
  { name: 'Database URL', pattern: '(?:postgres|mysql|mongodb|redis)://[^\\s]+@[^\\s]+' },
  { name: 'JWT Token', pattern: 'eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.' },
];

// ── Suspicious Command Patterns ─────────────────────────────────────────────

export const SUSPICIOUS_COMMANDS: ReadonlyArray<{ pattern: string; reason: string }> = [
  { pattern: 'curl.*\\|\\s*(?:sh|bash)', reason: 'Downloads and executes script from network (curl|sh)' },
  { pattern: 'wget.*\\|\\s*(?:sh|bash)', reason: 'Downloads and executes script from network (wget|sh)' },
  { pattern: 'curl.*\\|\\s*python', reason: 'Downloads and executes Python script from network' },
  { pattern: 'nc\\s+-[el]', reason: 'Netcat listener (potential reverse shell)' },
  { pattern: '/dev/tcp/', reason: 'Bash reverse shell using /dev/tcp' },
  { pattern: 'nmap\\s', reason: 'Network scanner embedded in image' },
  { pattern: 'masscan\\s', reason: 'Mass port scanner embedded in image' },
  { pattern: 'chmod\\s+[0-7]*[2367][0-7]*\\s', reason: 'World-writable file permissions set' },
  { pattern: 'chmod\\s+\\+s', reason: 'SUID bit set on executable' },
  { pattern: 'apt.*install.*(?:nmap|netcat|socat|ncat)', reason: 'Installing network recon/pivot tools' },
  { pattern: 'apk.*add.*(?:nmap|netcat|socat|ncat)', reason: 'Installing network recon/pivot tools' },
  { pattern: 'pip.*install.*(?:pwntools|impacket|responder)', reason: 'Installing offensive security tools' },
  { pattern: 'useradd.*-o.*-u\\s*0', reason: 'Creating user with UID 0 (root equivalent)' },
  { pattern: 'echo.*>>.*(?:/etc/passwd|/etc/shadow)', reason: 'Modifying system authentication files' },
  { pattern: 'iptables.*-D', reason: 'Deleting firewall rules' },
  { pattern: 'cryptominer|xmrig|minerd|cpuminer', reason: 'Cryptocurrency miner detected' },
];

// ── Analysis Script ─────────────────────────────────────────────────────────

/**
 * Returns a Python script that performs comprehensive container image analysis.
 * The script:
 * 1. Accepts an exported image tarball path as argument
 * 2. Extracts and analyzes each layer
 * 3. Parses package databases for SBOM
 * 4. Scans for secrets
 * 5. Checks for suspicious Dockerfile commands
 *
 * NOTE: This returns a self-contained Python script (not a bash+heredoc script)
 * that can be written to disk and executed directly with `python3 script.py <tarball>`.
 */
export function getContainerAnalysisScript(): string {
  // Build the secret patterns and suspicious command patterns as Python literals
  const secretPatternsLiteral = JSON.stringify(
    SECRET_PATTERNS.map(s => [s.pattern, s.name]),
  );
  const suspiciousCommandsLiteral = JSON.stringify(
    SUSPICIOUS_COMMANDS.map(s => [s.pattern, s.reason]),
  );

  // Use plain string concatenation to avoid template literal interpolation issues
  // with shell variables like ${WORK_DIR}
  const lines = [
    '#!/usr/bin/env python3',
    '"""FraudVault Container Image Analyzer - extracts SBOM, secrets, and suspicious layers."""',
    '',
    'import json',
    'import os',
    'import re',
    'import sys',
    'import tarfile',
    'import hashlib',
    'import tempfile',
    'import shutil',
    '',
    'SECRET_PATTERNS = ' + secretPatternsLiteral,
    'SUSPICIOUS_COMMANDS = ' + suspiciousCommandsLiteral,
    '',
    '',
    'def analyze_container_image(image_tarball_path):',
    '    """Analyze a docker-saved image tarball."""',
    '    result = {',
    '        "imageId": "",',
    '        "baseImage": "",',
    '        "layers": [],',
    '        "sbom": [],',
    '        "vulnerabilities": [],',
    '        "suspiciousLayers": [],',
    '        "exposedPorts": [],',
    '        "entrypoint": [],',
    '        "env": {},',
    '        "secrets": [],',
    '    }',
    '',
    '    if not os.path.isfile(image_tarball_path):',
    '        return {"error": "Tarball not found"}',
    '',
    '    work_dir = tempfile.mkdtemp(prefix="scanboy-container-")',
    '    try:',
    '        extract_dir = os.path.join(work_dir, "extracted")',
    '        os.makedirs(extract_dir, exist_ok=True)',
    '',
    '        # Extract image tarball',
    '        import tarfile as tf_module',
    '        with tf_module.open(image_tarball_path) as tf:',
    '            safe_members = [m for m in tf.getmembers() if not m.name.startswith("/") and ".." not in m.name]',
    '            tf.extractall(extract_dir, members=safe_members)',
    '',
    '        # Parse manifest.json',
    '        manifest_path = os.path.join(extract_dir, "manifest.json")',
    '        if not os.path.isfile(manifest_path):',
    '            return {"error": "No manifest.json found"}',
    '',
    '        with open(manifest_path) as f:',
    '            manifest = json.load(f)',
    '',
    '        if not manifest:',
    '            return {"error": "Empty manifest"}',
    '',
    '        config_file = manifest[0].get("Config", "")',
    '        layer_paths = manifest[0].get("Layers", [])',
    '        result["imageId"] = config_file.replace(".json", "").replace("blobs/sha256/", "")',
    '',
    '        # Parse image config',
    '        config_path = os.path.join(extract_dir, config_file) if config_file else ""',
    '        if config_path and os.path.isfile(config_path):',
    '            with open(config_path) as f:',
    '                config = json.load(f)',
    '',
    '            container_config = config.get("config", config.get("container_config", {}))',
    '            result["entrypoint"] = container_config.get("Entrypoint", []) or []',
    '',
    '            # Exposed ports',
    '            exposed = container_config.get("ExposedPorts", {})',
    '            for port_spec in exposed.keys():',
    '                port_num = port_spec.split("/")[0]',
    '                if port_num.isdigit():',
    '                    result["exposedPorts"].append(int(port_num))',
    '',
    '            # Environment variables',
    '            env_list = container_config.get("Env", []) or []',
    '            for env_entry in env_list:',
    '                if "=" in env_entry:',
    '                    key, _, value = env_entry.partition("=")',
    '                    result["env"][key] = value',
    '',
    '            # Layer history',
    '            history = config.get("history", [])',
    '            for i, entry in enumerate(history):',
    '                created_by = entry.get("created_by", "")',
    '                result["layers"].append({',
    '                    "digest": layer_paths[i] if i < len(layer_paths) else f"layer-{i}",',
    '                    "size": 0,',
    '                    "createdBy": created_by,',
    '                })',
    '',
    '                # Check for suspicious commands',
    '                for pattern, reason in SUSPICIOUS_COMMANDS:',
    '                    if re.search(pattern, created_by):',
    '                        result["suspiciousLayers"].append({',
    '                            "index": i,',
    '                            "reason": reason,',
    '                            "command": created_by[:200],',
    '                        })',
    '',
    '            # Detect base image',
    '            for entry in history:',
    '                created_by = entry.get("created_by", "")',
    '                if "FROM" in created_by or not entry.get("empty_layer", False):',
    '                    result["baseImage"] = created_by.replace("/bin/sh -c #(nop) ", "").strip()[:100]',
    '                    break',
    '',
    '        # Scan layers for packages and secrets',
    '        packages_found = {}',
    '',
    '        for layer_path in layer_paths:',
    '            full_path = os.path.join(extract_dir, layer_path)',
    '            if not os.path.isfile(full_path):',
    '                continue',
    '',
    '            layer_size = os.path.getsize(full_path)',
    '            for layer_info in result["layers"]:',
    '                if layer_info["digest"] == layer_path:',
    '                    layer_info["size"] = layer_size',
    '                    break',
    '',
    '            try:',
    '                with tarfile.open(full_path) as ltf:',
    '                    for member in ltf.getmembers():',
    '                        # Debian dpkg status',
    '                        if member.name.endswith("var/lib/dpkg/status"):',
    '                            try:',
    '                                f = ltf.extractfile(member)',
    '                                if f:',
    '                                    content = f.read().decode("utf-8", errors="ignore")',
    '                                    pkg = {}',
    '                                    for line in content.split("\\n"):',
    '                                        if line.startswith("Package: "): pkg = {"name": line[9:].strip()}',
    '                                        elif line.startswith("Version: ") and pkg: pkg["version"] = line[9:].strip()',
    '                                        elif line.startswith("Status: ") and "installed" in line: pkg["installed"] = True',
    '                                        elif line == "" and pkg.get("installed"):',
    '                                            n, v = pkg.get("name",""), pkg.get("version","")',
    '                                            if n and v: packages_found[f"deb:{n}"] = {"name":n,"version":v,"type":"deb","license":None}',
    '                                            pkg = {}',
    '                            except Exception: pass',
    '',
    '                        # Alpine apk installed',
    '                        elif "lib/apk/db/installed" in member.name:',
    '                            try:',
    '                                f = ltf.extractfile(member)',
    '                                if f:',
    '                                    content = f.read().decode("utf-8", errors="ignore")',
    '                                    pkg = {}',
    '                                    for line in content.split("\\n"):',
    '                                        if line.startswith("P:"): pkg["name"] = line[2:].strip()',
    '                                        elif line.startswith("V:"): pkg["version"] = line[2:].strip()',
    '                                        elif line.startswith("L:"): pkg["license"] = line[2:].strip()',
    '                                        elif line == "" and pkg.get("name"):',
    '                                            n = pkg["name"]',
    '                                            packages_found[f"apk:{n}"] = {"name":n,"version":pkg.get("version",""),"type":"apk","license":pkg.get("license")}',
    '                                            pkg = {}',
    '                            except Exception: pass',
    '',
    '                        # Python pip METADATA',
    '                        elif "site-packages" in member.name and member.name.endswith("METADATA"):',
    '                            try:',
    '                                f = ltf.extractfile(member)',
    '                                if f:',
    '                                    content = f.read().decode("utf-8", errors="ignore")',
    '                                    name, version, lic = "", "", None',
    '                                    for line in content.split("\\n")[:30]:',
    '                                        if line.startswith("Name: "): name = line[6:].strip()',
    '                                        elif line.startswith("Version: "): version = line[9:].strip()',
    '                                        elif line.startswith("License: "): lic = line[9:].strip()',
    '                                    if name and version:',
    '                                        packages_found[f"pip:{name}"] = {"name":name,"version":version,"type":"pip","license":lic}',
    '                            except Exception: pass',
    '',
    '                        # Node.js package.json',
    '                        elif "node_modules/" in member.name and member.name.endswith("/package.json"):',
    '                            parts = member.name.split("node_modules/")',
    '                            if len(parts) >= 2 and parts[-1].count("/") <= 2:',
    '                                try:',
    '                                    f = ltf.extractfile(member)',
    '                                    if f:',
    '                                        pkg_json = json.loads(f.read().decode("utf-8", errors="ignore"))',
    '                                        name = pkg_json.get("name", "")',
    '                                        version = pkg_json.get("version", "")',
    '                                        lic = pkg_json.get("license", None)',
    '                                        if isinstance(lic, dict): lic = lic.get("type", None)',
    '                                        if name and version:',
    '                                            packages_found[f"npm:{name}"] = {"name":name,"version":version,"type":"npm","license":lic}',
    '                                except Exception: pass',
    '',
    '                        # Secret scanning (text files < 1MB)',
    '                        if member.isfile() and member.size < 1024 * 1024:',
    '                            skip_exts = (".png",".jpg",".gif",".ico",".woff",".ttf",".eot",".so",".a",".o",".pyc",".class",".jar")',
    '                            if not member.name.endswith(skip_exts):',
    '                                try:',
    '                                    f = ltf.extractfile(member)',
    '                                    if f:',
    '                                        content = f.read().decode("utf-8", errors="ignore")',
    '                                        for pattern, secret_name in SECRET_PATTERNS:',
    '                                            matches = re.findall(pattern, content[:50000])',
    '                                            for match in matches[:3]:',
    '                                                redacted = match[:8]+"..."+match[-4:] if len(match)>16 else match[:4]+"..."',
    '                                                entry = f"{secret_name} in {member.name}: {redacted}"',
    '                                                if entry not in result["secrets"]:',
    '                                                    result["secrets"].append(entry)',
    '                                except Exception: pass',
    '            except Exception: pass',
    '',
    '        result["sbom"] = list(packages_found.values())',
    '        result["secrets"] = result["secrets"][:50]',
    '',
    '    finally:',
    '        shutil.rmtree(work_dir, ignore_errors=True)',
    '',
    '    return result',
    '',
    '',
    'if __name__ == "__main__":',
    '    if len(sys.argv) < 2:',
    '        print(json.dumps({"error": "Usage: container_analyzer.py <image_tarball>"}))',
    '        sys.exit(1)',
    '    result = analyze_container_image(sys.argv[1])',
    '    print(json.dumps(result, indent=2))',
    '',
  ];

  return lines.join('\n');
}

// ── Result Parsing ──────────────────────────────────────────────────────────

/**
 * Parse the JSON output from the container analysis script.
 */
export function parseContainerAnalysisOutput(jsonOutput: string): ContainerAnalysisResult | null {
  try {
    const parsed = JSON.parse(jsonOutput) as Record<string, unknown>;
    if ('error' in parsed) return null;

    return {
      imageId: String(parsed['imageId'] ?? ''),
      baseImage: String(parsed['baseImage'] ?? ''),
      layers: (parsed['layers'] as LayerInfo[]) ?? [],
      sbom: (parsed['sbom'] as SbomEntry[]) ?? [],
      vulnerabilities: (parsed['vulnerabilities'] as VulnerabilityFinding[]) ?? [],
      suspiciousLayers: (parsed['suspiciousLayers'] as SuspiciousLayer[]) ?? [],
      exposedPorts: (parsed['exposedPorts'] as number[]) ?? [],
      entrypoint: (parsed['entrypoint'] as string[]) ?? [],
      env: (parsed['env'] as Record<string, string>) ?? {},
      secrets: (parsed['secrets'] as string[]) ?? [],
    };
  } catch {
    return null;
  }
}

/**
 * Compute a risk score (0-100) for a container image based on analysis results.
 */
export function computeContainerRiskScore(result: ContainerAnalysisResult): number {
  let score = 0;

  // Suspicious layers
  score += Math.min(result.suspiciousLayers.length * 15, 45);

  // Secrets found
  if (result.secrets.length > 0) {
    score += Math.min(result.secrets.length * 5, 25);
  }

  // Vulnerabilities
  for (const vuln of result.vulnerabilities) {
    if (vuln.severity === 'critical') score += 10;
    else if (vuln.severity === 'high') score += 5;
    else if (vuln.severity === 'medium') score += 2;
  }

  // Running as root with exposed ports
  if (result.exposedPorts.length > 0 && !result.entrypoint.some(e => e.includes('--user'))) {
    score += 5;
  }

  // Sensitive environment variables
  const sensitiveEnvKeys = Object.keys(result.env).filter(k =>
    /password|secret|key|token|credential/i.test(k),
  );
  if (sensitiveEnvKeys.length > 0) {
    score += sensitiveEnvKeys.length * 5;
  }

  return Math.min(100, Math.max(0, score));
}
