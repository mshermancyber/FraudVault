// ── Offline-Only Vulnerability Lookup Client ────────────────────────────────
//
// Pure local client. Queries the vuln-feeds SQLite service only.
// NEVER makes live API calls during scans. If feeds are down, returns empty.

import type pg from 'pg';

// ── Types ──────────────────────────────────────────────────────────────────────

export interface PeVersionInfo {
  ProductName?: string;
  CompanyName?: string;
  FileVersion?: string;
  ProductVersion?: string;
  FileDescription?: string;
  OriginalFilename?: string;
  InternalName?: string;
}

export interface CveEntry {
  id: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  cvssScore: number;
  publishedDate: string;
  isKev: boolean;
  epssScore: number;
  epssPercentile: number;
  references: string[];
}

export interface VulnResult {
  cves: CveEntry[];
  softwareName: string;
  softwareVersion: string;
}

export interface TechDebtResult {
  productName: string;
  installedVersion: string;
  latestVersion: string | null;
  majorsBehind: number | null;
  isEol: boolean;
  eolDate: string | null;
  releaseDate: string | null;
}

export interface CpeClassification {
  cpeUri: string | null;
  vendor: string | null;
  product: string | null;
  version: string | null;
  category: string;
  classification: string;
  confidence: number;
}

export interface SbomVulnQuery {
  name: string;
  version: string;
  ecosystem: string;
}

// ── Feeds Service ──────────────────────────────────────────────────────────────

const FEEDS_URL = process.env['VULN_FEEDS_URL'] ?? 'http://vuln-feeds:9000';
const TIMEOUT = 10_000;

async function post(path: string, body: unknown): Promise<Record<string, unknown> | null> {
  try {
    const r = await fetch(`${FEEDS_URL}${path}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(process.env['INTERNAL_API_KEY'] ? { 'x-internal-api-key': process.env['INTERNAL_API_KEY'] } : {}),
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(TIMEOUT),
    });
    return r.ok ? (await r.json() as Record<string, unknown>) : null;
  } catch { return null; }
}

// ── Product Lookup Tables ──────────────────────────────────────────────────────

// Product name → normalized slug (handles special characters)
const PRODUCT_SLUG_MAP: Record<string, string> = {
  'notepad++': 'notepad-plus-plus',
  'notepad plus plus': 'notepad-plus-plus',
  'c++': 'cpp',
  '7-zip': '7-zip',
  '.net': 'dotnet',
  '.net framework': 'dotnet-framework',
  'visual studio code': 'vscode',
  'visual studio': 'visual-studio',
  'adobe acrobat reader': 'acrobat-reader',
  'adobe acrobat': 'acrobat-reader',
};

const PRODUCT_CATEGORIES: Record<string, string> = {
  chrome: 'Web Browser', firefox: 'Web Browser', edge: 'Web Browser', safari: 'Web Browser',
  webex: 'Communication Software', zoom: 'Communication Software', teams: 'Communication Software',
  outlook: 'Email Client', thunderbird: 'Email Client',
  word: 'Office Suite', excel: 'Office Suite', powerpoint: 'Office Suite',
  acrobat: 'Document Viewer', 'acrobat-reader': 'Document Viewer', vlc: 'Media Player',
  vscode: 'Development Tool', 'visual-studio': 'Development Tool',
  putty: 'Remote Access Tool', wireshark: 'Network Analysis Tool',
  '7-zip': 'Archive Tool', git: 'Version Control',
  python: 'Runtime', node: 'Runtime', java: 'Runtime', dotnet: 'Runtime',
  nginx: 'Web Server', apache: 'Web Server',
  mysql: 'Database', postgres: 'Database', redis: 'Database',
  'notepad-plus-plus': 'Text Editor', notepad: 'Text Editor',
};

const CPE_MAP: Record<string, string> = {
  chrome: 'cpe:2.3:a:google:chrome', firefox: 'cpe:2.3:a:mozilla:firefox',
  edge: 'cpe:2.3:a:microsoft:edge', webex: 'cpe:2.3:a:cisco:webex',
  zoom: 'cpe:2.3:a:zoom:zoom', teams: 'cpe:2.3:a:microsoft:teams',
  outlook: 'cpe:2.3:a:microsoft:outlook', acrobat: 'cpe:2.3:a:adobe:acrobat_reader',
  vlc: 'cpe:2.3:a:videolan:vlc_media_player', putty: 'cpe:2.3:a:putty:putty',
  wireshark: 'cpe:2.3:a:wireshark:wireshark', python: 'cpe:2.3:a:python:python',
  java: 'cpe:2.3:a:oracle:jdk', nginx: 'cpe:2.3:a:nginx:nginx',
  'notepad-plus-plus': 'cpe:2.3:a:notepad-plus-plus:notepad-plus-plus',
};

function normalize(name: string): string {
  const lower = name.toLowerCase().trim();
  // Check special slug mappings first (handles ++, .NET, etc.)
  if (PRODUCT_SLUG_MAP[lower]) return PRODUCT_SLUG_MAP[lower];
  for (const [key, slug] of Object.entries(PRODUCT_SLUG_MAP)) {
    if (lower.includes(key)) return slug;
  }
  return lower.replace(/\s+(inc\.?|corp\.?|ltd\.?|llc|systems|software)$/i, '').replace(/[^a-z0-9\-]/g, '').trim();
}

// ── Vendor normalization for CPE matching ──────────────────────────────────────

const VENDOR_ALIASES: Record<string, string> = {
  'cisco systems': 'cisco',
  'cisco systems inc': 'cisco',
  'microsoft corporation': 'microsoft',
  'microsoft corp': 'microsoft',
  'google llc': 'google',
  'google inc': 'google',
  'adobe inc': 'adobe',
  'adobe systems': 'adobe',
  'adobe systems incorporated': 'adobe',
  'apple inc': 'apple',
  'mozilla corporation': 'mozilla',
  'mozilla foundation': 'mozilla',
  'oracle corporation': 'oracle',
  'ibm corporation': 'ibm',
  'ibm corp': 'ibm',
  'sap se': 'sap',
  'vmware inc': 'vmware',
  'broadcom inc': 'broadcom',
  'fortinet inc': 'fortinet',
  'palo alto networks': 'paloaltonetworks',
  'juniper networks': 'juniper',
  'siemens ag': 'siemens',
  'dell technologies': 'dell',
  'dell inc': 'dell',
  'hewlett packard enterprise': 'hpe',
  'hp inc': 'hp',
  'red hat inc': 'redhat',
  'red hat': 'redhat',
  'canonical ltd': 'canonical',
  'videolan': 'videolan',
  'the putty team': 'putty',
  'wireshark foundation': 'wireshark',
  'python software foundation': 'python',
  'nodejs': 'nodejs',
  'node.js foundation': 'nodejs',
  'openjs foundation': 'nodejs',
};

function normalizeVendor(companyName: string): string {
  const lower = companyName.toLowerCase()
    .replace(/,/g, '')
    .replace(/\s+(inc\.?|corp\.?|corporation|ltd\.?|llc|gmbh|co\.?|plc|ag|se|s\.a\.?)$/i, '')
    .trim();

  // Check exact alias match
  if (VENDOR_ALIASES[lower]) return VENDOR_ALIASES[lower];

  // Check if any alias key is a prefix
  for (const [alias, normalized] of Object.entries(VENDOR_ALIASES)) {
    if (lower.startsWith(alias)) return normalized;
  }

  // Fallback: strip non-alphanumeric
  return lower.replace(/[^a-z0-9\-]/g, '').trim();
}

function normalizeProduct(productName: string): string {
  return productName
    .toLowerCase()
    .replace(/[^a-z0-9\-_]/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_|_$/g, '')
    .trim();
}

function extractVersion(versionInfo: PeVersionInfo): string {
  const raw = versionInfo.FileVersion ?? versionInfo.ProductVersion ?? '';
  // FileVersion can be like "21.33.0.123" or "21, 33, 0, 123" — normalize
  return raw.replace(/,\s*/g, '.').replace(/\s+/g, '').trim();
}

// ── CPE Lookup Response Types ──────────────────────────────────────────────────

interface CpeLookupResponseEntry {
  cve: string;
  score: number | null;
  severity: string | null;
  kev: boolean;
  kevDueDate: string | null;
  epss: number | null;
  epssPercentile: number | null;
  version: string | null;
  vector: string | null;
  cwes: string[];
  refs: string[];
}

interface CpeLookupResponse {
  results: CpeLookupResponseEntry[];
}

// ── Exported Functions ─────────────────────────────────────────────────────────

export async function lookupVulnerabilities(versionInfo: PeVersionInfo): Promise<VulnResult> {
  const productName = versionInfo.ProductName ?? versionInfo.InternalName ?? '';
  const version = extractVersion(versionInfo);
  if (!productName) return { cves: [], softwareName: '', softwareVersion: '' };

  const cves: CveEntry[] = [];
  const seenCves = new Set<string>();

  // Strategy 1: CPE-based lookup using vendor + product + version
  const companyName = versionInfo.CompanyName ?? '';
  if (companyName) {
    const vendor = normalizeVendor(companyName);
    const product = normalizeProduct(productName);

    if (vendor && product) {
      const cpeResult = await post('/feeds/cpe-lookup', {
        vendor,
        product,
        version: version || undefined,
      });

      if (cpeResult) {
        const response = cpeResult as unknown as CpeLookupResponse;
        if (Array.isArray(response.results)) {
          for (const d of response.results) {
            if (seenCves.has(d.cve)) continue;
            seenCves.add(d.cve);
            cves.push({
              id: d.cve,
              description: '',
              severity: (String(d.severity ?? 'medium').toLowerCase() as CveEntry['severity']),
              cvssScore: typeof d.score === 'number' ? d.score : 0,
              publishedDate: '',
              isKev: d.kev === true,
              epssScore: typeof d.epss === 'number' ? d.epss : 0,
              epssPercentile: typeof d.epssPercentile === 'number' ? d.epssPercentile : 0,
              references: Array.isArray(d.refs) ? d.refs : [],
            });
          }
        }
      }
    }
  }

  // Strategy 2: Also try the well-known CPE_MAP slug for fallback
  const slug = normalize(productName);
  if (CPE_MAP[slug]) {
    // Extract vendor and product from the CPE URI pattern "cpe:2.3:a:vendor:product"
    const cpeParts = CPE_MAP[slug].split(':');
    const mappedVendor = cpeParts[3];
    const mappedProduct = cpeParts[4];

    if (mappedVendor && mappedProduct) {
      const cpeResult = await post('/feeds/cpe-lookup', {
        vendor: mappedVendor,
        product: mappedProduct,
        version: version || undefined,
      });

      if (cpeResult) {
        const response = cpeResult as unknown as CpeLookupResponse;
        if (Array.isArray(response.results)) {
          for (const d of response.results) {
            if (seenCves.has(d.cve)) continue;
            seenCves.add(d.cve);
            cves.push({
              id: d.cve,
              description: '',
              severity: (String(d.severity ?? 'medium').toLowerCase() as CveEntry['severity']),
              cvssScore: typeof d.score === 'number' ? d.score : 0,
              publishedDate: '',
              isKev: d.kev === true,
              epssScore: typeof d.epss === 'number' ? d.epss : 0,
              epssPercentile: typeof d.epssPercentile === 'number' ? d.epssPercentile : 0,
              references: Array.isArray(d.refs) ? d.refs : [],
            });
          }
        }
      }
    }
  }

  // Strategy 3: Try slug as both vendor AND product (common for OSS where vendor=product)
  if (cves.length === 0 && slug) {
    const cpeResult = await post('/feeds/cpe-lookup', {
      vendor: slug,
      product: slug,
      version: version || undefined,
    });
    if (cpeResult) {
      const response = cpeResult as unknown as CpeLookupResponse;
      if (Array.isArray(response.results)) {
        for (const d of response.results) {
          if (seenCves.has(d.cve)) continue;
          seenCves.add(d.cve);
          cves.push({
            id: d.cve,
            description: '',
            severity: (String(d.severity ?? 'medium').toLowerCase() as CveEntry['severity']),
            cvssScore: typeof d.score === 'number' ? d.score : 0,
            publishedDate: '',
            isKev: d.kev === true,
            epssScore: typeof d.epss === 'number' ? d.epss : 0,
            epssPercentile: typeof d.epssPercentile === 'number' ? d.epssPercentile : 0,
            references: Array.isArray(d.refs) ? d.refs : [],
          });
        }
      }
    }
  }

  // Strategy 4: Fall back to enriched table keyword search (original behavior)
  if (cves.length === 0) {
    const result = await post('/feeds/enriched', {
      cves: [],
      keyword: `${productName} ${version}`.trim(),
    });

    if (result) {
      const results = result['results'] as Record<string, Record<string, unknown>> | undefined;
      if (results) {
        for (const [id, d] of Object.entries(results)) {
          if (seenCves.has(id)) continue;
          seenCves.add(id);
          cves.push({
            id,
            description: '',
            severity: (String(d['severity'] ?? 'medium').toLowerCase() as CveEntry['severity']),
            cvssScore: typeof d['score'] === 'number' ? d['score'] : 0,
            publishedDate: '',
            isKev: d['kev'] === true || d['kev'] === 1,
            epssScore: typeof d['epss'] === 'number' ? d['epss'] : 0,
            epssPercentile: typeof d['percentile'] === 'number' ? d['percentile'] : 0,
            references: Array.isArray(d['refs']) ? d['refs'] as string[] : [],
          });
        }
      }
    }
  }

  cves.sort((a, b) => {
    if (a.isKev !== b.isKev) return a.isKev ? -1 : 1;
    return b.cvssScore - a.cvssScore;
  });

  return { cves, softwareName: productName, softwareVersion: version };
}

export async function lookupSbomVulnerabilities(
  _packages: SbomVulnQuery[],
): Promise<Array<{ package: string; version: string; vulns: CveEntry[] }>> {
  // SBOM scanning uses local OSV cache via osv-scanner binary — not implemented yet
  return _packages.map(p => ({ package: p.name, version: p.version, vulns: [] }));
}

export async function lookupTechDebt(
  productName: string,
  version: string,
): Promise<TechDebtResult | null> {
  const slug = normalize(productName);
  const result = await post('/feeds/endoflife', { product: slug });
  if (!result || result['found'] !== true) return null;
  const latestVersion = result['latestVersion'] as string | null;
  const cycles = result['cycles'] as Array<{ cycle: string; latest: string; eol: boolean | string; lts: boolean; releaseDate: string }> | undefined;
  if (!cycles || cycles.length === 0 || !latestVersion) return null;
  const installedMajor = version.split('.')[0] ?? '';
  const latestMajor = latestVersion.split('.')[0] ?? '';
  const majorsBehind = Math.max(0, parseInt(latestMajor, 10) - parseInt(installedMajor, 10));
  const matchedCycle = cycles.find(c => version.startsWith(c.cycle) || c.cycle === installedMajor);
  const isEol = matchedCycle?.eol === true || (typeof matchedCycle?.eol === 'string' && new Date(matchedCycle.eol).getTime() < Date.now());
  return {
    productName,
    installedVersion: version,
    latestVersion,
    majorsBehind: isNaN(majorsBehind) ? null : majorsBehind,
    isEol,
    eolDate: typeof matchedCycle?.eol === 'string' ? matchedCycle.eol : null,
    releaseDate: matchedCycle?.releaseDate ?? null,
  };
}

export async function classifyApplicationFromCpe(
  productName: string,
  version?: string,
): Promise<CpeClassification | null> {
  const slug = normalize(productName);
  return {
    cpeUri: CPE_MAP[slug] ?? null,
    vendor: null,
    product: slug,
    version: version ?? null,
    category: 'application',
    classification: PRODUCT_CATEGORIES[slug] ?? 'Unknown',
    confidence: CPE_MAP[slug] ? 90 : 50,
  };
}

export async function storeCpeClassification(
  pool: pg.Pool,
  submissionId: string,
  classification: CpeClassification,
): Promise<void> {
  await pool.query(
    `INSERT INTO threat_intel_results (submission_id, provider, verdict, detection_count, total_engines, malware_family, raw_response)
     VALUES ($1, 'cpe-classification', 'info', 0, 0, NULL, $2)
     ON CONFLICT DO NOTHING`,
    [submissionId, JSON.stringify(classification)],
  );
}
