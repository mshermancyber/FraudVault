import type pino from 'pino';

// ── Types ───────────────────────────────────────────────────────────────────

export interface NetworkEvent {
  readonly eventType: 'dns_query' | 'http_request' | 'tcp_connection' | 'udp_connection' | 'tls_handshake';
  readonly protocol: 'tcp' | 'udp' | 'dns' | 'http' | 'https' | 'tls';
  readonly sourceAddress: string;
  readonly sourcePort: number;
  readonly destinationAddress: string;
  readonly destinationPort: number;
  readonly domain: string | null;
  readonly url: string | null;
  readonly method: string | null;
  readonly userAgent: string | null;
  readonly statusCode: number | null;
  readonly bytesSent: number;
  readonly bytesReceived: number;
  readonly tlsCertSubject: string | null;
  readonly tlsCertIssuer: string | null;
  readonly timestamp: string;
  readonly isSuspicious: boolean;
  readonly suspiciousReason: string | null;
}

interface DnsQuery {
  readonly domain: string;
  readonly queryType: string;
  readonly responseAddresses: readonly string[];
  readonly timestamp: string;
}

// ── Constants ───────────────────────────────────────────────────────────────

const SUSPICIOUS_PORTS = new Set([
  4444, 5555, 6666, 7777, 8888, 9999, // Common backdoor ports
  1337, 31337, // Elite/hacker ports
  3389, // RDP (outbound is suspicious)
  445, 139, // SMB (outbound is suspicious from sandbox)
  22, // SSH (outbound from Windows sandbox)
]);

const SUSPICIOUS_DOMAINS_PATTERNS: readonly RegExp[] = [
  /\.onion$/i,
  /\.bit$/i,
  /\.i2p$/i,
  /^[a-z0-9]{30,}\./, // Long random-looking subdomains (DGA)
  /pastebin\./i,
  /paste\./i,
  /raw\.githubusercontent/i,
  /discord(?:app)?\.com\/api\/webhooks/i,
  /telegram\.org\/bot/i,
];

/** Common C2 URL patterns - exported for use by callers. */
export const KNOWN_C2_PATTERNS: readonly RegExp[] = [
  /\/gate\.php$/i,
  /\/panel\//i,
  /\/admin\/gate/i,
  /\/upload\.php$/i,
  /\/c2\//i,
  /\/beacon/i,
  /\/connect\.php$/i,
];

/** Suspicious user agent patterns - exported for use by callers. */
export const SUSPICIOUS_USER_AGENTS: readonly RegExp[] = [
  /^python-/i,
  /^curl\//i,
  /^wget\//i,
  /^powershell/i,
  /^go-http/i,
  /^java\//i,
  /^okhttp/i,
];

// ── Network Monitor ─────────────────────────────────────────────────────────

export class NetworkMonitor {
  private readonly events: NetworkEvent[] = [];
  private readonly dnsQueries: DnsQuery[] = [];
  private readonly seenConnections = new Set<string>();

  private readonly logger: pino.Logger;

  constructor(logger: pino.Logger) {
    this.logger = logger;
  }

  /**
   * Ingest raw output from network monitoring (netstat, ss, DNS logs, etc.).
   */
  ingestRawOutput(raw: string): void {
    const lines = raw.split('\n').filter((l) => l.trim().length > 0);
    let newCount = 0;

    for (const line of lines) {
      const events = this.parseLine(line);
      for (const event of events) {
        this.addEvent(event);
        newCount++;
      }
    }

    if (newCount > 0) {
      this.logger.debug({ newEvents: newCount }, 'Ingested network events');
    }
  }

  /**
   * Add a network event directly.
   */
  addEvent(event: NetworkEvent): void {
    const key = `${event.protocol}:${event.sourceAddress}:${event.sourcePort}:${event.destinationAddress}:${event.destinationPort}`;
    if (this.seenConnections.has(key)) return;
    this.seenConnections.add(key);

    this.events.push(event);

    if (event.eventType === 'dns_query' && event.domain) {
      this.dnsQueries.push({
        domain: event.domain,
        queryType: 'A',
        responseAddresses: event.destinationAddress ? [event.destinationAddress] : [],
        timestamp: event.timestamp,
      });
    }
  }

  /**
   * Get all recorded network events.
   */
  getEvents(): NetworkEvent[] {
    return [...this.events];
  }

  /**
   * Get all DNS queries.
   */
  getDnsQueries(): DnsQuery[] {
    return [...this.dnsQueries];
  }

  /**
   * Get unique domains contacted.
   */
  getContactedDomains(): string[] {
    const domains = new Set<string>();
    for (const event of this.events) {
      if (event.domain) {
        domains.add(event.domain);
      }
    }
    return [...domains];
  }

  /**
   * Get unique IP addresses contacted.
   */
  getContactedIps(): string[] {
    const ips = new Set<string>();
    for (const event of this.events) {
      if (event.destinationAddress) {
        ips.add(event.destinationAddress);
      }
    }
    return [...ips];
  }

  /**
   * Get HTTP/HTTPS requests.
   */
  getHttpRequests(): NetworkEvent[] {
    return this.events.filter(
      (e) => e.eventType === 'http_request' || e.protocol === 'http' || e.protocol === 'https',
    );
  }

  /**
   * Get all user agents observed.
   */
  getUserAgents(): string[] {
    const agents = new Set<string>();
    for (const event of this.events) {
      if (event.userAgent) {
        agents.add(event.userAgent);
      }
    }
    return [...agents];
  }

  /**
   * Get TLS certificate information.
   */
  getTlsCertificates(): Array<{ subject: string; issuer: string }> {
    const certs: Array<{ subject: string; issuer: string }> = [];
    const seen = new Set<string>();

    for (const event of this.events) {
      if (event.tlsCertSubject) {
        const key = `${event.tlsCertSubject}:${event.tlsCertIssuer ?? ''}`;
        if (!seen.has(key)) {
          seen.add(key);
          certs.push({
            subject: event.tlsCertSubject,
            issuer: event.tlsCertIssuer ?? 'unknown',
          });
        }
      }
    }

    return certs;
  }

  /**
   * Get suspicious network events.
   */
  getSuspiciousEvents(): NetworkEvent[] {
    return this.events.filter((e) => e.isSuspicious);
  }

  // ── Private helpers ─────────────────────────────────────────────────────

  private parseLine(line: string): NetworkEvent[] {
    const events: NetworkEvent[] = [];

    // netstat -anob format: proto  local_addr  foreign_addr  state  [process]
    const netstatMatch = line.match(
      /^\s*(TCP|UDP)\s+(\S+):(\d+)\s+(\S+):(\d+)\s+(\S+)?/i,
    );
    if (netstatMatch) {
      const event = this.parseNetstat(netstatMatch);
      if (event) events.push(event);
      return events;
    }

    // ss -tupn format: proto State Recv-Q Send-Q Local:Port Peer:Port Process
    const ssMatch = line.match(
      /^(tcp|udp)\s+\S+\s+\d+\s+\d+\s+(\S+):(\d+)\s+(\S+):(\d+)/i,
    );
    if (ssMatch) {
      const event = this.parseSs(ssMatch);
      if (event) events.push(event);
      return events;
    }

    // DNS query format (from strace connect calls): connect(..., {sa_family=AF_INET, sin_port=htons(53)...
    const dnsMatch = line.match(
      /connect\([^,]+,\s*\{[^}]*sin_port=htons\(53\)[^}]*sin_addr=inet_addr\("([^"]+)"\)/,
    );
    if (dnsMatch) {
      events.push(this.createDnsEvent(dnsMatch[1] ?? ''));
      return events;
    }

    // General connect syscall
    const connectMatch = line.match(
      /connect\([^,]+,\s*\{[^}]*sin_port=htons\((\d+)\)[^}]*sin_addr=inet_addr\("([^"]+)"\)/,
    );
    if (connectMatch) {
      const port = parseInt(connectMatch[1] ?? '0', 10);
      const addr = connectMatch[2] ?? '';
      if (!Number.isNaN(port)) {
        events.push(this.createTcpEvent(addr, port));
      }
      return events;
    }

    return events;
  }

  private parseNetstat(match: RegExpMatchArray): NetworkEvent | null {
    const proto = (match[1] ?? 'tcp').toLowerCase() as 'tcp' | 'udp';
    const localAddr = match[2] ?? '0.0.0.0';
    const localPort = parseInt(match[3] ?? '0', 10);
    const remoteAddr = match[4] ?? '0.0.0.0';
    const remotePort = parseInt(match[5] ?? '0', 10);

    if (remoteAddr === '0.0.0.0' || remoteAddr === '*' || remoteAddr === '[::]') {
      return null; // Listening socket, not a connection
    }

    const isSuspicious = this.isConnectionSuspicious(remoteAddr, remotePort, null);

    return {
      eventType: proto === 'udp' ? 'udp_connection' : 'tcp_connection',
      protocol: proto,
      sourceAddress: localAddr,
      sourcePort: localPort,
      destinationAddress: remoteAddr,
      destinationPort: remotePort,
      domain: null,
      url: null,
      method: null,
      userAgent: null,
      statusCode: null,
      bytesSent: 0,
      bytesReceived: 0,
      tlsCertSubject: null,
      tlsCertIssuer: null,
      timestamp: new Date().toISOString(),
      isSuspicious: isSuspicious.flag,
      suspiciousReason: isSuspicious.reason,
    };
  }

  private parseSs(match: RegExpMatchArray): NetworkEvent | null {
    const proto = (match[1] ?? 'tcp').toLowerCase() as 'tcp' | 'udp';
    const localAddr = match[2] ?? '0.0.0.0';
    const localPort = parseInt(match[3] ?? '0', 10);
    const remoteAddr = match[4] ?? '0.0.0.0';
    const remotePort = parseInt(match[5] ?? '0', 10);

    if (remoteAddr === '0.0.0.0' || remoteAddr === '*') {
      return null;
    }

    const isSuspicious = this.isConnectionSuspicious(remoteAddr, remotePort, null);

    return {
      eventType: proto === 'udp' ? 'udp_connection' : 'tcp_connection',
      protocol: proto,
      sourceAddress: localAddr,
      sourcePort: localPort,
      destinationAddress: remoteAddr,
      destinationPort: remotePort,
      domain: null,
      url: null,
      method: null,
      userAgent: null,
      statusCode: null,
      bytesSent: 0,
      bytesReceived: 0,
      tlsCertSubject: null,
      tlsCertIssuer: null,
      timestamp: new Date().toISOString(),
      isSuspicious: isSuspicious.flag,
      suspiciousReason: isSuspicious.reason,
    };
  }

  private createDnsEvent(serverAddr: string): NetworkEvent {
    return {
      eventType: 'dns_query',
      protocol: 'dns',
      sourceAddress: '0.0.0.0',
      sourcePort: 0,
      destinationAddress: serverAddr,
      destinationPort: 53,
      domain: null,
      url: null,
      method: null,
      userAgent: null,
      statusCode: null,
      bytesSent: 0,
      bytesReceived: 0,
      tlsCertSubject: null,
      tlsCertIssuer: null,
      timestamp: new Date().toISOString(),
      isSuspicious: false,
      suspiciousReason: null,
    };
  }

  private createTcpEvent(addr: string, port: number): NetworkEvent {
    const isSuspicious = this.isConnectionSuspicious(addr, port, null);

    return {
      eventType: 'tcp_connection',
      protocol: 'tcp',
      sourceAddress: '0.0.0.0',
      sourcePort: 0,
      destinationAddress: addr,
      destinationPort: port,
      domain: null,
      url: null,
      method: null,
      userAgent: null,
      statusCode: null,
      bytesSent: 0,
      bytesReceived: 0,
      tlsCertSubject: null,
      tlsCertIssuer: null,
      timestamp: new Date().toISOString(),
      isSuspicious: isSuspicious.flag,
      suspiciousReason: isSuspicious.reason,
    };
  }

  private isConnectionSuspicious(
    addr: string,
    port: number,
    domain: string | null,
  ): { flag: boolean; reason: string | null } {
    // Check suspicious ports
    if (SUSPICIOUS_PORTS.has(port)) {
      return {
        flag: true,
        reason: `Connection to suspicious port ${port}`,
      };
    }

    // Check suspicious domains
    if (domain) {
      for (const pattern of SUSPICIOUS_DOMAINS_PATTERNS) {
        if (pattern.test(domain)) {
          return {
            flag: true,
            reason: `Connection to suspicious domain: ${domain}`,
          };
        }
      }
    }

    // Check for connections to RFC1918 addresses (possible lateral movement)
    if (this.isPrivateIp(addr)) {
      return {
        flag: true,
        reason: `Connection to private IP: ${addr} (possible lateral movement)`,
      };
    }

    return { flag: false, reason: null };
  }

  private isPrivateIp(ip: string): boolean {
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4) return false;

    const [a, b] = parts;
    if (a === undefined || b === undefined) return false;

    // 10.0.0.0/8
    if (a === 10) return true;
    // 172.16.0.0/12
    if (a === 172 && b >= 16 && b <= 31) return true;
    // 192.168.0.0/16
    if (a === 192 && b === 168) return true;
    // 169.254.0.0/16
    if (a === 169 && b === 254) return true;

    return false;
  }
}
