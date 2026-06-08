import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import type pino from 'pino';
import { InternetMode } from '@scanboy/shared';

const execFileAsync = promisify(execFile);

// ── Types ───────────────────────────────────────────────────────────────────

interface IptablesRule {
  readonly chain: string;
  readonly table: string;
  readonly args: readonly string[];
  readonly comment: string;
}

interface NetworkIsolationPolicy {
  readonly instanceId: string;
  readonly tapInterface: string;
  readonly internetMode: InternetMode;
  readonly allowedDnsServers: readonly string[];
  readonly allowedHosts: readonly string[];
}

interface BlockedRange {
  readonly cidr: string;
  readonly description: string;
}

// ── Constants ───────────────────────────────────────────────────────────────

const BLOCKED_PRIVATE_RANGES: readonly BlockedRange[] = [
  { cidr: '10.0.0.0/8', description: 'RFC1918 Class A private' },
  { cidr: '172.16.0.0/12', description: 'RFC1918 Class B private' },
  { cidr: '192.168.0.0/16', description: 'RFC1918 Class C private' },
  { cidr: '169.254.0.0/16', description: 'Link-local addresses' },
  { cidr: '100.64.0.0/10', description: 'Carrier-grade NAT (RFC6598)' },
  { cidr: '198.18.0.0/15', description: 'Benchmark testing (RFC2544)' },
];

const BLOCKED_INFRASTRUCTURE_RANGES: readonly BlockedRange[] = [
  { cidr: '127.0.0.0/8', description: 'Loopback' },
  { cidr: '0.0.0.0/8', description: 'Current network' },
  { cidr: '224.0.0.0/4', description: 'Multicast' },
  { cidr: '240.0.0.0/4', description: 'Reserved' },
  { cidr: 'fc00::/7', description: 'IPv6 unique local' },
  { cidr: 'fe80::/10', description: 'IPv6 link-local' },
];

const SCANBOY_CHAIN = 'SCANBOY-SANDBOX';

// ── Network isolation service ───────────────────────────────────────────────

export class NetworkIsolationService {
  private readonly activePolicies = new Map<string, NetworkIsolationPolicy>();

  constructor(private readonly logger: pino.Logger) {}

  /**
   * Initialize the FraudVault iptables chain (idempotent).
   */
  async initialize(): Promise<void> {
    // Create custom chain if it doesn't exist
    await this.safeIptables(['-N', SCANBOY_CHAIN]);
    await this.safeIptables(['-t', 'nat', '-N', SCANBOY_CHAIN]);

    // Ensure our chain is referenced from FORWARD
    await this.safeIptables([
      '-C', 'FORWARD', '-j', SCANBOY_CHAIN,
    ]).catch(async () => {
      await this.iptables(['-I', 'FORWARD', '1', '-j', SCANBOY_CHAIN]);
    });

    this.logger.info('Network isolation iptables chain initialized');
  }

  /**
   * Apply network isolation rules for a sandbox instance.
   */
  async applyPolicy(policy: NetworkIsolationPolicy): Promise<void> {
    const { instanceId, tapInterface, internetMode } = policy;

    this.logger.info(
      { instanceId, tapInterface, internetMode },
      'Applying network isolation policy',
    );

    const rules = this.buildRules(policy);

    for (const rule of rules) {
      await this.iptables([
        '-t', rule.table,
        '-A', rule.chain,
        ...rule.args,
        '-m', 'comment', '--comment', rule.comment,
      ]);
    }

    this.activePolicies.set(instanceId, policy);

    this.logger.info(
      { instanceId, ruleCount: rules.length },
      'Network isolation policy applied',
    );
  }

  /**
   * Remove all network isolation rules for a sandbox instance.
   */
  async removePolicy(instanceId: string): Promise<void> {
    const policy = this.activePolicies.get(instanceId);
    if (!policy) {
      this.logger.warn(
        { instanceId },
        'No active network isolation policy found',
      );
      return;
    }

    const rules = this.buildRules(policy);

    // Remove rules in reverse order
    for (const rule of rules.reverse()) {
      await this.safeIptables([
        '-t', rule.table,
        '-D', rule.chain,
        ...rule.args,
        '-m', 'comment', '--comment', rule.comment,
      ]);
    }

    this.activePolicies.delete(instanceId);

    this.logger.info({ instanceId }, 'Network isolation policy removed');
  }

  /**
   * Remove all FraudVault sandbox rules (for cleanup on shutdown).
   */
  async flushAll(): Promise<void> {
    await this.safeIptables(['-F', SCANBOY_CHAIN]);
    await this.safeIptables(['-t', 'nat', '-F', SCANBOY_CHAIN]);

    this.activePolicies.clear();
    this.logger.info('All network isolation rules flushed');
  }

  /**
   * Get the currently active policies.
   */
  getActivePolicies(): ReadonlyMap<string, NetworkIsolationPolicy> {
    return this.activePolicies;
  }

  // ── Rule building ─────────────────────────────────────────────────────────

  private buildRules(policy: NetworkIsolationPolicy): IptablesRule[] {
    const { tapInterface, internetMode, instanceId } = policy;
    const tag = `scanboy-${instanceId.slice(0, 8)}`;
    const rules: IptablesRule[] = [];

    switch (internetMode) {
      case InternetMode.Disabled:
        rules.push(...this.buildIsolatedRules(tapInterface, tag));
        break;

      case InternetMode.Simulated:
        rules.push(...this.buildSimulatedRules(tapInterface, tag, policy));
        break;

      case InternetMode.Monitored:
        rules.push(...this.buildMonitoredRules(tapInterface, tag, policy));
        break;
    }

    return rules;
  }

  /**
   * Fully isolated: no outbound traffic at all.
   */
  private buildIsolatedRules(
    tapInterface: string,
    tag: string,
  ): IptablesRule[] {
    return [
      {
        chain: SCANBOY_CHAIN,
        table: 'filter',
        args: ['-i', tapInterface, '-j', 'DROP'],
        comment: `${tag}-drop-all-outbound`,
      },
      {
        chain: SCANBOY_CHAIN,
        table: 'filter',
        args: ['-o', tapInterface, '-j', 'DROP'],
        comment: `${tag}-drop-all-inbound`,
      },
    ];
  }

  /**
   * Simulated internet: allow DNS to specific servers,
   * block private ranges and infrastructure, allow limited outbound.
   */
  private buildSimulatedRules(
    tapInterface: string,
    tag: string,
    policy: NetworkIsolationPolicy,
  ): IptablesRule[] {
    const rules: IptablesRule[] = [];

    // Allow established/related connections back in
    rules.push({
      chain: SCANBOY_CHAIN,
      table: 'filter',
      args: [
        '-i', tapInterface,
        '-m', 'state', '--state', 'ESTABLISHED,RELATED',
        '-j', 'ACCEPT',
      ],
      comment: `${tag}-allow-established`,
    });

    // Allow DNS to specified servers
    for (const dns of policy.allowedDnsServers) {
      rules.push({
        chain: SCANBOY_CHAIN,
        table: 'filter',
        args: [
          '-i', tapInterface,
          '-p', 'udp', '--dport', '53',
          '-d', dns,
          '-j', 'ACCEPT',
        ],
        comment: `${tag}-allow-dns-${dns}`,
      });
      rules.push({
        chain: SCANBOY_CHAIN,
        table: 'filter',
        args: [
          '-i', tapInterface,
          '-p', 'tcp', '--dport', '53',
          '-d', dns,
          '-j', 'ACCEPT',
        ],
        comment: `${tag}-allow-dns-tcp-${dns}`,
      });
    }

    // Block RFC1918, link-local, and infrastructure ranges
    rules.push(...this.buildBlockPrivateRangeRules(tapInterface, tag));

    // Block everything else from outbound (simulated means no real internet)
    rules.push({
      chain: SCANBOY_CHAIN,
      table: 'filter',
      args: ['-i', tapInterface, '-j', 'DROP'],
      comment: `${tag}-drop-remaining-outbound`,
    });

    return rules;
  }

  /**
   * Monitored/controlled internet: allow outbound but block private ranges
   * and infrastructure to prevent lateral movement.
   */
  private buildMonitoredRules(
    tapInterface: string,
    tag: string,
    policy: NetworkIsolationPolicy,
  ): IptablesRule[] {
    const rules: IptablesRule[] = [];

    // Allow established/related connections
    rules.push({
      chain: SCANBOY_CHAIN,
      table: 'filter',
      args: [
        '-i', tapInterface,
        '-m', 'state', '--state', 'ESTABLISHED,RELATED',
        '-j', 'ACCEPT',
      ],
      comment: `${tag}-allow-established`,
    });

    // Allow DNS to specified servers
    for (const dns of policy.allowedDnsServers) {
      rules.push({
        chain: SCANBOY_CHAIN,
        table: 'filter',
        args: [
          '-i', tapInterface,
          '-p', 'udp', '--dport', '53',
          '-d', dns,
          '-j', 'ACCEPT',
        ],
        comment: `${tag}-allow-dns-${dns}`,
      });
    }

    // Allow explicitly allowed hosts
    for (const host of policy.allowedHosts) {
      rules.push({
        chain: SCANBOY_CHAIN,
        table: 'filter',
        args: [
          '-i', tapInterface,
          '-d', host,
          '-j', 'ACCEPT',
        ],
        comment: `${tag}-allow-host-${host}`,
      });
    }

    // Block RFC1918, link-local, and infrastructure ranges
    rules.push(...this.buildBlockPrivateRangeRules(tapInterface, tag));

    // Log remaining outbound for monitoring (rate limited)
    rules.push({
      chain: SCANBOY_CHAIN,
      table: 'filter',
      args: [
        '-i', tapInterface,
        '-m', 'limit', '--limit', '100/min',
        '-j', 'LOG',
        '--log-prefix', `SCANBOY-${tag}: `,
      ],
      comment: `${tag}-log-outbound`,
    });

    // Allow remaining outbound (controlled internet access)
    rules.push({
      chain: SCANBOY_CHAIN,
      table: 'filter',
      args: ['-i', tapInterface, '-j', 'ACCEPT'],
      comment: `${tag}-allow-remaining-outbound`,
    });

    return rules;
  }

  /**
   * Build rules to block private/infrastructure IP ranges.
   */
  private buildBlockPrivateRangeRules(
    tapInterface: string,
    tag: string,
  ): IptablesRule[] {
    const rules: IptablesRule[] = [];
    const allBlocked = [
      ...BLOCKED_PRIVATE_RANGES,
      ...BLOCKED_INFRASTRUCTURE_RANGES,
    ];

    for (const range of allBlocked) {
      rules.push({
        chain: SCANBOY_CHAIN,
        table: 'filter',
        args: [
          '-i', tapInterface,
          '-d', range.cidr,
          '-j', 'DROP',
        ],
        comment: `${tag}-block-${range.description.replace(/\s+/g, '-').toLowerCase()}`,
      });
    }

    return rules;
  }

  // ── iptables execution ────────────────────────────────────────────────────

  private async iptables(args: readonly string[]): Promise<string> {
    const { stdout } = await execFileAsync('iptables', [...args]);
    return stdout;
  }

  /**
   * Run an iptables command, ignoring errors (used for idempotent operations).
   */
  private async safeIptables(args: readonly string[]): Promise<void> {
    try {
      await execFileAsync('iptables', [...args]);
    } catch {
      // Rule/chain may already exist or not exist
    }
  }
}
