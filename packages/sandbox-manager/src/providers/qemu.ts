import { execFile } from 'node:child_process';
import { readFile, writeFile, mkdir, unlink } from 'node:fs/promises';
import { join, resolve, normalize } from 'node:path';
import { promisify } from 'node:util';
import { randomUUID } from 'node:crypto';
import net from 'node:net';
import { SandboxStatus } from '@scanboy/shared';
import {
  SandboxProvider,
  type SandboxConfig,
  type SandboxInstance,
  type CommandResult,
} from './base.js';
import type { SandboxManagerConfig } from '../config.js';

const execFileAsync = promisify(execFile);

// ── Instance tracking ───────────────────────────────────────────────────────

interface QemuInstanceState {
  readonly instanceId: string;
  readonly config: SandboxConfig;
  readonly diskPath: string;
  readonly pidFile: string;
  readonly monitorPort: number;
  readonly vncPort: number;
  readonly tapInterface: string;
  readonly pcapPath: string;
  readonly createdAt: string;
  status: SandboxStatus;
  ipAddress: string | null;
}

// ── QEMU/KVM provider ──────────────────────────────────────────────────────

export class QemuProvider extends SandboxProvider {
  readonly providerName = 'qemu';

  private readonly instances = new Map<string, QemuInstanceState>();
  private nextVncOffset = 0;
  private nextMonitorOffset = 0;

  constructor(private readonly cfg: SandboxManagerConfig['qemu']) {
    super();
  }

  async provision(config: SandboxConfig): Promise<SandboxInstance> {
    const instanceId = randomUUID();
    const vncOffset = this.nextVncOffset++;
    const monitorOffset = this.nextMonitorOffset++;
    const vncPort = this.cfg.vncBasePort + vncOffset;
    const monitorPort = this.cfg.monitorBasePort + monitorOffset;
    const tapInterface = `tap-${instanceId.slice(0, 8)}`;

    // Create working directories
    const instanceDir = join(this.cfg.imagesDir, instanceId);
    await mkdir(instanceDir, { recursive: true });

    // Validate baseImage path is within the images directory
    const resolvedBase = resolve(normalize(config.baseImage));
    const allowedDir = resolve(this.cfg.imagesDir);
    if (!resolvedBase.startsWith(allowedDir + '/')) {
      throw new Error(`baseImage path must be within ${allowedDir}`);
    }

    // Create a copy-on-write overlay backed by the base image
    const diskPath = join(instanceDir, 'disk.qcow2');
    await execFileAsync('qemu-img', [
      'create',
      '-f', 'qcow2',
      '-b', resolvedBase,
      '-F', 'qcow2',
      diskPath,
    ]);

    // Create tap interface for isolated networking
    await execFileAsync('ip', ['tuntap', 'add', tapInterface, 'mode', 'tap']);
    await execFileAsync('ip', ['link', 'set', tapInterface, 'up']);
    await execFileAsync('ip', ['link', 'set', tapInterface, 'master', this.cfg.bridgeInterface]);

    // Start pcap capture on the tap interface (backgrounded via spawn to avoid shell interpolation)
    const pcapPath = join(instanceDir, 'capture.pcap');
    const pcapPidFile = join(instanceDir, 'tcpdump.pid');
    const { spawn } = await import('node:child_process');
    const tcpdump = spawn('tcpdump', ['-i', tapInterface, '-w', pcapPath, '-U'], {
      detached: true,
      stdio: 'ignore',
    });
    tcpdump.unref();
    if (tcpdump.pid) {
      await writeFile(pcapPidFile, String(tcpdump.pid));
    }

    // Build QEMU command
    const pidFile = join(instanceDir, 'qemu.pid');
    const qemuArgs = this.buildQemuArgs({
      diskPath,
      pidFile,
      monitorPort,
      vncOffset,
      tapInterface,
      config,
    });

    await execFileAsync(this.cfg.binaryPath, qemuArgs);

    const state: QemuInstanceState = {
      instanceId,
      config,
      diskPath,
      pidFile,
      monitorPort,
      vncPort,
      tapInterface,
      pcapPath,
      createdAt: new Date().toISOString(),
      status: SandboxStatus.Running,
      ipAddress: null,
    };

    this.instances.set(instanceId, state);

    return this.toSandboxInstance(state);
  }

  async destroy(instanceId: string): Promise<void> {
    const state = this.requireInstance(instanceId);

    // Send quit command via monitor
    try {
      await this.sendMonitorCommand(state.monitorPort, 'quit');
    } catch {
      // If monitor is unresponsive, kill via PID file
      try {
        const pid = await readFile(state.pidFile, 'utf-8');
        await execFileAsync('kill', ['-9', pid.trim()]);
      } catch {
        // Instance may already be gone
      }
    }

    // Stop tcpdump
    const tcpdumpPidFile = join(
      this.cfg.imagesDir,
      instanceId,
      'tcpdump.pid',
    );
    try {
      const tcpPid = await readFile(tcpdumpPidFile, 'utf-8');
      await execFileAsync('kill', [tcpPid.trim()]);
    } catch {
      // Already stopped
    }

    // Clean up tap interface
    try {
      await execFileAsync('ip', ['link', 'del', state.tapInterface]);
    } catch {
      // Interface may already be removed
    }

    // Remove instance disk overlay (keep base image intact)
    try {
      await unlink(state.diskPath);
    } catch {
      // File may already be removed
    }

    state.status = SandboxStatus.Offline;
    this.instances.delete(instanceId);
  }

  async snapshot(instanceId: string): Promise<string> {
    const state = this.requireInstance(instanceId);
    const snapshotId = `snap-${randomUUID().slice(0, 12)}`;
    if (!/^[a-zA-Z0-9_-]+$/.test(snapshotId)) {
      throw new Error(`Invalid snapshot ID: ${snapshotId}`);
    }
    const snapshotDir = join(this.cfg.snapshotsDir, instanceId);
    await mkdir(snapshotDir, { recursive: true });

    state.status = SandboxStatus.Snapshotting;

    // Use QEMU monitor to create an internal snapshot
    await this.sendMonitorCommand(
      state.monitorPort,
      `savevm ${snapshotId}`,
    );

    // Also create an external qcow2 snapshot for disk state
    const snapshotPath = join(snapshotDir, `${snapshotId}.qcow2`);
    await execFileAsync('qemu-img', [
      'snapshot',
      '-c', snapshotId,
      state.diskPath,
    ]);

    // Record snapshot metadata
    const metaPath = join(snapshotDir, `${snapshotId}.json`);
    await writeFile(
      metaPath,
      JSON.stringify({
        snapshotId,
        instanceId,
        snapshotPath,
        createdAt: new Date().toISOString(),
      }),
    );

    state.status = SandboxStatus.Running;
    return snapshotId;
  }

  async restore(instanceId: string, snapshotId: string): Promise<void> {
    if (!/^[a-zA-Z0-9_-]+$/.test(snapshotId)) {
      throw new Error(`Invalid snapshot ID: ${snapshotId}`);
    }
    const state = this.requireInstance(instanceId);

    // Restore from internal QEMU snapshot via monitor
    await this.sendMonitorCommand(
      state.monitorPort,
      `loadvm ${snapshotId}`,
    );

    state.status = SandboxStatus.Running;
  }

  async getStatus(instanceId: string): Promise<SandboxStatus> {
    const state = this.instances.get(instanceId);
    if (!state) {
      return SandboxStatus.Offline;
    }

    // Ping the monitor port to verify the VM is responsive
    try {
      await this.sendMonitorCommand(state.monitorPort, 'info status');
      return SandboxStatus.Running;
    } catch {
      state.status = SandboxStatus.Error;
      return SandboxStatus.Error;
    }
  }

  async executeCommand(instanceId: string, command: string): Promise<CommandResult> {
    const state = this.requireInstance(instanceId);
    const startTime = Date.now();

    // Use QEMU Guest Agent (QGA) to execute command in the guest
    const guestExecPayload = JSON.stringify({
      execute: 'guest-exec',
      arguments: {
        path: '/bin/sh',
        arg: ['-c', command],
        'capture-output': true,
      },
    });

    const response = await this.sendMonitorCommand(
      state.monitorPort,
      `guest-exec ${guestExecPayload}`,
    );

    const durationMs = Date.now() - startTime;

    // Parse guest agent response
    const parsed = this.parseGuestExecResponse(response);

    return {
      exitCode: parsed.exitCode,
      stdout: parsed.stdout,
      stderr: parsed.stderr,
      durationMs,
    };
  }

  async uploadFile(
    instanceId: string,
    localPath: string,
    remotePath: string,
  ): Promise<void> {
    const state = this.requireInstance(instanceId);
    const fileContent = await readFile(localPath);
    const base64Content = fileContent.toString('base64');

    // Open file on guest via guest agent
    const openPayload = JSON.stringify({
      execute: 'guest-file-open',
      arguments: { path: remotePath, mode: 'w' },
    });
    const handleResponse = await this.sendMonitorCommand(
      state.monitorPort,
      `guest-file-open ${openPayload}`,
    );
    const handle = this.parseFileHandle(handleResponse);

    // Write content in chunks
    const chunkSize = 65536; // 64KB chunks
    for (let offset = 0; offset < base64Content.length; offset += chunkSize) {
      const chunk = base64Content.slice(offset, offset + chunkSize);
      const writePayload = JSON.stringify({
        execute: 'guest-file-write',
        arguments: { handle, 'buf-b64': chunk },
      });
      await this.sendMonitorCommand(
        state.monitorPort,
        `guest-file-write ${writePayload}`,
      );
    }

    // Close the file
    const closePayload = JSON.stringify({
      execute: 'guest-file-close',
      arguments: { handle },
    });
    await this.sendMonitorCommand(
      state.monitorPort,
      `guest-file-close ${closePayload}`,
    );
  }

  async downloadFile(instanceId: string, remotePath: string): Promise<Buffer> {
    const state = this.requireInstance(instanceId);

    // Open file on guest for reading
    const openPayload = JSON.stringify({
      execute: 'guest-file-open',
      arguments: { path: remotePath, mode: 'r' },
    });
    const handleResponse = await this.sendMonitorCommand(
      state.monitorPort,
      `guest-file-open ${openPayload}`,
    );
    const handle = this.parseFileHandle(handleResponse);

    // Read the full file
    const chunks: string[] = [];
    let eof = false;
    while (!eof) {
      const readPayload = JSON.stringify({
        execute: 'guest-file-read',
        arguments: { handle, count: 65536 },
      });
      const readResponse = await this.sendMonitorCommand(
        state.monitorPort,
        `guest-file-read ${readPayload}`,
      );
      const parsed = this.parseFileReadResponse(readResponse);
      chunks.push(parsed.content);
      eof = parsed.eof;
    }

    // Close file
    const closePayload = JSON.stringify({
      execute: 'guest-file-close',
      arguments: { handle },
    });
    await this.sendMonitorCommand(
      state.monitorPort,
      `guest-file-close ${closePayload}`,
    );

    return Buffer.from(chunks.join(''), 'base64');
  }

  async captureScreenshot(instanceId: string): Promise<Buffer> {
    const state = this.requireInstance(instanceId);
    const screenshotPath = join(
      this.cfg.imagesDir,
      instanceId,
      `screenshot-${Date.now()}.ppm`,
    );

    // Use QEMU monitor to capture the framebuffer
    if (/["\n\r]/.test(screenshotPath)) {
      throw new Error('Invalid screenshot path');
    }
    await this.sendMonitorCommand(
      state.monitorPort,
      `screendump "${screenshotPath}"`,
    );

    const imageData = await readFile(screenshotPath);

    // Clean up the temporary PPM file
    try {
      await unlink(screenshotPath);
    } catch {
      // Non-critical
    }

    return imageData;
  }

  async getNetworkCapture(instanceId: string): Promise<Buffer> {
    const state = this.requireInstance(instanceId);
    return readFile(state.pcapPath);
  }

  async getMemoryDump(instanceId: string): Promise<Buffer> {
    const state = this.requireInstance(instanceId);
    const dumpPath = join(
      this.cfg.imagesDir,
      instanceId,
      `memdump-${Date.now()}.raw`,
    );

    // Use QEMU monitor pmemsave to dump full physical memory
    if (/["\n\r]/.test(dumpPath)) {
      throw new Error('Invalid dump path');
    }
    const memorySizeBytes = state.config.memoryMb * 1024 * 1024;
    await this.sendMonitorCommand(
      state.monitorPort,
      `pmemsave 0 ${memorySizeBytes} "${dumpPath}"`,
    );

    const dumpData = await readFile(dumpPath);

    try {
      await unlink(dumpPath);
    } catch {
      // Non-critical
    }

    return dumpData;
  }

  // ── Private helpers ─────────────────────────────────────────────────────────

  private buildQemuArgs(params: {
    diskPath: string;
    pidFile: string;
    monitorPort: number;
    vncOffset: number;
    tapInterface: string;
    config: SandboxConfig;
  }): string[] {
    const { diskPath, pidFile, monitorPort, vncOffset, tapInterface, config } =
      params;

    const args: string[] = [
      '-enable-kvm',
      '-daemonize',
      '-pidfile', pidFile,

      // CPU and memory
      '-m', `${config.memoryMb}`,
      '-smp', `${config.cpuCores}`,
      '-cpu', 'host',

      // Disk
      '-drive', `file=${diskPath},format=qcow2,if=virtio`,

      // Networking via tap interface
      '-netdev', `tap,id=net0,ifname=${tapInterface},script=no,downscript=no`,
      '-device', 'virtio-net-pci,netdev=net0',

      // Monitor for control commands
      '-monitor', `tcp:127.0.0.1:${monitorPort},server,nowait`,

      // VNC for screenshot capture
      '-vnc', `:${vncOffset}`,

      // Guest agent channel
      '-chardev', `socket,path=/tmp/qga-${pidFile.split('/').pop()},server,nowait,id=qga0`,
      '-device', 'virtio-serial',
      '-device', 'virtserialport,chardev=qga0,name=org.qemu.guest_agent.0',

      // Hide virtualization indicators to counter VM detection
      '-cpu', 'host,hv_relaxed,hv_spinlocks=0x1fff,hv_vapic,hv_time',

      // RTC set to local time (for Windows guests)
      '-rtc', 'base=localtime,clock=host',
    ];

    return args;
  }

  private requireInstance(instanceId: string): QemuInstanceState {
    const state = this.instances.get(instanceId);
    if (!state) {
      throw new Error(`QEMU instance not found: ${instanceId}`);
    }
    return state;
  }

  private async sendMonitorCommand(
    port: number,
    command: string,
  ): Promise<string> {
    return new Promise<string>((resolve, reject) => {
      const socket = new net.Socket();
      let data = '';

      socket.setTimeout(10_000);

      socket.connect(port, '127.0.0.1', () => {
        socket.write(`${command}\n`);
      });

      socket.on('data', (chunk) => {
        data += chunk.toString();
        // QEMU monitor prompt ends with "(qemu) "
        if (data.includes('(qemu)')) {
          socket.end();
        }
      });

      socket.on('end', () => {
        resolve(data);
      });

      socket.on('timeout', () => {
        socket.destroy();
        reject(new Error(`Monitor command timed out on port ${port}`));
      });

      socket.on('error', (err) => {
        reject(new Error(`Monitor connection error on port ${port}: ${err.message}`));
      });
    });
  }

  private parseGuestExecResponse(raw: string): {
    exitCode: number;
    stdout: string;
    stderr: string;
  } {
    try {
      // Extract JSON from monitor response (strip prompt text)
      const jsonMatch = raw.match(/\{[\s\S]*\}/);
      if (!jsonMatch) {
        return { exitCode: -1, stdout: '', stderr: 'Failed to parse guest agent response' };
      }
      const parsed = JSON.parse(jsonMatch[0]) as {
        return?: {
          exitcode?: number;
          'out-data'?: string;
          'err-data'?: string;
        };
      };
      const ret = parsed.return;
      return {
        exitCode: ret?.exitcode ?? -1,
        stdout: ret?.['out-data']
          ? Buffer.from(ret['out-data'], 'base64').toString('utf-8')
          : '',
        stderr: ret?.['err-data']
          ? Buffer.from(ret['err-data'], 'base64').toString('utf-8')
          : '',
      };
    } catch {
      return { exitCode: -1, stdout: '', stderr: 'Failed to parse guest agent response' };
    }
  }

  private parseFileHandle(raw: string): number {
    try {
      const jsonMatch = raw.match(/\{[\s\S]*\}/);
      if (!jsonMatch) {
        throw new Error('No JSON in guest agent response');
      }
      const parsed = JSON.parse(jsonMatch[0]) as { return?: number };
      if (typeof parsed.return !== 'number') {
        throw new Error('Invalid file handle response');
      }
      return parsed.return;
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      throw new Error(`Failed to parse file handle: ${message}`);
    }
  }

  private parseFileReadResponse(raw: string): {
    content: string;
    eof: boolean;
  } {
    try {
      const jsonMatch = raw.match(/\{[\s\S]*\}/);
      if (!jsonMatch) {
        return { content: '', eof: true };
      }
      const parsed = JSON.parse(jsonMatch[0]) as {
        return?: { 'buf-b64'?: string; eof?: boolean };
      };
      return {
        content: parsed.return?.['buf-b64'] ?? '',
        eof: parsed.return?.eof ?? true,
      };
    } catch {
      return { content: '', eof: true };
    }
  }

  private toSandboxInstance(state: QemuInstanceState): SandboxInstance {
    return {
      instanceId: state.instanceId,
      provider: this.providerName,
      status: state.status,
      ipAddress: state.ipAddress,
      portMappings: new Map<number, number>([
        [state.vncPort, 5900],
        [state.monitorPort, state.monitorPort],
      ]),
      createdAt: state.createdAt,
      config: state.config,
    };
  }
}
