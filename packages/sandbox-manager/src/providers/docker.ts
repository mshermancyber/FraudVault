import { readFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import http from 'node:http';
import { SandboxStatus } from '@scanboy/shared';
import {
  SandboxProvider,
  type SandboxConfig,
  type SandboxInstance,
  type CommandResult,
} from './base.js';
import type { SandboxManagerConfig } from '../config.js';

// ── Docker API types ────────────────────────────────────────────────────────

interface DockerCreateResponse {
  readonly Id: string;
  readonly Warnings: string[];
}

interface DockerInspectResponse {
  readonly State: {
    readonly Status: string;
    readonly Running: boolean;
    readonly Pid: number;
  };
  readonly NetworkSettings: {
    readonly IPAddress: string;
    readonly Networks: Record<
      string,
      { readonly IPAddress: string }
    >;
  };
}

interface DockerExecCreateResponse {
  readonly Id: string;
}

interface DockerExecInspectResponse {
  readonly ExitCode: number;
  readonly Running: boolean;
}

// ── Instance tracking ───────────────────────────────────────────────────────

interface DockerInstanceState {
  readonly instanceId: string;
  readonly containerId: string;
  readonly config: SandboxConfig;
  readonly createdAt: string;
  status: SandboxStatus;
  ipAddress: string | null;
}

// ── Docker provider ─────────────────────────────────────────────────────────

export class DockerProvider extends SandboxProvider {
  readonly providerName = 'docker';

  private readonly instances = new Map<string, DockerInstanceState>();

  constructor(private readonly cfg: SandboxManagerConfig['docker']) {
    super();
  }

  async provision(config: SandboxConfig): Promise<SandboxInstance> {
    const instanceId = randomUUID();
    const containerName = `scanboy-${instanceId.slice(0, 12)}`;
    if (!/^[a-zA-Z0-9][a-zA-Z0-9._\-/:]{0,127}$/.test(config.baseImage) || /\.\./.test(config.baseImage)) {
      throw new Error('Invalid baseImage name');
    }
    const imageName = `${this.cfg.registryPrefix}/${config.baseImage}`;

    // Create the container with strict resource limits and no network by default
    const createBody = {
      Image: imageName,
      Hostname: containerName,
      Tty: true,
      OpenStdin: true,
      HostConfig: {
        Memory: config.memoryMb * 1024 * 1024,
        MemorySwap: config.memoryMb * 1024 * 1024, // No swap
        CpuShares: this.cfg.defaultCpuShares,
        NanoCpus: config.cpuCores * 1_000_000_000,
        NetworkMode: config.internetMode === 'disabled' ? 'none' : this.cfg.networkName,
        SecurityOpt: ['no-new-privileges'],
        CapDrop: ['ALL'],
        CapAdd: ['SYS_PTRACE', 'NET_RAW'],
        ReadonlyRootfs: false,
        Tmpfs: { '/run': 'rw,noexec,nosuid,size=64m' },
        PidsLimit: 256,
        StopTimeout: config.maxExecutionSeconds,
        Ulimits: [
          { Name: 'nofile', Soft: 1024, Hard: 2048 },
          { Name: 'nproc', Soft: 128, Hard: 256 },
        ],
      },
      NetworkingConfig:
        config.internetMode !== 'disabled'
          ? {
              EndpointsConfig: {
                [this.cfg.networkName]: {},
              },
            }
          : undefined,
      Labels: {
        'fraudvault.instance-id': instanceId,
        'fraudvault.sandbox': 'true',
        'fraudvault.os': config.os,
        'fraudvault.internet-mode': config.internetMode,
      },
    };

    const createResult = await this.dockerApi<DockerCreateResponse>(
      'POST',
      `/containers/create?name=${containerName}`,
      createBody,
    );

    const containerId = createResult.Id;

    // Start the container
    await this.dockerApi<null>('POST', `/containers/${containerId}/start`);

    // Inspect to get IP address
    const inspectResult = await this.dockerApi<DockerInspectResponse>(
      'GET',
      `/containers/${containerId}/json`,
    );

    const networkName = this.cfg.networkName;
    const networks = inspectResult.NetworkSettings.Networks;
    const networkInfo = networks[networkName];
    const ipAddress =
      networkInfo?.IPAddress ??
      inspectResult.NetworkSettings.IPAddress ??
      null;

    const state: DockerInstanceState = {
      instanceId,
      containerId,
      config,
      createdAt: new Date().toISOString(),
      status: SandboxStatus.Running,
      ipAddress,
    };

    this.instances.set(instanceId, state);

    return this.toSandboxInstance(state);
  }

  async destroy(instanceId: string): Promise<void> {
    const state = this.requireInstance(instanceId);

    // Stop and remove the container, with force flag
    try {
      await this.dockerApi<null>(
        'POST',
        `/containers/${state.containerId}/stop?t=5`,
      );
    } catch {
      // Container may already be stopped
    }

    await this.dockerApi<null>(
      'DELETE',
      `/containers/${state.containerId}?force=true&v=true`,
    );

    state.status = SandboxStatus.Offline;
    this.instances.delete(instanceId);
  }

  async snapshot(instanceId: string): Promise<string> {
    const state = this.requireInstance(instanceId);
    const snapshotId = `snap-${randomUUID().slice(0, 12)}`;
    const repo = `${this.cfg.registryPrefix}/snapshot`;
    const tag = snapshotId;

    state.status = SandboxStatus.Snapshotting;

    // Commit the container state as a new image
    await this.dockerApi<{ Id: string }>(
      'POST',
      `/commit?container=${state.containerId}&repo=${repo}&tag=${tag}&comment=FraudVault+snapshot`,
    );

    state.status = SandboxStatus.Running;
    return `${repo}:${tag}`;
  }

  async restore(_instanceId: string, _snapshotId: string): Promise<void> {
    // Docker containers cannot be directly restored from a commit snapshot.
    // The workflow is: destroy current container, provision new one from snapshot image.
    throw new Error(
      'Docker containers do not support in-place restore. ' +
        'Destroy this instance and provision a new one from the snapshot image.',
    );
  }

  async getStatus(instanceId: string): Promise<SandboxStatus> {
    const state = this.instances.get(instanceId);
    if (!state) {
      return SandboxStatus.Offline;
    }

    try {
      const inspect = await this.dockerApi<DockerInspectResponse>(
        'GET',
        `/containers/${state.containerId}/json`,
      );

      if (inspect.State.Running) {
        return SandboxStatus.Running;
      }

      return SandboxStatus.Offline;
    } catch {
      state.status = SandboxStatus.Error;
      return SandboxStatus.Error;
    }
  }

  async executeCommand(instanceId: string, command: string): Promise<CommandResult> {
    const state = this.requireInstance(instanceId);
    const startTime = Date.now();

    // Create exec instance
    const execCreate = await this.dockerApi<DockerExecCreateResponse>(
      'POST',
      `/containers/${state.containerId}/exec`,
      {
        AttachStdout: true,
        AttachStderr: true,
        Cmd: ['/bin/sh', '-c', command],
      },
    );

    // Start the exec instance and capture output
    const output = await this.dockerApiRaw(
      'POST',
      `/exec/${execCreate.Id}/start`,
      { Detach: false, Tty: false },
    );

    // Inspect to get exit code
    const execInspect = await this.dockerApi<DockerExecInspectResponse>(
      'GET',
      `/exec/${execCreate.Id}/json`,
    );

    const durationMs = Date.now() - startTime;

    // Docker multiplexes stdout/stderr in the stream.
    // Each frame: [stream_type(1 byte), 0, 0, 0, size(4 bytes big-endian), payload]
    const { stdout, stderr } = this.demuxDockerStream(output);

    return {
      exitCode: execInspect.ExitCode,
      stdout,
      stderr,
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

    // Docker expects a tar archive for the PUT /containers/{id}/archive endpoint.
    // Build a minimal tar with one entry.
    const fileName = remotePath.split('/').pop() ?? 'file';
    const dirPath = remotePath.slice(0, remotePath.length - fileName.length - 1) || '/';
    const tarBuffer = this.createMinimalTar(fileName, fileContent);

    await this.dockerApiRaw(
      'PUT',
      `/containers/${state.containerId}/archive?path=${encodeURIComponent(dirPath)}`,
      tarBuffer,
    );
  }

  async downloadFile(instanceId: string, remotePath: string): Promise<Buffer> {
    const state = this.requireInstance(instanceId);

    // GET /containers/{id}/archive returns a tar archive
    const tarData = await this.dockerApiRaw(
      'GET',
      `/containers/${state.containerId}/archive?path=${encodeURIComponent(remotePath)}`,
    );

    // Extract the first file from the tar
    return this.extractFirstFileFromTar(tarData);
  }

  async captureScreenshot(_instanceId: string): Promise<Buffer> {
    // Docker containers are headless; no display to capture.
    // Return an empty buffer. Callers should use QEMU for GUI-based analysis.
    throw new Error(
      'Docker containers do not have a graphical display. ' +
        'Use the QEMU provider for screenshot capture.',
    );
  }

  async getNetworkCapture(instanceId: string): Promise<Buffer> {
    // Execute tcpdump inside the container to retrieve captured packets
    const result = await this.executeCommand(
      instanceId,
      'cat /tmp/scanboy-capture.pcap 2>/dev/null || echo ""',
    );
    return Buffer.from(result.stdout, 'binary');
  }

  async getMemoryDump(instanceId: string): Promise<Buffer> {
    const state = this.requireInstance(instanceId);

    // Read the container's memory cgroup to get the memory dump
    const inspect = await this.dockerApi<DockerInspectResponse>(
      'GET',
      `/containers/${state.containerId}/json`,
    );

    const pid = inspect.State.Pid;
    // Read process memory maps from the host /proc filesystem
    const result = await this.executeCommand(
      instanceId,
      `cat /proc/${pid}/maps`,
    );

    return Buffer.from(result.stdout, 'utf-8');
  }

  // ── Private helpers ─────────────────────────────────────────────────────────

  private requireInstance(instanceId: string): DockerInstanceState {
    const state = this.instances.get(instanceId);
    if (!state) {
      throw new Error(`Docker instance not found: ${instanceId}`);
    }
    return state;
  }

  private toSandboxInstance(state: DockerInstanceState): SandboxInstance {
    return {
      instanceId: state.instanceId,
      provider: this.providerName,
      status: state.status,
      ipAddress: state.ipAddress,
      portMappings: new Map<number, number>(),
      createdAt: state.createdAt,
      config: state.config,
    };
  }

  /**
   * Make a JSON request to the Docker Engine API via Unix socket.
   */
  private dockerApi<T>(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      const options: http.RequestOptions = {
        socketPath: this.cfg.socketPath,
        path: `/v1.43${path}`,
        method,
        headers: {
          'Content-Type': 'application/json',
        },
      };

      const req = http.request(options, (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => chunks.push(chunk));
        res.on('end', () => {
          const rawBody = Buffer.concat(chunks).toString('utf-8');
          const statusCode = res.statusCode ?? 0;

          if (statusCode >= 200 && statusCode < 300) {
            if (!rawBody || rawBody.trim() === '') {
              resolve(null as T);
              return;
            }
            try {
              resolve(JSON.parse(rawBody) as T);
            } catch {
              resolve(null as T);
            }
          } else {
            reject(
              new Error(
                `Docker API error ${statusCode} ${method} ${path}: ${rawBody}`,
              ),
            );
          }
        });
      });

      req.on('error', reject);

      if (body !== undefined) {
        if (Buffer.isBuffer(body)) {
          req.write(body);
        } else {
          req.write(JSON.stringify(body));
        }
      }

      req.end();
    });
  }

  /**
   * Make a raw request to the Docker API, returning the response as a Buffer.
   */
  private dockerApiRaw(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<Buffer> {
    return new Promise<Buffer>((resolve, reject) => {
      const headers: Record<string, string> = {};
      if (body && Buffer.isBuffer(body)) {
        headers['Content-Type'] = 'application/x-tar';
      } else if (body !== undefined) {
        headers['Content-Type'] = 'application/json';
      }

      const options: http.RequestOptions = {
        socketPath: this.cfg.socketPath,
        path: `/v1.43${path}`,
        method,
        headers,
      };

      const req = http.request(options, (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => chunks.push(chunk));
        res.on('end', () => {
          const statusCode = res.statusCode ?? 0;
          const result = Buffer.concat(chunks);
          if (statusCode >= 200 && statusCode < 300) {
            resolve(result);
          } else {
            reject(
              new Error(
                `Docker API error ${statusCode} ${method} ${path}: ${result.toString('utf-8')}`,
              ),
            );
          }
        });
      });

      req.on('error', reject);

      if (body !== undefined) {
        if (Buffer.isBuffer(body)) {
          req.write(body);
        } else {
          req.write(JSON.stringify(body));
        }
      }

      req.end();
    });
  }

  /**
   * Demultiplex Docker's stream protocol for exec output.
   * Each frame: [type(1), 0, 0, 0, size(4 big-endian), payload(size)]
   * type=1 -> stdout, type=2 -> stderr
   */
  private demuxDockerStream(data: Buffer): {
    stdout: string;
    stderr: string;
  } {
    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];
    let offset = 0;

    while (offset + 8 <= data.length) {
      const streamType = data[offset];
      const frameSize = data.readUInt32BE(offset + 4);
      const frameData = data.subarray(offset + 8, offset + 8 + frameSize);

      if (streamType === 1) {
        stdoutChunks.push(frameData);
      } else if (streamType === 2) {
        stderrChunks.push(frameData);
      }

      offset += 8 + frameSize;
    }

    return {
      stdout: Buffer.concat(stdoutChunks).toString('utf-8'),
      stderr: Buffer.concat(stderrChunks).toString('utf-8'),
    };
  }

  /**
   * Create a minimal POSIX tar archive containing a single file.
   */
  private createMinimalTar(fileName: string, content: Buffer): Buffer {
    // Tar header is 512 bytes
    const header = Buffer.alloc(512, 0);
    const nameBytes = Buffer.from(fileName, 'utf-8');
    nameBytes.copy(header, 0, 0, Math.min(nameBytes.length, 100));

    // File mode: 0644
    Buffer.from('0000644\0', 'ascii').copy(header, 100);
    // Owner/group: 0/0
    Buffer.from('0000000\0', 'ascii').copy(header, 108);
    Buffer.from('0000000\0', 'ascii').copy(header, 116);
    // File size in octal
    const sizeOctal = content.length.toString(8).padStart(11, '0') + '\0';
    Buffer.from(sizeOctal, 'ascii').copy(header, 124);
    // Modification time
    const mtime = Math.floor(Date.now() / 1000).toString(8).padStart(11, '0') + '\0';
    Buffer.from(mtime, 'ascii').copy(header, 136);
    // Type flag: regular file
    header[156] = 0x30; // '0'
    // USTAR magic
    Buffer.from('ustar\0', 'ascii').copy(header, 257);
    Buffer.from('00', 'ascii').copy(header, 263);

    // Calculate checksum
    // First fill checksum field with spaces
    Buffer.from('        ', 'ascii').copy(header, 148);
    let checksum = 0;
    for (let i = 0; i < 512; i++) {
      checksum += header[i] ?? 0;
    }
    const checksumOctal = checksum.toString(8).padStart(6, '0') + '\0 ';
    Buffer.from(checksumOctal, 'ascii').copy(header, 148);

    // Pad content to 512-byte boundary
    const paddingSize = (512 - (content.length % 512)) % 512;
    const padding = Buffer.alloc(paddingSize, 0);

    // Two empty 512-byte blocks mark end of archive
    const endOfArchive = Buffer.alloc(1024, 0);

    return Buffer.concat([header, content, padding, endOfArchive]);
  }

  /**
   * Extract the first file from a tar archive.
   */
  private extractFirstFileFromTar(tar: Buffer): Buffer {
    if (tar.length < 512) {
      throw new Error('Invalid tar archive: too small');
    }

    // Read file size from header bytes 124-135 (octal string)
    const sizeStr = tar.subarray(124, 136).toString('ascii').replace(/\0/g, '').trim();
    const fileSize = parseInt(sizeStr, 8);

    if (Number.isNaN(fileSize) || fileSize < 0) {
      throw new Error('Invalid tar archive: cannot parse file size');
    }

    return Buffer.from(tar.subarray(512, 512 + fileSize));
  }
}
