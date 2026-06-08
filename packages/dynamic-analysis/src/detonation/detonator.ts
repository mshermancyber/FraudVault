import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import type pino from 'pino';
import { type InternetMode } from '@scanboy/shared';
import type { DynamicAnalysisConfig } from '../config.js';
import {
  getExecutionStrategy,
  buildExecutionCommand,
  buildDllCommands,
  classifyFile,
} from './executors.js';
import { ProcessMonitor, type ProcessEvent } from '../monitors/processMonitor.js';
import { FileMonitor, type FileEvent } from '../monitors/fileMonitor.js';
import { RegistryMonitor, type RegistryEvent } from '../monitors/registryMonitor.js';
import { NetworkMonitor, type NetworkEvent } from '../monitors/networkMonitor.js';
import { MemoryMonitor, type MemoryAnalysisResult } from '../monitors/memoryMonitor.js';
import { EvasionDetector, type EvasionDetectionResult } from '../evasion/detector.js';
import { ScreenshotCapture, type ScreenshotTimelineEntry } from '../capture/screenshotCapture.js';
import { VideoRecorder } from '../capture/videoRecorder.js';
import { ActivityTimeline, type TimelineEvent, type KeyMoment } from '../capture/activityTimeline.js';

// ── Types ───────────────────────────────────────────────────────────────────

interface SandboxClient {
  provision(params: {
    name: string;
    provider: string;
    os: string;
    osVersion: string;
    architecture: string;
    baseImage: string;
    internetMode: InternetMode;
    maxExecutionSeconds: number;
  }): Promise<{ instanceId: string; provider: string }>;

  destroy(instanceId: string): Promise<void>;

  executeCommand(
    instanceId: string,
    command: string,
  ): Promise<{ exitCode: number; stdout: string; stderr: string; durationMs: number }>;

  uploadFile(
    instanceId: string,
    localPath: string,
    remotePath: string,
  ): Promise<void>;

  captureScreenshot(instanceId: string): Promise<Buffer>;
  getNetworkCapture(instanceId: string): Promise<Buffer>;
  getMemoryDump(instanceId: string): Promise<Buffer>;
}

export interface DetonationRequest {
  readonly submissionId: string;
  readonly samplePath: string;
  readonly fileName: string;
  readonly mimeType: string;
  readonly sha256: string;
  readonly os: string;
  readonly osVersion: string;
  readonly architecture: string;
  readonly baseImage: string;
  readonly internetMode: InternetMode;
  readonly durationSeconds: number;
  readonly provider: string;
}

export interface CaptureResult {
  readonly screenshotTimeline: readonly ScreenshotTimelineEntry[];
  readonly interestingFrameCount: number;
  readonly videoPath: string | null;
  readonly videoDurationSeconds: number;
  readonly activityTimeline: readonly TimelineEvent[];
  readonly keyMoments: readonly KeyMoment[];
  readonly timelineJsonPath: string | null;
  readonly screenshotTimelineJsonPath: string | null;
}

export interface DetonationArtifacts {
  readonly screenshotPaths: string[];
  readonly pcapPath: string | null;
  readonly memoryDumpPath: string | null;
  readonly processTreePath: string | null;
  readonly filesystemDiffPath: string | null;
  readonly registryDiffPath: string | null;
}

export interface DetonationResult {
  readonly submissionId: string;
  readonly sessionId: string;
  readonly durationMs: number;
  readonly processEvents: readonly ProcessEvent[];
  readonly fileEvents: readonly FileEvent[];
  readonly registryEvents: readonly RegistryEvent[];
  readonly networkEvents: readonly NetworkEvent[];
  readonly memoryAnalysis: MemoryAnalysisResult;
  readonly evasionDetection: EvasionDetectionResult;
  readonly artifacts: DetonationArtifacts;
  readonly capture: CaptureResult;
  readonly executionExitCode: number;
  readonly executionStdout: string;
  readonly executionStderr: string;
}

// ── Detonator ───────────────────────────────────────────────────────────────

export class Detonator {
  constructor(
    private readonly cfg: DynamicAnalysisConfig['detonation'],
    private readonly sandboxClient: SandboxClient,
    private readonly logger: pino.Logger,
  ) {}

  /**
   * Detonate a sample in a sandbox and collect comprehensive results.
   */
  async detonate(request: DetonationRequest): Promise<DetonationResult> {
    const sessionId = `det-${Date.now()}-${request.submissionId.slice(0, 8)}`;
    const startTime = Date.now();

    // Create artifact storage directory
    const artifactDir = join(
      this.cfg.artifactStoragePath,
      request.submissionId,
      sessionId,
    );
    await mkdir(artifactDir, { recursive: true });

    this.logger.info(
      {
        submissionId: request.submissionId,
        sessionId,
        fileName: request.fileName,
        mimeType: request.mimeType,
        os: request.os,
        durationSeconds: request.durationSeconds,
      },
      'Starting detonation session',
    );

    // Step 1: Provision sandbox
    const sandbox = await this.sandboxClient.provision({
      name: `detonation-${sessionId}`,
      provider: request.provider,
      os: request.os,
      osVersion: request.osVersion,
      architecture: request.architecture,
      baseImage: request.baseImage,
      internetMode: request.internetMode,
      maxExecutionSeconds: request.durationSeconds,
    });

    const instanceId = sandbox.instanceId;

    try {
      // Step 2: Upload sample to sandbox
      const remoteSamplePath = this.getRemoteSamplePath(request.os, request.fileName);
      await this.sandboxClient.uploadFile(
        instanceId,
        request.samplePath,
        remoteSamplePath,
      );

      this.logger.info(
        { instanceId, remoteSamplePath },
        'Sample uploaded to sandbox',
      );

      // Step 3: Install monitoring hooks
      await this.installMonitoringHooks(instanceId, request.os);

      // Step 3b: Initialize screenshot capture and video recording
      const screenshotDir = join(artifactDir, 'screenshots');
      await mkdir(screenshotDir, { recursive: true });

      const screenshotCapture = new ScreenshotCapture(
        this.sandboxClient,
        instanceId,
        screenshotDir,
        this.logger,
      );

      const videoRecorder = new VideoRecorder(this.logger);
      const videoOutputPath = join(artifactDir, 'recording.mp4');

      screenshotCapture.start(this.cfg.screenshotIntervalSeconds * 1000);
      videoRecorder.startRecording(videoOutputPath, screenshotDir);

      // Step 4: Execute sample
      const strategy = getExecutionStrategy(request.mimeType, request.fileName);
      const category = classifyFile(request.mimeType, request.fileName);

      this.logger.info(
        { strategy: strategy.label, category },
        'Executing sample',
      );

      let executionResult: {
        exitCode: number;
        stdout: string;
        stderr: string;
        durationMs: number;
      };

      if (category === 'windows_dll') {
        // Try multiple DLL entry points
        executionResult = await this.executeDll(instanceId, remoteSamplePath);
      } else {
        const command = buildExecutionCommand(strategy, remoteSamplePath);
        executionResult = await this.sandboxClient.executeCommand(
          instanceId,
          command,
        );
      }

      // Step 5: Monitor execution for configured duration
      const monitorResults = await this.monitorExecution(
        instanceId,
        request,
        artifactDir,
      );

      // Step 5b: Stop screenshot capture and generate video
      screenshotCapture.stop();
      const generatedVideoPath = await videoRecorder.stopRecording();

      // Step 5c: Export screenshot timeline metadata
      const screenshotTimelineJsonPath = join(artifactDir, 'screenshot-timeline.json');
      await screenshotCapture.exportTimeline(screenshotTimelineJsonPath);

      // Step 6: Collect artifacts
      const artifacts = await this.collectArtifacts(
        instanceId,
        artifactDir,
        screenshotCapture.getScreenshotPaths() as string[],
      );

      // Step 6b: Build combined activity timeline
      const activityTimeline = new ActivityTimeline(this.logger);
      activityTimeline.setScreenshots(screenshotCapture.getTimeline());
      activityTimeline.setProcessEvents(monitorResults.processEvents);
      activityTimeline.setNetworkEvents(monitorResults.networkEvents);
      activityTimeline.setFileEvents(monitorResults.fileEvents);
      activityTimeline.setRegistryEvents(monitorResults.registryEvents);

      const timelineJsonPath = join(artifactDir, 'activity-timeline.json');
      await activityTimeline.exportAsJson(timelineJsonPath);

      const captureResult: CaptureResult = {
        screenshotTimeline: screenshotCapture.getTimeline(),
        interestingFrameCount: screenshotCapture.getInterestingFrames().length,
        videoPath: generatedVideoPath,
        videoDurationSeconds: videoRecorder.getDuration(),
        activityTimeline: activityTimeline.generateTimeline(),
        keyMoments: activityTimeline.getKeyMoments(),
        timelineJsonPath,
        screenshotTimelineJsonPath,
      };

      // Step 7: Run memory analysis
      const memoryMonitor = new MemoryMonitor(this.logger);
      let memoryAnalysis: MemoryAnalysisResult;
      try {
        const memoryDump = await this.sandboxClient.getMemoryDump(instanceId);
        memoryAnalysis = memoryMonitor.analyzeMemoryDump(memoryDump);
      } catch (err) {
        this.logger.warn({ err }, 'Memory dump collection failed');
        memoryAnalysis = memoryMonitor.emptyResult();
      }

      // Step 8: Run evasion detection
      const evasionDetector = new EvasionDetector(this.logger);
      const evasionDetection = evasionDetector.analyze({
        processEvents: monitorResults.processEvents,
        fileEvents: monitorResults.fileEvents,
        registryEvents: monitorResults.registryEvents,
        networkEvents: monitorResults.networkEvents,
        executionOutput: executionResult.stdout + executionResult.stderr,
      });

      const durationMs = Date.now() - startTime;

      this.logger.info(
        {
          sessionId,
          durationMs,
          processEvents: monitorResults.processEvents.length,
          fileEvents: monitorResults.fileEvents.length,
          registryEvents: monitorResults.registryEvents.length,
          networkEvents: monitorResults.networkEvents.length,
          evasionAttempts: evasionDetection.attempts.length,
          screenshots: captureResult.screenshotTimeline.length,
          interestingFrames: captureResult.interestingFrameCount,
          videoGenerated: captureResult.videoPath !== null,
          keyMoments: captureResult.keyMoments.length,
        },
        'Detonation session complete',
      );

      return {
        submissionId: request.submissionId,
        sessionId,
        durationMs,
        processEvents: monitorResults.processEvents,
        fileEvents: monitorResults.fileEvents,
        registryEvents: monitorResults.registryEvents,
        networkEvents: monitorResults.networkEvents,
        memoryAnalysis,
        evasionDetection,
        artifacts,
        capture: captureResult,
        executionExitCode: executionResult.exitCode,
        executionStdout: executionResult.stdout,
        executionStderr: executionResult.stderr,
      };
    } finally {
      // Step 9: Always destroy sandbox
      try {
        await this.sandboxClient.destroy(instanceId);
        this.logger.info({ instanceId }, 'Sandbox destroyed');
      } catch (err) {
        this.logger.error({ instanceId, err }, 'Failed to destroy sandbox');
      }
    }
  }

  // ── Private helpers ─────────────────────────────────────────────────────

  private getRemoteSamplePath(os: string, fileName: string): string {
    const safe = fileName.replace(/[/\\";$`&|!<>(){}[\]#~*?\x00-\x1f]/g, '_');
    if (os.toLowerCase().startsWith('windows')) {
      return `C:\\Users\\analyst\\Desktop\\${safe}`;
    }
    return `/home/analyst/Desktop/${safe}`;
  }

  private async installMonitoringHooks(
    instanceId: string,
    os: string,
  ): Promise<void> {
    if (os.toLowerCase().startsWith('windows')) {
      // Start Process Monitor (Procmon) in the background
      await this.sandboxClient.executeCommand(
        instanceId,
        'start /B C:\\Tools\\Procmon.exe /AcceptEula /Quiet /Minimized /BackingFile C:\\Logs\\procmon.pml',
      );

      // Start Sysmon if available
      await this.sandboxClient.executeCommand(
        instanceId,
        'net start sysmon64 2>nul || echo Sysmon not installed',
      );

      // Start API monitoring
      await this.sandboxClient.executeCommand(
        instanceId,
        'start /B C:\\Tools\\apimon.exe /log C:\\Logs\\apimon.log',
      );
    } else {
      // Linux: start auditd-based monitoring
      await this.sandboxClient.executeCommand(
        instanceId,
        'auditctl -a always,exit -F arch=b64 -S execve -S fork -S clone -k process_tracking',
      );

      // Start inotifywait for file monitoring
      await this.sandboxClient.executeCommand(
        instanceId,
        'inotifywait -m -r --format "%T %w%f %e" --timefmt "%s" /tmp /home /var/tmp /usr/local/bin > /var/log/scanboy-files.log 2>&1 &',
      );

      // Start strace on the parent shell
      await this.sandboxClient.executeCommand(
        instanceId,
        'strace -f -e trace=network,process,file -o /var/log/scanboy-strace.log -p 1 &',
      );
    }
  }

  private async executeDll(
    instanceId: string,
    dllPath: string,
  ): Promise<{ exitCode: number; stdout: string; stderr: string; durationMs: number }> {
    const commands = buildDllCommands(dllPath);
    let lastResult = { exitCode: -1, stdout: '', stderr: '', durationMs: 0 };

    for (const cmd of commands) {
      try {
        lastResult = await this.sandboxClient.executeCommand(instanceId, cmd);
        if (lastResult.exitCode === 0) {
          this.logger.info(
            { command: cmd },
            'DLL entry point executed successfully',
          );
          break;
        }
      } catch (err) {
        this.logger.debug(
          { command: cmd, err },
          'DLL entry point failed, trying next',
        );
      }
    }

    return lastResult;
  }

  private async monitorExecution(
    instanceId: string,
    request: DetonationRequest,
    artifactDir: string,
  ): Promise<{
    processEvents: ProcessEvent[];
    fileEvents: FileEvent[];
    registryEvents: RegistryEvent[];
    networkEvents: NetworkEvent[];
  }> {
    const processMonitor = new ProcessMonitor(this.logger);
    const fileMonitor = new FileMonitor(this.logger);
    const registryMonitor = new RegistryMonitor(this.logger);
    const networkMonitor = new NetworkMonitor(this.logger);

    const durationMs = request.durationSeconds * 1000;
    const pollInterval = this.cfg.monitorPollIntervalMs;
    const screenshotInterval = this.cfg.screenshotIntervalSeconds * 1000;
    const screenshotPaths: string[] = [];
    let elapsed = 0;
    let lastScreenshot = 0;

    while (elapsed < durationMs) {
      const pollStart = Date.now();

      // Poll process events
      try {
        const procOutput = await this.sandboxClient.executeCommand(
          instanceId,
          this.getProcessPollCommand(request.os),
        );
        processMonitor.ingestRawOutput(procOutput.stdout);
      } catch {
        // Monitor polling failure is non-fatal
      }

      // Poll file events
      try {
        const fileOutput = await this.sandboxClient.executeCommand(
          instanceId,
          this.getFilePollCommand(request.os),
        );
        fileMonitor.ingestRawOutput(fileOutput.stdout);
      } catch {
        // Non-fatal
      }

      // Poll registry events (Windows only)
      if (request.os.toLowerCase().startsWith('windows')) {
        try {
          const regOutput = await this.sandboxClient.executeCommand(
            instanceId,
            this.getRegistryPollCommand(),
          );
          registryMonitor.ingestRawOutput(regOutput.stdout);
        } catch {
          // Non-fatal
        }
      }

      // Poll network events
      try {
        const netOutput = await this.sandboxClient.executeCommand(
          instanceId,
          this.getNetworkPollCommand(request.os),
        );
        networkMonitor.ingestRawOutput(netOutput.stdout);
      } catch {
        // Non-fatal
      }

      // Capture screenshot at intervals
      if (elapsed - lastScreenshot >= screenshotInterval) {
        try {
          const screenshot = await this.sandboxClient.captureScreenshot(instanceId);
          const screenshotPath = join(
            artifactDir,
            `screenshot-${Date.now()}.ppm`,
          );
          await writeFile(screenshotPath, screenshot);
          screenshotPaths.push(screenshotPath);
          lastScreenshot = elapsed;
        } catch {
          // Screenshot failure is non-fatal
        }
      }

      const pollDuration = Date.now() - pollStart;
      const sleepTime = Math.max(0, pollInterval - pollDuration);

      if (sleepTime > 0) {
        await new Promise<void>((resolve) => setTimeout(resolve, sleepTime));
      }

      elapsed += pollInterval;
    }

    return {
      processEvents: processMonitor.getEvents(),
      fileEvents: fileMonitor.getEvents(),
      registryEvents: registryMonitor.getEvents(),
      networkEvents: networkMonitor.getEvents(),
    };
  }

  private async collectArtifacts(
    instanceId: string,
    artifactDir: string,
    capturedScreenshotPaths: string[] = [],
  ): Promise<DetonationArtifacts> {
    const screenshotPaths: string[] = [...capturedScreenshotPaths];
    let pcapPath: string | null = null;
    let memoryDumpPath: string | null = null;

    // Collect network capture
    try {
      const pcap = await this.sandboxClient.getNetworkCapture(instanceId);
      pcapPath = join(artifactDir, 'capture.pcap');
      await writeFile(pcapPath, pcap);
    } catch (err) {
      this.logger.warn({ err }, 'Failed to collect network capture');
    }

    // Collect memory dump
    try {
      const memDump = await this.sandboxClient.getMemoryDump(instanceId);
      memoryDumpPath = join(artifactDir, 'memory.raw');
      await writeFile(memoryDumpPath, memDump);
    } catch (err) {
      this.logger.warn({ err }, 'Failed to collect memory dump');
    }

    return {
      screenshotPaths,
      pcapPath,
      memoryDumpPath,
      processTreePath: join(artifactDir, 'process-tree.json'),
      filesystemDiffPath: join(artifactDir, 'filesystem-diff.json'),
      registryDiffPath: join(artifactDir, 'registry-diff.json'),
    };
  }

  private getProcessPollCommand(os: string): string {
    if (os.toLowerCase().startsWith('windows')) {
      return 'wmic process list brief /format:csv';
    }
    return 'ps auxf --no-headers';
  }

  private getFilePollCommand(os: string): string {
    if (os.toLowerCase().startsWith('windows')) {
      return 'type C:\\Logs\\filechanges.log 2>nul';
    }
    return 'cat /var/log/scanboy-files.log 2>/dev/null';
  }

  private getRegistryPollCommand(): string {
    return 'reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /s & ' +
      'reg query HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /s & ' +
      'reg query HKLM\\SYSTEM\\CurrentControlSet\\Services /s 2>nul';
  }

  private getNetworkPollCommand(os: string): string {
    if (os.toLowerCase().startsWith('windows')) {
      return 'netstat -anob 2>nul';
    }
    return 'ss -tupn 2>/dev/null && cat /var/log/scanboy-strace.log 2>/dev/null | grep -E "connect|sendto|recvfrom" | tail -100';
  }
}
