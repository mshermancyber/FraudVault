import { access, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import type pino from 'pino';

// ── Types ───────────────────────────────────────────────────────────────────

interface FfmpegResult {
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;
}

// ── Constants ───────────────────────────────────────────────────────────────

/** Default framerate when stitching screenshots into video. */
const DEFAULT_FRAMERATE = 2;

/** Default video codec. */
const DEFAULT_CODEC = 'libx264';

/** Pixel format required for broad player compatibility. */
const DEFAULT_PIX_FMT = 'yuv420p';

/** Maximum time (ms) to wait for ffmpeg to finish. */
const FFMPEG_TIMEOUT_MS = 120_000;

// ── VideoRecorder ───────────────────────────────────────────────────────────

export class VideoRecorder {
  private recordingStartTime: number | null = null;
  private recordingStopTime: number | null = null;
  private recordingPath: string | null = null;
  private screenshotDir: string | null = null;
  private recording = false;

  constructor(private readonly logger: pino.Logger) {}

  // ── Public API ──────────────────────────────────────────────────────────

  /**
   * Begin a recording session.  This records the start time and the
   * directory where frame images will be collected.  Actual video
   * generation happens in {@link stopRecording}.
   *
   * @param outputPath - Path for the final MP4 file.
   * @param screenshotDirectory - Directory containing sequentially-named
   *   `frame_NNNN.png` images produced by {@link ScreenshotCapture}.
   */
  startRecording(outputPath: string, screenshotDirectory: string): void {
    if (this.recording) {
      this.logger.warn('VideoRecorder.startRecording called while already recording');
      return;
    }

    this.recording = true;
    this.recordingStartTime = Date.now();
    this.recordingStopTime = null;
    this.recordingPath = outputPath;
    this.screenshotDir = screenshotDirectory;

    this.logger.info(
      { outputPath, screenshotDirectory },
      'Video recording session started',
    );
  }

  /**
   * Stop the recording session and generate an MP4 video from the
   * collected screenshot frames using ffmpeg.
   *
   * @returns The path to the generated video, or `null` if generation failed.
   */
  async stopRecording(): Promise<string | null> {
    if (!this.recording) {
      this.logger.warn('VideoRecorder.stopRecording called but not recording');
      return null;
    }

    this.recording = false;
    this.recordingStopTime = Date.now();

    const outputPath = this.recordingPath;
    const screenshotDir = this.screenshotDir;

    if (outputPath === null || screenshotDir === null) {
      this.logger.error('Recording paths not set');
      return null;
    }

    this.logger.info(
      { outputPath, screenshotDir },
      'Stopping video recording, generating MP4',
    );

    try {
      const inputPattern = join(screenshotDir, 'frame_%04d.png');

      // Verify at least one frame exists
      const firstFrame = join(screenshotDir, 'frame_0000.png');
      await access(firstFrame);

      const result = await this.runFfmpeg([
        '-framerate', String(DEFAULT_FRAMERATE),
        '-i', inputPattern,
        '-c:v', DEFAULT_CODEC,
        '-pix_fmt', DEFAULT_PIX_FMT,
        '-movflags', '+faststart',
        '-y',
        outputPath,
      ]);

      if (result.exitCode !== 0) {
        this.logger.error(
          { exitCode: result.exitCode, stderr: result.stderr },
          'ffmpeg exited with non-zero code',
        );
        return null;
      }

      // Verify output was created
      await access(outputPath);

      const fileStat = await stat(outputPath);
      this.logger.info(
        {
          outputPath,
          fileSizeBytes: fileStat.size,
          durationSeconds: this.getDuration(),
        },
        'Video generated successfully',
      );

      return outputPath;
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      this.logger.error(
        { error: message, outputPath },
        'Failed to generate video from screenshots',
      );
      return null;
    }
  }

  /**
   * Get the path to the generated video file, or `null` if recording has
   * not been stopped / generation failed.
   */
  getRecordingPath(): string | null {
    return this.recordingPath;
  }

  /**
   * Get the recording duration in seconds.
   * Returns 0 if the recording has not started or is still in progress.
   */
  getDuration(): number {
    if (this.recordingStartTime === null) return 0;
    const endTime = this.recordingStopTime ?? Date.now();
    return Math.round((endTime - this.recordingStartTime) / 1000);
  }

  /**
   * Whether the recorder is currently in a recording session.
   */
  isRecording(): boolean {
    return this.recording;
  }

  // ── Private helpers ─────────────────────────────────────────────────────

  private runFfmpeg(args: readonly string[]): Promise<FfmpegResult> {
    return new Promise<FfmpegResult>((resolve) => {
      const child = execFile(
        'ffmpeg',
        args as string[],
        { timeout: FFMPEG_TIMEOUT_MS, maxBuffer: 10 * 1024 * 1024 },
        (error, stdout, stderr) => {
          if (error !== null && 'code' in error && typeof error.code === 'number') {
            resolve({ exitCode: error.code, stdout, stderr });
            return;
          }
          if (error !== null) {
            // Process was killed / timed out
            resolve({ exitCode: 1, stdout, stderr: stderr || error.message });
            return;
          }
          resolve({ exitCode: 0, stdout, stderr });
        },
      );

      child.on('error', (err) => {
        resolve({ exitCode: 1, stdout: '', stderr: err.message });
      });
    });
  }
}
