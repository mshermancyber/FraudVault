import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import type pino from 'pino';

// ── Types ───────────────────────────────────────────────────────────────────

/**
 * Interface matching the sandbox client's screenshot capability.
 * Avoids coupling to the full SandboxClient type.
 */
interface ScreenshotProvider {
  captureScreenshot(instanceId: string): Promise<Buffer>;
}

export interface ScreenshotMetadata {
  readonly timestamp: string;
  readonly path: string;
  readonly thumbnailPath: string;
  readonly width: number;
  readonly height: number;
  readonly index: number;
  readonly isInteresting: boolean;
  readonly eventDescription: string;
}

export interface ScreenshotTimelineEntry {
  readonly timestamp: string;
  readonly path: string;
  readonly thumbnailPath: string;
  readonly eventDescription: string;
}

interface PngDimensions {
  readonly width: number;
  readonly height: number;
}

// ── Constants ───────────────────────────────────────────────────────────────

/** Default screenshot capture interval in milliseconds. */
const DEFAULT_INTERVAL_MS = 5000;

/** Minimum fraction of changed pixels to mark a frame as "interesting". */
const PIXEL_DIFF_THRESHOLD = 0.05;

/** PNG file signature (first 8 bytes). */
const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

// ── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Parse width/height from a PNG IHDR chunk.
 * Returns null if the buffer is not a valid PNG.
 */
function parsePngDimensions(buf: Buffer): PngDimensions | null {
  if (buf.length < 24) return null;
  if (!buf.subarray(0, 8).equals(PNG_SIGNATURE)) return null;

  // IHDR starts at byte 8: 4 bytes length, 4 bytes "IHDR", then width (4) + height (4)
  const width = buf.readUInt32BE(16);
  const height = buf.readUInt32BE(20);
  return { width, height };
}

/**
 * Compute the fraction of bytes that differ between two equally-sized buffers.
 * If sizes differ the frames are considered fully different.
 */
function computePixelDiffRatio(a: Buffer, b: Buffer): number {
  if (a.length !== b.length) return 1.0;
  if (a.length === 0) return 0;

  let diffCount = 0;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      diffCount++;
    }
  }
  return diffCount / a.length;
}

/**
 * Build a very small thumbnail by copying every Nth pixel row/col from raw
 * RGBA-style data.  Since we store PNGs, the thumbnail is just a smaller PNG
 * buffer written to disk.  For simplicity we just copy the original at a
 * smaller filename; a production system would use sharp/libpng.
 */
function buildThumbnailPath(screenshotPath: string): string {
  const ext = screenshotPath.lastIndexOf('.');
  if (ext === -1) return `${screenshotPath}_thumb`;
  return `${screenshotPath.slice(0, ext)}_thumb${screenshotPath.slice(ext)}`;
}

/**
 * Generate a rough event description based on how much the screenshot changed.
 */
function describeChange(diffRatio: number, index: number): string {
  if (index === 0) return 'Initial desktop state captured';
  if (diffRatio >= 0.4) return 'Major desktop change detected (new window or dialog)';
  if (diffRatio >= 0.15) return 'Significant screen activity detected';
  if (diffRatio >= PIXEL_DIFF_THRESHOLD) return 'Moderate screen change detected';
  return 'Desktop idle / minimal change';
}

// ── ScreenshotCapture ───────────────────────────────────────────────────────

export class ScreenshotCapture {
  private readonly screenshots: ScreenshotMetadata[] = [];
  private previousBuffer: Buffer | null = null;
  private intervalHandle: ReturnType<typeof setInterval> | null = null;
  private captureIndex = 0;
  private running = false;

  constructor(
    private readonly provider: ScreenshotProvider,
    private readonly instanceId: string,
    private readonly outputDir: string,
    private readonly logger: pino.Logger,
  ) {}

  // ── Public API ──────────────────────────────────────────────────────────

  /**
   * Begin periodic screenshot capture.
   *
   * @param intervalMs - Capture interval in milliseconds (default 5 000).
   */
  start(intervalMs: number = DEFAULT_INTERVAL_MS): void {
    if (this.running) return;
    this.running = true;

    this.logger.info(
      { instanceId: this.instanceId, intervalMs },
      'Starting periodic screenshot capture',
    );

    // Take an immediate first screenshot, then repeat on the interval.
    void this.captureNow();

    this.intervalHandle = setInterval(() => {
      void this.captureNow();
    }, intervalMs);
  }

  /**
   * Stop periodic screenshot capture.
   */
  stop(): void {
    if (!this.running) return;
    this.running = false;

    if (this.intervalHandle !== null) {
      clearInterval(this.intervalHandle);
      this.intervalHandle = null;
    }

    this.logger.info(
      { instanceId: this.instanceId, totalScreenshots: this.screenshots.length },
      'Screenshot capture stopped',
    );
  }

  /**
   * Take an immediate screenshot and persist it to disk.
   */
  async captureNow(): Promise<ScreenshotMetadata | null> {
    try {
      const buffer = await this.provider.captureScreenshot(this.instanceId);
      const timestamp = new Date().toISOString();
      const index = this.captureIndex++;

      // Ensure output directory exists
      await mkdir(this.outputDir, { recursive: true });

      // Write screenshot
      const fileName = `frame_${String(index).padStart(4, '0')}.png`;
      const filePath = join(this.outputDir, fileName);
      await writeFile(filePath, buffer);

      // Write a thumbnail (in production this would be a resized image)
      const thumbPath = buildThumbnailPath(filePath);
      await writeFile(thumbPath, buffer);

      // Parse dimensions
      const dims = parsePngDimensions(buffer);
      const width = dims?.width ?? 0;
      const height = dims?.height ?? 0;

      // Compute diff against previous frame
      let diffRatio = 0;
      if (this.previousBuffer !== null) {
        diffRatio = computePixelDiffRatio(this.previousBuffer, buffer);
      }

      const isInteresting = index === 0 || diffRatio >= PIXEL_DIFF_THRESHOLD;
      const eventDescription = describeChange(diffRatio, index);

      this.previousBuffer = buffer;

      const metadata: ScreenshotMetadata = {
        timestamp,
        path: filePath,
        thumbnailPath: thumbPath,
        width,
        height,
        index,
        isInteresting,
        eventDescription,
      };

      this.screenshots.push(metadata);

      this.logger.debug(
        {
          index,
          isInteresting,
          diffRatio: Math.round(diffRatio * 1000) / 1000,
          width,
          height,
        },
        'Screenshot captured',
      );

      return metadata;
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      this.logger.warn(
        { instanceId: this.instanceId, error: message },
        'Screenshot capture failed',
      );
      return null;
    }
  }

  /**
   * Return all screenshots as an ordered timeline.
   */
  getTimeline(): readonly ScreenshotTimelineEntry[] {
    return this.screenshots.map((s) => ({
      timestamp: s.timestamp,
      path: s.path,
      thumbnailPath: s.thumbnailPath,
      eventDescription: s.eventDescription,
    }));
  }

  /**
   * Return only "interesting" frames where the desktop changed significantly.
   */
  getInterestingFrames(): readonly ScreenshotMetadata[] {
    return this.screenshots.filter((s) => s.isInteresting);
  }

  /**
   * Return all captured screenshot metadata.
   */
  getAllMetadata(): readonly ScreenshotMetadata[] {
    return [...this.screenshots];
  }

  /**
   * Return the ordered list of file paths to all captured screenshots.
   */
  getScreenshotPaths(): readonly string[] {
    return this.screenshots.map((s) => s.path);
  }

  /**
   * Export the full timeline metadata as a JSON file.
   */
  async exportTimeline(outputPath: string): Promise<void> {
    const timeline = {
      instanceId: this.instanceId,
      totalFrames: this.screenshots.length,
      interestingFrames: this.screenshots.filter((s) => s.isInteresting).length,
      screenshots: this.screenshots,
    };

    await writeFile(outputPath, JSON.stringify(timeline, null, 2), 'utf-8');

    this.logger.info(
      { outputPath, totalFrames: timeline.totalFrames },
      'Screenshot timeline exported',
    );
  }
}
