import * as fs from 'node:fs/promises';
import * as crypto from 'node:crypto';

// ── Result type ──────────────────────────────────────────────────────────────

export interface FileMetadataResult {
  /** File size in bytes. */
  fileSize: number;
  /** Detected MIME type via magic bytes, or 'application/octet-stream'. */
  mimeType: string;
  /** Human-readable file-type description (e.g. "PE32 executable"). */
  fileTypeLabel: string;
  /** File extension suggested by magic bytes (e.g. "exe"). */
  fileExtension: string | null;
  /** First 16 bytes of the file as a hex string ("magic bytes"). */
  magicHex: string;
  /** MD5 digest of the file. */
  md5: string;
  /** SHA-1 digest of the file. */
  sha1: string;
  /** SHA-256 digest of the file. */
  sha256: string;
  /** File-system timestamps. */
  timestamps: {
    created: string | null;
    modified: string | null;
    accessed: string | null;
  };
}

// ── Well-known magic bytes for supplementary detection ───────────────────────

interface MagicSignature {
  readonly bytes: readonly number[];
  readonly offset: number;
  readonly mime: string;
  readonly label: string;
}

const MAGIC_SIGNATURES: readonly MagicSignature[] = [
  { bytes: [0x4d, 0x5a], offset: 0, mime: 'application/vnd.microsoft.portable-executable', label: 'PE executable' },
  { bytes: [0x7f, 0x45, 0x4c, 0x46], offset: 0, mime: 'application/x-elf', label: 'ELF executable' },
  { bytes: [0x25, 0x50, 0x44, 0x46], offset: 0, mime: 'application/pdf', label: 'PDF document' },
  { bytes: [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1], offset: 0, mime: 'application/x-ole-storage', label: 'OLE Compound Document' },
  { bytes: [0x50, 0x4b, 0x03, 0x04], offset: 0, mime: 'application/zip', label: 'ZIP archive' },
  { bytes: [0xfe, 0xed, 0xfa, 0xce], offset: 0, mime: 'application/x-mach-binary', label: 'Mach-O 32-bit' },
  { bytes: [0xfe, 0xed, 0xfa, 0xcf], offset: 0, mime: 'application/x-mach-binary', label: 'Mach-O 64-bit' },
  { bytes: [0xca, 0xfe, 0xba, 0xbe], offset: 0, mime: 'application/java-archive', label: 'Java class / Mach-O Universal' },
  { bytes: [0x1f, 0x8b], offset: 0, mime: 'application/gzip', label: 'GZIP archive' },
  { bytes: [0x52, 0x61, 0x72, 0x21], offset: 0, mime: 'application/x-rar-compressed', label: 'RAR archive' },
];

function detectViaMagic(buf: Buffer): { mime: string; label: string } | null {
  for (const sig of MAGIC_SIGNATURES) {
    if (buf.length < sig.offset + sig.bytes.length) continue;
    let match = true;
    for (let i = 0; i < sig.bytes.length; i++) {
      if (buf[sig.offset + i] !== sig.bytes[i]) {
        match = false;
        break;
      }
    }
    if (match) return { mime: sig.mime, label: sig.label };
  }
  return null;
}

// ── Main extraction function ─────────────────────────────────────────────────

export async function extractMetadata(filePath: string): Promise<FileMetadataResult> {
  // Read the full file for hashing. For very large files in production this
  // would be streamed, but for the analysis sizes we support this is fine.
  const fileBuffer = await fs.readFile(filePath);
  const stat = await fs.stat(filePath);

  // Compute hashes.
  const md5 = crypto.createHash('md5').update(fileBuffer).digest('hex');
  const sha1 = crypto.createHash('sha1').update(fileBuffer).digest('hex');
  const sha256 = crypto.createHash('sha256').update(fileBuffer).digest('hex');

  // Detect file type via `file-type` (magic-bytes library).
  // file-type v19+ is ESM-only, so we use a dynamic import.
  const { fileTypeFromBuffer } = await import('file-type') as { fileTypeFromBuffer: (buf: Uint8Array) => Promise<{ mime: string; ext: string } | undefined> };
  const ftResult = await fileTypeFromBuffer(fileBuffer);

  // Fallback to our own signature table when file-type doesn't recognise it.
  const magicFallback = detectViaMagic(fileBuffer);

  const mimeType = ftResult?.mime ?? magicFallback?.mime ?? 'application/octet-stream';
  const fileExtension = ftResult?.ext ?? null;
  const fileTypeLabel = ftResult
    ? ftResult.mime
    : magicFallback?.label ?? 'Unknown binary';

  // First 16 bytes as hex.
  const magicHex = fileBuffer.subarray(0, 16).toString('hex');

  return {
    fileSize: stat.size,
    mimeType,
    fileTypeLabel,
    fileExtension,
    magicHex,
    md5,
    sha1,
    sha256,
    timestamps: {
      created: stat.birthtime ? stat.birthtime.toISOString() : null,
      modified: stat.mtime ? stat.mtime.toISOString() : null,
      accessed: stat.atime ? stat.atime.toISOString() : null,
    },
  };
}
