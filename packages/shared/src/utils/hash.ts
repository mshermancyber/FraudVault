/**
 * Supported hash algorithms for file identification.
 */
export type HashAlgorithm = 'md5' | 'sha1' | 'sha256' | 'ssdeep';

/**
 * A collection of hashes computed for a single artifact.
 */
export interface FileHashes {
  readonly md5: string;
  readonly sha1: string;
  readonly sha256: string;
  readonly ssdeep: string | null;
}

/**
 * Validates that a string looks like a hex-encoded hash of the expected length.
 */
export function isValidHex(value: string, expectedLength: number): boolean {
  const hexPattern = new RegExp(`^[a-fA-F0-9]{${String(expectedLength)}}$`);
  return hexPattern.test(value);
}

/**
 * Validates an MD5 hash string (32 hex characters).
 */
export function isValidMd5(value: string): boolean {
  return isValidHex(value, 32);
}

/**
 * Validates a SHA-1 hash string (40 hex characters).
 */
export function isValidSha1(value: string): boolean {
  return isValidHex(value, 40);
}

/**
 * Validates a SHA-256 hash string (64 hex characters).
 */
export function isValidSha256(value: string): boolean {
  return isValidHex(value, 64);
}
