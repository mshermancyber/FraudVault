import { describe, it, expect } from 'vitest';
import { calculateEntropy } from '../analyzers/entropy.js';

describe('calculateEntropy', () => {
  it('returns 0 for an empty buffer', () => {
    const buf = Buffer.alloc(0);
    expect(calculateEntropy(buf)).toBe(0);
  });

  it('returns 0 for a buffer of all-zero bytes', () => {
    const buf = Buffer.alloc(1024, 0x00);
    expect(calculateEntropy(buf)).toBe(0);
  });

  it('returns 0 for a buffer of identical bytes', () => {
    const buf = Buffer.alloc(1024, 0xAA);
    expect(calculateEntropy(buf)).toBe(0);
  });

  it('returns exactly 1.0 for a buffer with exactly two equally-distributed byte values', () => {
    // 512 bytes of 0x00 followed by 512 bytes of 0x01
    const buf = Buffer.alloc(1024);
    for (let i = 512; i < 1024; i++) {
      buf[i] = 0x01;
    }
    const entropy = calculateEntropy(buf);
    expect(entropy).toBeCloseTo(1.0, 5);
  });

  it('returns entropy close to 8.0 for uniformly random bytes', () => {
    // Create a buffer with all 256 byte values equally represented
    const buf = Buffer.alloc(256 * 100);
    for (let i = 0; i < buf.length; i++) {
      buf[i] = i % 256;
    }
    const entropy = calculateEntropy(buf);
    // Should be exactly 8.0 for perfectly uniform distribution
    expect(entropy).toBeCloseTo(8.0, 5);
  });

  it('returns entropy approaching 8.0 for pseudo-random data', () => {
    // Simulate random data using a better LCG to get good byte distribution
    const buf = Buffer.alloc(256 * 400);
    let state = 42;
    for (let i = 0; i < buf.length; i++) {
      // Use a full-period LCG to ensure good byte distribution
      state = (state * 1103515245 + 12345) >>> 0;
      buf[i] = (state >>> 16) & 0xff;
    }
    const entropy = calculateEntropy(buf);
    expect(entropy).toBeGreaterThan(7.5);
    expect(entropy).toBeLessThanOrEqual(8.0);
  });

  it('returns low entropy for a repeated pattern', () => {
    // Repeating "AAAA" = single byte value
    const buf = Buffer.alloc(1000, 0x41);
    expect(calculateEntropy(buf)).toBe(0);
  });

  it('returns moderate entropy for a short repeating pattern with a few distinct bytes', () => {
    // Pattern "ABCD" repeated -> 4 byte values, equally distributed -> entropy = 2.0
    const buf = Buffer.alloc(1000);
    for (let i = 0; i < buf.length; i++) {
      buf[i] = 0x41 + (i % 4); // A, B, C, D
    }
    const entropy = calculateEntropy(buf);
    // 4 equally-distributed values => log2(4) = 2.0
    expect(entropy).toBeCloseTo(2.0, 1);
  });

  it('returns appropriate entropy for English-like text', () => {
    // Repeated English sentence (limited character set)
    const text = 'The quick brown fox jumps over the lazy dog. ';
    const buf = Buffer.from(text.repeat(100), 'ascii');
    const entropy = calculateEntropy(buf);
    // English text typically has entropy around 3.5-4.5 bits per byte
    expect(entropy).toBeGreaterThan(3.0);
    expect(entropy).toBeLessThan(5.0);
  });

  it('handles a single-byte buffer', () => {
    const buf = Buffer.from([0x42]);
    // Only one byte, only one frequency => entropy = 0
    expect(calculateEntropy(buf)).toBe(0);
  });

  it('works with Uint8Array as well as Buffer', () => {
    const arr = new Uint8Array(256);
    for (let i = 0; i < 256; i++) arr[i] = i;
    const entropy = calculateEntropy(arr);
    expect(entropy).toBeCloseTo(8.0, 5);
  });
});
