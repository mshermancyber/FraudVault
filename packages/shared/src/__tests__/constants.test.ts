import { describe, it, expect } from 'vitest';
import {
  threatLevelFromScore,
  SUPPORTED_FILE_EXTENSIONS,
  MAX_FILE_SIZE_BYTES,
  THREAT_SCORE_THRESHOLDS,
  ThreatLevel,
} from '../index.js';

describe('threatLevelFromScore', () => {
  it('returns Informational for score 0', () => {
    expect(threatLevelFromScore(0)).toBe(ThreatLevel.Informational);
  });

  it('returns Informational for score 9', () => {
    expect(threatLevelFromScore(9)).toBe(ThreatLevel.Informational);
  });

  it('returns Low for score 10', () => {
    expect(threatLevelFromScore(10)).toBe(ThreatLevel.Low);
  });

  it('returns Low for score 20', () => {
    expect(threatLevelFromScore(20)).toBe(ThreatLevel.Low);
  });

  it('returns Low for score 39', () => {
    expect(threatLevelFromScore(39)).toBe(ThreatLevel.Low);
  });

  it('returns Medium for score 40', () => {
    expect(threatLevelFromScore(40)).toBe(ThreatLevel.Medium);
  });

  it('returns Medium for score 50', () => {
    expect(threatLevelFromScore(50)).toBe(ThreatLevel.Medium);
  });

  it('returns Medium for score 69', () => {
    expect(threatLevelFromScore(69)).toBe(ThreatLevel.Medium);
  });

  it('returns High for score 70', () => {
    expect(threatLevelFromScore(70)).toBe(ThreatLevel.High);
  });

  it('returns High for score 80', () => {
    expect(threatLevelFromScore(80)).toBe(ThreatLevel.High);
  });

  it('returns High for score 89', () => {
    expect(threatLevelFromScore(89)).toBe(ThreatLevel.High);
  });

  it('returns Critical for score 90', () => {
    expect(threatLevelFromScore(90)).toBe(ThreatLevel.Critical);
  });

  it('returns Critical for score 100', () => {
    expect(threatLevelFromScore(100)).toBe(ThreatLevel.Critical);
  });

  it('clamps negative scores to 0 (Informational)', () => {
    expect(threatLevelFromScore(-10)).toBe(ThreatLevel.Informational);
  });

  it('clamps scores above 100 to 100 (Critical)', () => {
    expect(threatLevelFromScore(150)).toBe(ThreatLevel.Critical);
  });

  it('rounds fractional scores before lookup', () => {
    // 9.4 rounds to 9 -> Informational
    expect(threatLevelFromScore(9.4)).toBe(ThreatLevel.Informational);
    // 9.6 rounds to 10 -> Low
    expect(threatLevelFromScore(9.6)).toBe(ThreatLevel.Low);
  });
});

describe('SUPPORTED_FILE_EXTENSIONS', () => {
  it('contains common executable extensions', () => {
    expect(SUPPORTED_FILE_EXTENSIONS.has('.exe')).toBe(true);
    expect(SUPPORTED_FILE_EXTENSIONS.has('.dll')).toBe(true);
    expect(SUPPORTED_FILE_EXTENSIONS.has('.sys')).toBe(true);
  });

  it('contains script extensions', () => {
    expect(SUPPORTED_FILE_EXTENSIONS.has('.ps1')).toBe(true);
    expect(SUPPORTED_FILE_EXTENSIONS.has('.bat')).toBe(true);
    expect(SUPPORTED_FILE_EXTENSIONS.has('.sh')).toBe(true);
    expect(SUPPORTED_FILE_EXTENSIONS.has('.py')).toBe(true);
    expect(SUPPORTED_FILE_EXTENSIONS.has('.js')).toBe(true);
    expect(SUPPORTED_FILE_EXTENSIONS.has('.vbs')).toBe(true);
  });

  it('contains document extensions', () => {
    expect(SUPPORTED_FILE_EXTENSIONS.has('.pdf')).toBe(true);
    expect(SUPPORTED_FILE_EXTENSIONS.has('.doc')).toBe(true);
    expect(SUPPORTED_FILE_EXTENSIONS.has('.docx')).toBe(true);
    expect(SUPPORTED_FILE_EXTENSIONS.has('.xls')).toBe(true);
    expect(SUPPORTED_FILE_EXTENSIONS.has('.xlsx')).toBe(true);
  });

  it('contains archive extensions', () => {
    expect(SUPPORTED_FILE_EXTENSIONS.has('.zip')).toBe(true);
    expect(SUPPORTED_FILE_EXTENSIONS.has('.rar')).toBe(true);
    expect(SUPPORTED_FILE_EXTENSIONS.has('.7z')).toBe(true);
  });

  it('contains mobile/java extensions', () => {
    expect(SUPPORTED_FILE_EXTENSIONS.has('.apk')).toBe(true);
    expect(SUPPORTED_FILE_EXTENSIONS.has('.jar')).toBe(true);
    expect(SUPPORTED_FILE_EXTENSIONS.has('.dex')).toBe(true);
  });

  it('does not contain unsupported extensions', () => {
    expect(SUPPORTED_FILE_EXTENSIONS.has('.mp3')).toBe(false);
    expect(SUPPORTED_FILE_EXTENSIONS.has('.jpg')).toBe(false);
    expect(SUPPORTED_FILE_EXTENSIONS.has('.mp4')).toBe(false);
  });
});

describe('MAX_FILE_SIZE_BYTES', () => {
  it('is 256 MB', () => {
    expect(MAX_FILE_SIZE_BYTES).toBe(256 * 1024 * 1024);
  });

  it('is a positive number', () => {
    expect(MAX_FILE_SIZE_BYTES).toBeGreaterThan(0);
  });

  it('is at least 1 MB', () => {
    expect(MAX_FILE_SIZE_BYTES).toBeGreaterThanOrEqual(1024 * 1024);
  });

  it('does not exceed 1 GB', () => {
    expect(MAX_FILE_SIZE_BYTES).toBeLessThanOrEqual(1024 * 1024 * 1024);
  });
});

describe('THREAT_SCORE_THRESHOLDS', () => {
  it('covers the full range 0-100 with no gaps', () => {
    // Sort by min to ensure order
    const sorted = [...THREAT_SCORE_THRESHOLDS].sort((a, b) => a.min - b.min);
    expect(sorted[0]!.min).toBe(0);
    expect(sorted[sorted.length - 1]!.max).toBe(100);

    for (let i = 1; i < sorted.length; i++) {
      expect(sorted[i]!.min).toBe(sorted[i - 1]!.max + 1);
    }
  });

  it('has exactly 5 threat levels', () => {
    expect(THREAT_SCORE_THRESHOLDS).toHaveLength(5);
  });
});
