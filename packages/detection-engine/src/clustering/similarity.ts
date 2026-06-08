import type { BehaviorVector, NetworkPattern } from './behaviorVector.js';
import { toNumericalVector } from './behaviorVector.js';

// ── Feature category weights ───────────────────────────────────────────────
//
// These weights control how much each feature category contributes to the
// overall behavioural similarity score.  They must sum to 1.0.

export const FEATURE_WEIGHTS = {
  techniques: 0.3,
  network: 0.25,
  persistence: 0.2,
  files: 0.15,
  registry: 0.1,
} as const;

// ── Primitive similarity functions ─────────────────────────────────────────

/**
 * Jaccard similarity between two sets.
 * Returns a value in [0, 1] where 1 means the sets are identical.
 * Returns 1.0 when both sets are empty (vacuous truth).
 */
export function jaccardSimilarity(setA: ReadonlyArray<string>, setB: ReadonlyArray<string>): number {
  if (setA.length === 0 && setB.length === 0) return 1.0;

  const a = new Set(setA);
  const b = new Set(setB);

  let intersection = 0;
  for (const item of a) {
    if (b.has(item)) intersection++;
  }

  const union = a.size + b.size - intersection;
  return union === 0 ? 1.0 : intersection / union;
}

/**
 * Cosine similarity between two numerical vectors.
 * Returns a value in [0, 1] (clamped) where 1 means identical direction.
 * Returns 1.0 when both vectors are zero-vectors.
 */
export function cosineSimilarity(vectorA: ReadonlyArray<number>, vectorB: ReadonlyArray<number>): number {
  const len = Math.min(vectorA.length, vectorB.length);
  if (len === 0) return 1.0;

  let dotProduct = 0;
  let normA = 0;
  let normB = 0;

  for (let i = 0; i < len; i++) {
    const a = vectorA[i] ?? 0;
    const b = vectorB[i] ?? 0;
    dotProduct += a * b;
    normA += a * a;
    normB += b * b;
  }

  const magnitude = Math.sqrt(normA) * Math.sqrt(normB);
  if (magnitude === 0) return 1.0;

  return Math.max(0, Math.min(1, dotProduct / magnitude));
}

// ── Fuzzy string matching ──────────────────────────────────────────────────

/**
 * Fuzzy Jaccard similarity.
 *
 * For each element in setA we find the best fuzzy match in setB. An element
 * pair counts as a match when their normalised Levenshtein distance is below
 * `threshold` (default 0.3, i.e. up to 30 % edits).
 */
export function fuzzyJaccardSimilarity(
  setA: ReadonlyArray<string>,
  setB: ReadonlyArray<string>,
  threshold = 0.3,
): number {
  if (setA.length === 0 && setB.length === 0) return 1.0;
  if (setA.length === 0 || setB.length === 0) return 0.0;

  let matchCount = 0;
  const matchedB = new Set<number>();

  for (const a of setA) {
    let bestDist = Infinity;
    let bestIdx = -1;
    for (let j = 0; j < setB.length; j++) {
      if (matchedB.has(j)) continue;
      const b = setB[j]!;
      const maxLen = Math.max(a.length, b.length);
      if (maxLen === 0) {
        bestDist = 0;
        bestIdx = j;
        break;
      }
      const dist = levenshteinDistance(a, b) / maxLen;
      if (dist < bestDist) {
        bestDist = dist;
        bestIdx = j;
      }
    }
    if (bestDist <= threshold && bestIdx >= 0) {
      matchCount++;
      matchedB.add(bestIdx);
    }
  }

  const union = setA.length + setB.length - matchCount;
  return union === 0 ? 1.0 : matchCount / union;
}

/**
 * Classic Levenshtein edit-distance (insertions, deletions, substitutions).
 * Uses a single-row DP implementation for space efficiency.
 */
function levenshteinDistance(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;

  // prev and curr are the two active rows of the DP matrix.
  let prev = new Array<number>(n + 1);
  let curr = new Array<number>(n + 1);

  for (let j = 0; j <= n; j++) prev[j] = j;

  for (let i = 1; i <= m; i++) {
    curr[0] = i;
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(
        (prev[j] ?? 0) + 1,       // deletion
        (curr[j - 1] ?? 0) + 1,   // insertion
        (prev[j - 1] ?? 0) + cost, // substitution
      );
    }
    [prev, curr] = [curr, prev];
  }

  return prev[n] ?? 0;
}

// ── Network pattern similarity ─────────────────────────────────────────────

/**
 * Calculate similarity between two sets of NetworkPatterns.
 * Combines port/protocol overlap with DGA and encryption flags.
 */
function networkPatternSimilarity(
  patternsA: ReadonlyArray<NetworkPattern>,
  patternsB: ReadonlyArray<NetworkPattern>,
): number {
  if (patternsA.length === 0 && patternsB.length === 0) return 1.0;
  if (patternsA.length === 0 || patternsB.length === 0) return 0.0;

  // Port+protocol overlap (Jaccard)
  const keysA = patternsA.map((p) => `${p.protocol}:${String(p.port)}`);
  const keysB = patternsB.map((p) => `${p.protocol}:${String(p.port)}`);
  const portSimilarity = jaccardSimilarity(keysA, keysB);

  // DGA flag overlap
  const dgaA = patternsA.some((p) => p.isDGA);
  const dgaB = patternsB.some((p) => p.isDGA);
  const dgaSimilarity = dgaA === dgaB ? 1.0 : 0.0;

  // Encryption flag overlap
  const encA = patternsA.some((p) => p.usesEncryption);
  const encB = patternsB.some((p) => p.usesEncryption);
  const encSimilarity = encA === encB ? 1.0 : 0.0;

  // Beaconing similarity
  const beaconA = patternsA.some((p) => p.beaconInterval !== undefined && p.beaconInterval > 0);
  const beaconB = patternsB.some((p) => p.beaconInterval !== undefined && p.beaconInterval > 0);
  const beaconSimilarity = beaconA === beaconB ? 1.0 : 0.0;

  // Weighted combination
  return portSimilarity * 0.5 + dgaSimilarity * 0.2 + encSimilarity * 0.15 + beaconSimilarity * 0.15;
}

// ── Composite behavioural similarity ───────────────────────────────────────

/**
 * Calculate the overall behavioural similarity between two BehaviorVectors.
 *
 * Returns a value in [0, 1] where 1 means the samples are behaviourally
 * identical.  The score is a weighted combination of per-category
 * similarities:
 *
 *   techniques   = 0.30  (Jaccard on ATT&CK IDs)
 *   network      = 0.25  (custom network pattern similarity)
 *   persistence  = 0.20  (Jaccard on persistence method labels)
 *   files        = 0.15  (fuzzy Jaccard on normalised file patterns)
 *   registry     = 0.10  (fuzzy Jaccard on normalised registry patterns)
 *
 * A cosine-similarity adjustment on the numerical feature vector is blended
 * in as a secondary signal.
 */
export function calculateBehavioralSimilarity(
  vectorA: BehaviorVector,
  vectorB: BehaviorVector,
): number {
  // Per-category similarities
  const techniqueSim = jaccardSimilarity(vectorA.techniques, vectorB.techniques);
  const networkSim = networkPatternSimilarity(vectorA.networkPatterns, vectorB.networkPatterns);
  const persistenceSim = jaccardSimilarity(vectorA.persistenceMethods, vectorB.persistenceMethods);
  const fileSim = fuzzyJaccardSimilarity(vectorA.filePatterns, vectorB.filePatterns);
  const registrySim = fuzzyJaccardSimilarity(vectorA.registryPatterns, vectorB.registryPatterns);

  // Weighted categorical similarity
  const categoricalScore =
    techniqueSim * FEATURE_WEIGHTS.techniques +
    networkSim * FEATURE_WEIGHTS.network +
    persistenceSim * FEATURE_WEIGHTS.persistence +
    fileSim * FEATURE_WEIGHTS.files +
    registrySim * FEATURE_WEIGHTS.registry;

  // Cosine similarity on numerical features as a smoothing signal
  const numVecA = toNumericalVector(vectorA);
  const numVecB = toNumericalVector(vectorB);
  const cosineScore = cosineSimilarity(numVecA, numVecB);

  // Blend: 85 % categorical, 15 % cosine
  const blended = categoricalScore * 0.85 + cosineScore * 0.15;

  return Math.max(0, Math.min(1, blended));
}
