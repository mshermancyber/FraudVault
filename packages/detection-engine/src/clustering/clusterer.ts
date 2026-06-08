import { randomUUID } from 'node:crypto';
import type { Pool } from 'pg';
import type { BehaviorVector, NetworkPattern } from './behaviorVector.js';
import { buildBehaviorVector } from './behaviorVector.js';
import { calculateBehavioralSimilarity } from './similarity.js';

// ── Types ──────────────────────────────────────────────────────────────────

/** The output of a clustering run. */
export interface ClusterResult {
  clusterId: string;
  familyName: string | null;
  members: string[];
  centroid: BehaviorVector;
  cohesion: number;
}

/**
 * Internal node tracked during hierarchical agglomerative clustering.
 * Each node starts as a single submission and may later be merged into a
 * larger cluster.
 */
interface ClusterNode {
  id: string;
  members: string[];
  vectors: BehaviorVector[];
  centroid: BehaviorVector;
}

// ── Distance matrix ────────────────────────────────────────────────────────

/**
 * A symmetric distance matrix stored as a flat upper-triangular array.
 * Entry (i, j) where i < j is stored at index `i * n - i*(i+1)/2 + (j - i - 1)`.
 */
class DistanceMatrix {
  private readonly data: Float64Array;
  private readonly n: number;

  constructor(n: number) {
    this.n = n;
    // Upper-triangular storage: n*(n-1)/2 entries
    this.data = new Float64Array(n * (n - 1) / 2);
  }

  private index(i: number, j: number): number {
    const lo = Math.min(i, j);
    const hi = Math.max(i, j);
    return lo * this.n - lo * (lo + 1) / 2 + (hi - lo - 1);
  }

  get(i: number, j: number): number {
    if (i === j) return 0;
    return this.data[this.index(i, j)] ?? 0;
  }

  set(i: number, j: number, value: number): void {
    if (i === j) return;
    this.data[this.index(i, j)] = value;
  }
}

// ── Centroid computation ───────────────────────────────────────────────────

/**
 * Compute the centroid of a set of BehaviorVectors by taking the union of
 * string-set features and the most common network patterns.
 */
function computeCentroid(vectors: BehaviorVector[]): BehaviorVector {
  if (vectors.length === 0) {
    return {
      techniques: [],
      networkPatterns: [],
      persistenceMethods: [],
      filePatterns: [],
      registryPatterns: [],
      imports: [],
    };
  }

  if (vectors.length === 1) {
    return { ...vectors[0]! };
  }

  // For string sets: keep items that appear in at least half the members
  // (rounded down, but minimum 1 occurrence threshold).
  const threshold = Math.max(1, Math.floor(vectors.length / 2));

  const techniques = majoritySet(vectors.map((v) => v.techniques), threshold);
  const persistenceMethods = majoritySet(vectors.map((v) => v.persistenceMethods), threshold);
  const filePatterns = majoritySet(vectors.map((v) => v.filePatterns), threshold);
  const registryPatterns = majoritySet(vectors.map((v) => v.registryPatterns), threshold);
  const imports = majoritySet(vectors.map((v) => v.imports), threshold);

  // Network patterns: keep patterns seen in >= threshold members
  const networkPatterns = majorityNetworkPatterns(
    vectors.map((v) => v.networkPatterns),
    threshold,
  );

  return {
    techniques,
    networkPatterns,
    persistenceMethods,
    filePatterns,
    registryPatterns,
    imports,
  };
}

/** Keep strings that appear in at least `minCount` of the provided arrays. */
function majoritySet(arrays: string[][], minCount: number): string[] {
  const counts = new Map<string, number>();
  for (const arr of arrays) {
    const seen = new Set<string>();
    for (const item of arr) {
      if (!seen.has(item)) {
        seen.add(item);
        counts.set(item, (counts.get(item) ?? 0) + 1);
      }
    }
  }
  const result: string[] = [];
  for (const [item, count] of counts) {
    if (count >= minCount) result.push(item);
  }
  return result.sort();
}

/** Keep NetworkPatterns (keyed on protocol:port) seen in >= minCount arrays. */
function majorityNetworkPatterns(
  arrays: NetworkPattern[][],
  minCount: number,
): NetworkPattern[] {
  const counts = new Map<string, { pattern: NetworkPattern; count: number }>();
  for (const arr of arrays) {
    const seen = new Set<string>();
    for (const p of arr) {
      const key = `${p.protocol}:${String(p.port)}`;
      if (!seen.has(key)) {
        seen.add(key);
        const existing = counts.get(key);
        if (existing) {
          existing.count++;
        } else {
          counts.set(key, { pattern: { ...p }, count: 1 });
        }
      }
    }
  }
  const result: NetworkPattern[] = [];
  for (const [, entry] of counts) {
    if (entry.count >= minCount) result.push(entry.pattern);
  }
  return result;
}

// ── Cluster cohesion ───────────────────────────────────────────────────────

/** Average pairwise similarity within a cluster (1.0 for singletons). */
function computeCohesion(vectors: BehaviorVector[]): number {
  if (vectors.length <= 1) return 1.0;

  let totalSim = 0;
  let pairs = 0;

  for (let i = 0; i < vectors.length; i++) {
    for (let j = i + 1; j < vectors.length; j++) {
      totalSim += calculateBehavioralSimilarity(vectors[i]!, vectors[j]!);
      pairs++;
    }
  }

  return pairs > 0 ? totalSim / pairs : 1.0;
}

// ── Average linkage ────────────────────────────────────────────────────────

/**
 * Average-linkage distance between two clusters.
 *
 * This is the mean of all pairwise distances between members of the two
 * clusters.  Distance = 1 - similarity.
 */
function averageLinkageDistance(
  nodesA: BehaviorVector[],
  nodesB: BehaviorVector[],
): number {
  let totalDist = 0;
  let pairs = 0;
  for (const a of nodesA) {
    for (const b of nodesB) {
      totalDist += 1 - calculateBehavioralSimilarity(a, b);
      pairs++;
    }
  }
  return pairs > 0 ? totalDist / pairs : 1.0;
}

// ── MalwareFamilyClusterer ─────────────────────────────────────────────────

export class MalwareFamilyClusterer {
  private readonly db: Pool;
  private readonly similarityThreshold: number;

  /** In-memory cluster registry used between full re-clustering runs. */
  private clusters: Map<string, ClusterNode> = new Map();

  constructor(db: Pool, similarityThreshold = 0.7) {
    this.db = db;
    this.similarityThreshold = similarityThreshold;
  }

  // ── Full re-clustering via HAC ─────────────────────────────────────

  /**
   * Run hierarchical agglomerative clustering (HAC) with average linkage
   * on the given submission IDs.
   *
   * Algorithm outline:
   *   1. Fetch analysis data for each submission.
   *   2. Build a BehaviorVector for each.
   *   3. Initialise the distance matrix.
   *   4. Repeatedly merge the closest pair of clusters until the minimum
   *      inter-cluster similarity drops below the threshold (i.e. the
   *      minimum distance exceeds `1 - threshold`).
   *   5. Return the resulting clusters with centroids and cohesion scores.
   */
  async clusterSubmissions(submissionIds: string[]): Promise<ClusterResult[]> {
    if (submissionIds.length === 0) return [];

    // 1. Fetch analysis data and build vectors
    const vectors = await this.fetchVectors(submissionIds);
    if (vectors.length === 0) return [];

    // 2. Initialise cluster nodes (one per submission)
    let nodes: ClusterNode[] = vectors.map(({ submissionId, vector }) => ({
      id: randomUUID(),
      members: [submissionId],
      vectors: [vector],
      centroid: { ...vector },
    }));

    // Single-element shortcut
    if (nodes.length === 1) {
      const node = nodes[0]!;
      return [this.nodeToResult(node)];
    }

    // 3. Build initial distance matrix (distance = 1 - similarity)
    let n = nodes.length;
    let distMatrix = new DistanceMatrix(n);
    for (let i = 0; i < n; i++) {
      for (let j = i + 1; j < n; j++) {
        const dist = 1 - calculateBehavioralSimilarity(
          nodes[i]!.centroid,
          nodes[j]!.centroid,
        );
        distMatrix.set(i, j, dist);
      }
    }

    // 4. Iteratively merge closest pair
    const distThreshold = 1 - this.similarityThreshold;

    while (n > 1) {
      // Find the closest pair
      let minDist = Infinity;
      let mergeI = -1;
      let mergeJ = -1;

      for (let i = 0; i < n; i++) {
        for (let j = i + 1; j < n; j++) {
          const d = distMatrix.get(i, j);
          if (d < minDist) {
            minDist = d;
            mergeI = i;
            mergeJ = j;
          }
        }
      }

      // Stop if closest pair is above threshold
      if (minDist > distThreshold || mergeI < 0 || mergeJ < 0) break;

      // Merge mergeJ into mergeI
      const nodeI = nodes[mergeI]!;
      const nodeJ = nodes[mergeJ]!;

      const mergedNode: ClusterNode = {
        id: randomUUID(),
        members: [...nodeI.members, ...nodeJ.members],
        vectors: [...nodeI.vectors, ...nodeJ.vectors],
        centroid: computeCentroid([...nodeI.vectors, ...nodeJ.vectors]),
      };

      // Build new node list (remove mergeJ first since mergeJ > mergeI)
      const newNodes: ClusterNode[] = [];
      for (let k = 0; k < n; k++) {
        if (k === mergeI) {
          newNodes.push(mergedNode);
        } else if (k !== mergeJ) {
          newNodes.push(nodes[k]!);
        }
      }

      // Rebuild distance matrix using average linkage for the merged cluster
      const newN = newNodes.length;
      const newDist = new DistanceMatrix(newN);

      // Map old indices to new
      const oldToNew = new Map<number, number>();
      let newIdx = 0;
      for (let k = 0; k < n; k++) {
        if (k === mergeI) {
          oldToNew.set(k, newIdx);
          newIdx++;
        } else if (k !== mergeJ) {
          oldToNew.set(k, newIdx);
          newIdx++;
        }
      }

      // Fill new distance matrix
      for (let i = 0; i < newN; i++) {
        for (let j = i + 1; j < newN; j++) {
          if (i === 0) {
            // Index 0 in newNodes is the merged cluster; recompute with average linkage
            const other = newNodes[j]!;
            const dist = averageLinkageDistance(mergedNode.vectors, other.vectors);
            newDist.set(i, j, dist);
          } else {
            // Both are unchanged clusters -- find their old indices and copy
            const oldI = findOldIndex(oldToNew, i);
            const oldJ = findOldIndex(oldToNew, j);
            if (oldI !== undefined && oldJ !== undefined) {
              newDist.set(i, j, distMatrix.get(oldI, oldJ));
            } else {
              // Fallback: recompute
              const dist = averageLinkageDistance(newNodes[i]!.vectors, newNodes[j]!.vectors);
              newDist.set(i, j, dist);
            }
          }
        }
      }

      nodes = newNodes;
      n = newN;
      distMatrix = newDist;
    }

    // 5. Convert remaining nodes to results
    const results: ClusterResult[] = nodes.map((node) => this.nodeToResult(node));

    // Update in-memory registry
    this.clusters.clear();
    for (const node of nodes) {
      this.clusters.set(node.id, node);
    }

    return results;
  }

  // ── Incremental assignment ─────────────────────────────────────────

  /**
   * Assign a single submission to the best-matching existing cluster, or
   * create a new singleton cluster if no cluster exceeds the similarity
   * threshold.
   *
   * Returns the ClusterResult that the submission was assigned to.
   */
  assignToCluster(submissionId: string, vector: BehaviorVector): ClusterResult {
    let bestCluster: ClusterNode | null = null;
    let bestSimilarity = 0;

    for (const [, cluster] of this.clusters) {
      const sim = calculateBehavioralSimilarity(vector, cluster.centroid);
      if (sim > bestSimilarity) {
        bestSimilarity = sim;
        bestCluster = cluster;
      }
    }

    if (bestCluster && bestSimilarity >= this.similarityThreshold) {
      // Add to existing cluster
      bestCluster.members.push(submissionId);
      bestCluster.vectors.push(vector);
      bestCluster.centroid = computeCentroid(bestCluster.vectors);
      return this.nodeToResult(bestCluster);
    }

    // Create new singleton cluster
    const newNode: ClusterNode = {
      id: randomUUID(),
      members: [submissionId],
      vectors: [vector],
      centroid: { ...vector },
    };
    this.clusters.set(newNode.id, newNode);
    return this.nodeToResult(newNode);
  }

  // ── Merge ──────────────────────────────────────────────────────────

  /**
   * Merge two existing clusters into one.  The merged cluster replaces both
   * source clusters.
   */
  mergeClusters(clusterIdA: string, clusterIdB: string): ClusterResult {
    const a = this.clusters.get(clusterIdA);
    const b = this.clusters.get(clusterIdB);
    if (!a) throw new Error(`Cluster ${clusterIdA} not found`);
    if (!b) throw new Error(`Cluster ${clusterIdB} not found`);

    const merged: ClusterNode = {
      id: randomUUID(),
      members: [...a.members, ...b.members],
      vectors: [...a.vectors, ...b.vectors],
      centroid: computeCentroid([...a.vectors, ...b.vectors]),
    };

    this.clusters.delete(clusterIdA);
    this.clusters.delete(clusterIdB);
    this.clusters.set(merged.id, merged);

    return this.nodeToResult(merged);
  }

  // ── Split ──────────────────────────────────────────────────────────

  /**
   * Split a cluster when its internal cohesion drops below the similarity
   * threshold.  Uses the bisecting k-means heuristic:
   *
   *   1. Find the two most dissimilar members in the cluster.
   *   2. Partition remaining members by which seed they are closer to.
   *   3. Re-cluster only if both partitions are non-empty.
   *
   * Returns the resulting clusters (may be 1 if the cluster cannot be split).
   */
  splitCluster(clusterId: string): ClusterResult[] {
    const node = this.clusters.get(clusterId);
    if (!node) throw new Error(`Cluster ${clusterId} not found`);

    if (node.members.length <= 1) {
      return [this.nodeToResult(node)];
    }

    // Find the two most dissimilar members
    let maxDist = -1;
    let seedI = 0;
    let seedJ = 1;

    for (let i = 0; i < node.vectors.length; i++) {
      for (let j = i + 1; j < node.vectors.length; j++) {
        const dist = 1 - calculateBehavioralSimilarity(node.vectors[i]!, node.vectors[j]!);
        if (dist > maxDist) {
          maxDist = dist;
          seedI = i;
          seedJ = j;
        }
      }
    }

    // If the two most dissimilar members are still within threshold, don't split
    if (maxDist <= 1 - this.similarityThreshold) {
      return [this.nodeToResult(node)];
    }

    // Partition members
    const groupA: { member: string; vector: BehaviorVector }[] = [];
    const groupB: { member: string; vector: BehaviorVector }[] = [];

    const seedVecI = node.vectors[seedI]!;
    const seedVecJ = node.vectors[seedJ]!;

    for (let k = 0; k < node.members.length; k++) {
      const vec = node.vectors[k]!;
      const member = node.members[k]!;
      const simToI = calculateBehavioralSimilarity(vec, seedVecI);
      const simToJ = calculateBehavioralSimilarity(vec, seedVecJ);

      if (simToI >= simToJ) {
        groupA.push({ member, vector: vec });
      } else {
        groupB.push({ member, vector: vec });
      }
    }

    // If one group is empty, we cannot split
    if (groupA.length === 0 || groupB.length === 0) {
      return [this.nodeToResult(node)];
    }

    // Remove old cluster and create two new ones
    this.clusters.delete(clusterId);

    const nodeA: ClusterNode = {
      id: randomUUID(),
      members: groupA.map((g) => g.member),
      vectors: groupA.map((g) => g.vector),
      centroid: computeCentroid(groupA.map((g) => g.vector)),
    };

    const nodeB: ClusterNode = {
      id: randomUUID(),
      members: groupB.map((g) => g.member),
      vectors: groupB.map((g) => g.vector),
      centroid: computeCentroid(groupB.map((g) => g.vector)),
    };

    this.clusters.set(nodeA.id, nodeA);
    this.clusters.set(nodeB.id, nodeB);

    return [this.nodeToResult(nodeA), this.nodeToResult(nodeB)];
  }

  // ── Internal helpers ───────────────────────────────────────────────

  /**
   * Fetch static + dynamic analysis results from the database and build
   * BehaviorVectors for each submission.
   */
  private async fetchVectors(
    submissionIds: string[],
  ): Promise<Array<{ submissionId: string; vector: BehaviorVector }>> {
    const results: Array<{ submissionId: string; vector: BehaviorVector }> = [];

    for (const submissionId of submissionIds) {
      // Fetch static analysis
      const staticRows = await this.db.query<{
        result: Record<string, unknown> | null;
      }>(
        `SELECT result FROM analysis_jobs
         WHERE submission_id = $1 AND job_type = 'static_analysis' AND status = 'completed'
         ORDER BY completed_at DESC LIMIT 1`,
        [submissionId],
      );
      const staticResult = staticRows.rows[0]?.result ?? null;

      // Fetch dynamic analysis
      const dynamicRows = await this.db.query<{
        result: Record<string, unknown> | null;
      }>(
        `SELECT result FROM analysis_jobs
         WHERE submission_id = $1 AND job_type = 'dynamic_analysis' AND status = 'completed'
         ORDER BY completed_at DESC LIMIT 1`,
        [submissionId],
      );
      const dynamicResult = dynamicRows.rows[0]?.result ?? null;

      const vector = buildBehaviorVector(
        staticResult as Parameters<typeof buildBehaviorVector>[0],
        dynamicResult as Parameters<typeof buildBehaviorVector>[1],
      );

      results.push({ submissionId, vector });
    }

    return results;
  }

  private nodeToResult(node: ClusterNode): ClusterResult {
    return {
      clusterId: node.id,
      familyName: null,
      members: [...node.members],
      centroid: node.centroid,
      cohesion: computeCohesion(node.vectors),
    };
  }
}

// ── Utility ────────────────────────────────────────────────────────────────

/** Reverse-lookup: find the old index that maps to a given new index. */
function findOldIndex(
  oldToNew: Map<number, number>,
  newIndex: number,
): number | undefined {
  for (const [oldIdx, mappedNew] of oldToNew) {
    if (mappedNew === newIndex) return oldIdx;
  }
  return undefined;
}
