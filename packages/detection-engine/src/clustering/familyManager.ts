import type { Pool, PoolClient } from 'pg';
import type { BehaviorVector } from './behaviorVector.js';
import { buildBehaviorVector } from './behaviorVector.js';
import { calculateBehavioralSimilarity } from './similarity.js';
import type { ClusterResult } from './clusterer.js';

// ── Types ──────────────────────────────────────────────────────────────────

export interface MalwareFamily {
  id: string;
  name: string;
  description: string | null;
  sampleCount: number;
  firstSeen: string;
  lastSeen: string;
  createdAt: string;
  updatedAt: string;
}

export interface FamilyMembership {
  id: string;
  familyId: string;
  submissionId: string;
  confidence: number;
  assignedAt: string;
}

export interface FamilyDetails {
  family: MalwareFamily;
  members: FamilyMembership[];
  commonBehaviors: {
    techniques: string[];
    persistenceMethods: string[];
    networkPorts: number[];
    imports: string[];
  };
  timeline: Array<{ date: string; sampleCount: number }>;
}

export interface SimilarSample {
  submissionId: string;
  familyId: string | null;
  familyName: string | null;
  similarity: number;
}

// ── Behavioral name patterns ───────────────────────────────────────────────

/** Maps behavioural characteristics to descriptive name fragments. */
const BEHAVIOR_NAME_FRAGMENTS: ReadonlyArray<{
  check: (centroid: BehaviorVector) => boolean;
  fragment: string;
}> = [
  {
    check: (c) => c.techniques.includes('T1486'),
    fragment: 'Ransom',
  },
  {
    check: (c) => c.techniques.includes('T1055') || c.techniques.includes('T1055.001') || c.techniques.includes('T1055.012'),
    fragment: 'Injector',
  },
  {
    check: (c) => c.techniques.includes('T1003') || c.techniques.includes('T1003.001') || c.techniques.includes('T1555.003'),
    fragment: 'Stealer',
  },
  {
    check: (c) => c.techniques.includes('T1056.001'),
    fragment: 'Keylogger',
  },
  {
    check: (c) => c.networkPatterns.some((p) => p.isDGA),
    fragment: 'DGA',
  },
  {
    check: (c) => c.networkPatterns.some((p) => p.beaconInterval !== undefined && p.beaconInterval > 0),
    fragment: 'Beacon',
  },
  {
    check: (c) => c.techniques.includes('T1059.001'),
    fragment: 'PowerShell',
  },
  {
    check: (c) => c.persistenceMethods.length > 0,
    fragment: 'Persistent',
  },
  {
    check: (c) => c.techniques.includes('T1105'),
    fragment: 'Downloader',
  },
  {
    check: (c) => c.techniques.includes('T1562.001') || c.techniques.includes('T1562.004'),
    fragment: 'Disabler',
  },
];

// ── FamilyManager ──────────────────────────────────────────────────────────

export class FamilyManager {
  private readonly db: Pool;

  constructor(db: Pool) {
    this.db = db;
  }

  // ── Create / update family ─────────────────────────────────────────

  /**
   * Create a new malware family record from a cluster result.
   * Returns the family ID.
   */
  async createFamily(
    name: string,
    description: string | null,
    cluster: ClusterResult,
  ): Promise<string> {
    const client = await this.db.connect();
    try {
      await client.query('BEGIN');

      // Insert family record
      const familyResult = await client.query<{ id: string }>(
        `INSERT INTO malware_families (name, description, sample_count, first_seen, last_seen, created_at, updated_at)
         VALUES ($1, $2, $3, NOW(), NOW(), NOW(), NOW())
         RETURNING id`,
        [name, description, cluster.members.length],
      );
      const familyId = familyResult.rows[0]!.id;

      // Insert memberships
      for (const submissionId of cluster.members) {
        const confidence = calculateMemberConfidence(cluster, submissionId);
        await client.query(
          `INSERT INTO family_memberships (family_id, submission_id, confidence, assigned_at)
           VALUES ($1, $2, $3, NOW())
           ON CONFLICT (family_id, submission_id) DO UPDATE SET confidence = EXCLUDED.confidence`,
          [familyId, submissionId, confidence],
        );
      }

      // Store cluster vector
      await client.query(
        `INSERT INTO behavioral_clusters (family_id, cluster_id, centroid, cohesion, member_count, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
         ON CONFLICT (cluster_id) DO UPDATE SET
           centroid = EXCLUDED.centroid,
           cohesion = EXCLUDED.cohesion,
           member_count = EXCLUDED.member_count,
           updated_at = NOW()`,
        [
          familyId,
          cluster.clusterId,
          JSON.stringify(cluster.centroid),
          cluster.cohesion,
          cluster.members.length,
        ],
      );

      await client.query('COMMIT');
      return familyId;
    } catch (err: unknown) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  }

  /**
   * Update an existing family with new cluster information.
   */
  async updateFamily(
    familyId: string,
    cluster: ClusterResult,
  ): Promise<void> {
    const client = await this.db.connect();
    try {
      await client.query('BEGIN');

      // Update memberships
      for (const submissionId of cluster.members) {
        const confidence = calculateMemberConfidence(cluster, submissionId);
        await client.query(
          `INSERT INTO family_memberships (family_id, submission_id, confidence, assigned_at)
           VALUES ($1, $2, $3, NOW())
           ON CONFLICT (family_id, submission_id) DO UPDATE SET confidence = EXCLUDED.confidence`,
          [familyId, submissionId, confidence],
        );
      }

      // Update cluster record
      await client.query(
        `INSERT INTO behavioral_clusters (family_id, cluster_id, centroid, cohesion, member_count, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
         ON CONFLICT (cluster_id) DO UPDATE SET
           centroid = EXCLUDED.centroid,
           cohesion = EXCLUDED.cohesion,
           member_count = EXCLUDED.member_count,
           updated_at = NOW()`,
        [
          familyId,
          cluster.clusterId,
          JSON.stringify(cluster.centroid),
          cluster.cohesion,
          cluster.members.length,
        ],
      );

      // Refresh stats
      await this.updateFamilyStatsForFamily(client, familyId);

      await client.query('COMMIT');
    } catch (err: unknown) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  }

  // ── Stats ──────────────────────────────────────────────────────────

  /**
   * Recalculate aggregate statistics (sample_count, first_seen, last_seen)
   * for all malware families.
   */
  async updateFamilyStats(): Promise<void> {
    await this.db.query(
      `UPDATE malware_families mf
       SET
         sample_count = sub.cnt,
         first_seen   = sub.first_seen,
         last_seen    = sub.last_seen,
         updated_at   = NOW()
       FROM (
         SELECT
           fm.family_id,
           COUNT(*)::int AS cnt,
           MIN(fm.assigned_at) AS first_seen,
           MAX(fm.assigned_at) AS last_seen
         FROM family_memberships fm
         GROUP BY fm.family_id
       ) sub
       WHERE mf.id = sub.family_id`,
    );
  }

  /**
   * Recalculate stats for a single family (used within transactions).
   */
  private async updateFamilyStatsForFamily(
    client: PoolClient,
    familyId: string,
  ): Promise<void> {
    await client.query(
      `UPDATE malware_families
       SET
         sample_count = sub.cnt,
         first_seen   = sub.first_seen,
         last_seen    = sub.last_seen,
         updated_at   = NOW()
       FROM (
         SELECT
           COUNT(*)::int AS cnt,
           MIN(assigned_at) AS first_seen,
           MAX(assigned_at) AS last_seen
         FROM family_memberships
         WHERE family_id = $1
       ) sub
       WHERE id = $1`,
      [familyId],
    );
  }

  // ── Name suggestion ────────────────────────────────────────────────

  /**
   * Suggest a human-readable family name based on threat-intel labels
   * present in the cluster's members or, failing that, based on the
   * behavioural characteristics of the cluster centroid.
   */
  async suggestFamilyName(cluster: ClusterResult): Promise<string> {
    // Try to find a common TI-assigned family name
    if (cluster.members.length > 0) {
      const placeholders = cluster.members.map((_, i) => `$${String(i + 1)}`).join(', ');
      const tiRows = await this.db.query<{ malware_family: string }>(
        `SELECT malware_family FROM threat_intel_results
         WHERE submission_id IN (${placeholders})
           AND malware_family IS NOT NULL
         GROUP BY malware_family
         ORDER BY COUNT(*) DESC
         LIMIT 1`,
        cluster.members,
      );

      if (tiRows.rows.length > 0 && tiRows.rows[0]!.malware_family) {
        return tiRows.rows[0]!.malware_family;
      }
    }

    // Fall back to behavioural naming
    return generateBehavioralName(cluster.centroid);
  }

  // ── Similar samples ────────────────────────────────────────────────

  /**
   * Find the most similar samples to a given submission across all families.
   */
  async getSimilarSamples(
    submissionId: string,
    limit: number,
  ): Promise<SimilarSample[]> {
    // Build the target vector
    const targetVector = await this.fetchSubmissionVector(submissionId);
    if (!targetVector) return [];

    // Fetch all cluster centroids and their members
    const clusterRows = await this.db.query<{
      family_id: string;
      cluster_id: string;
      centroid: string;
    }>(
      `SELECT family_id, cluster_id, centroid FROM behavioral_clusters`,
    );

    // Find clusters with similar centroids (pre-filter)
    const candidateFamilies: Array<{ familyId: string; centroidSim: number }> = [];
    for (const row of clusterRows.rows) {
      const centroid = JSON.parse(row.centroid as string) as BehaviorVector;
      const sim = calculateBehavioralSimilarity(targetVector, centroid);
      if (sim > 0.3) {
        candidateFamilies.push({ familyId: row.family_id, centroidSim: sim });
      }
    }

    // Sort candidates by centroid similarity and take top families
    candidateFamilies.sort((a, b) => b.centroidSim - a.centroidSim);
    const topFamilies = candidateFamilies.slice(0, 10);

    if (topFamilies.length === 0) return [];

    // Fetch members of candidate families
    const familyIds = topFamilies.map((f) => f.familyId);
    const placeholders = familyIds.map((_, i) => `$${String(i + 1)}`).join(', ');
    const memberRows = await this.db.query<{
      submission_id: string;
      family_id: string;
    }>(
      `SELECT submission_id, family_id FROM family_memberships
       WHERE family_id IN (${placeholders})
         AND submission_id != $${String(familyIds.length + 1)}`,
      [...familyIds, submissionId],
    );

    // Compute similarity for each candidate member
    const results: SimilarSample[] = [];
    for (const row of memberRows.rows) {
      const memberVector = await this.fetchSubmissionVector(row.submission_id);
      if (!memberVector) continue;

      const similarity = calculateBehavioralSimilarity(targetVector, memberVector);

      // Fetch family name
      const familyNameRow = await this.db.query<{ name: string }>(
        `SELECT name FROM malware_families WHERE id = $1`,
        [row.family_id],
      );

      results.push({
        submissionId: row.submission_id,
        familyId: row.family_id,
        familyName: familyNameRow.rows[0]?.name ?? null,
        similarity,
      });
    }

    // Sort by similarity descending and return top N
    results.sort((a, b) => b.similarity - a.similarity);
    return results.slice(0, limit);
  }

  // ── Family details ─────────────────────────────────────────────────

  /**
   * Get comprehensive details about a malware family including members,
   * common behaviours, and a submission timeline.
   */
  async getFamilyDetails(familyId: string): Promise<FamilyDetails | null> {
    // Fetch family record
    const familyRows = await this.db.query<{
      id: string;
      name: string;
      description: string | null;
      sample_count: number;
      first_seen: string;
      last_seen: string;
      created_at: string;
      updated_at: string;
    }>(
      `SELECT id, name, description, sample_count, first_seen, last_seen, created_at, updated_at
       FROM malware_families WHERE id = $1`,
      [familyId],
    );

    if (familyRows.rows.length === 0) return null;
    const familyRow = familyRows.rows[0]!;

    const family: MalwareFamily = {
      id: familyRow.id,
      name: familyRow.name,
      description: familyRow.description,
      sampleCount: familyRow.sample_count,
      firstSeen: familyRow.first_seen,
      lastSeen: familyRow.last_seen,
      createdAt: familyRow.created_at,
      updatedAt: familyRow.updated_at,
    };

    // Fetch memberships
    const memberRows = await this.db.query<{
      id: string;
      family_id: string;
      submission_id: string;
      confidence: number;
      assigned_at: string;
    }>(
      `SELECT id, family_id, submission_id, confidence, assigned_at
       FROM family_memberships WHERE family_id = $1
       ORDER BY assigned_at DESC`,
      [familyId],
    );

    const members: FamilyMembership[] = memberRows.rows.map((r) => ({
      id: r.id,
      familyId: r.family_id,
      submissionId: r.submission_id,
      confidence: r.confidence,
      assignedAt: r.assigned_at,
    }));

    // Fetch cluster centroid for common behaviors
    const clusterRows = await this.db.query<{ centroid: string }>(
      `SELECT centroid FROM behavioral_clusters
       WHERE family_id = $1
       ORDER BY updated_at DESC LIMIT 1`,
      [familyId],
    );

    let commonBehaviors: FamilyDetails['commonBehaviors'] = {
      techniques: [],
      persistenceMethods: [],
      networkPorts: [],
      imports: [],
    };

    if (clusterRows.rows.length > 0 && clusterRows.rows[0]!.centroid) {
      const centroid = JSON.parse(clusterRows.rows[0]!.centroid as string) as BehaviorVector;
      commonBehaviors = {
        techniques: centroid.techniques,
        persistenceMethods: centroid.persistenceMethods,
        networkPorts: [...new Set(centroid.networkPatterns.map((p) => p.port))],
        imports: centroid.imports,
      };
    }

    // Build timeline (samples per day)
    const timelineRows = await this.db.query<{
      date: string;
      sample_count: number;
    }>(
      `SELECT DATE(assigned_at) AS date, COUNT(*)::int AS sample_count
       FROM family_memberships
       WHERE family_id = $1
       GROUP BY DATE(assigned_at)
       ORDER BY date ASC`,
      [familyId],
    );

    const timeline = timelineRows.rows.map((r) => ({
      date: r.date,
      sampleCount: r.sample_count,
    }));

    return { family, members, commonBehaviors, timeline };
  }

  // ── Internal helpers ───────────────────────────────────────────────

  /**
   * Build a BehaviorVector for a submission from its stored analysis data.
   */
  private async fetchSubmissionVector(
    submissionId: string,
  ): Promise<BehaviorVector | null> {
    const staticRows = await this.db.query<{
      result: Record<string, unknown> | null;
    }>(
      `SELECT result FROM analysis_jobs
       WHERE submission_id = $1 AND job_type = 'static_analysis' AND status = 'completed'
       ORDER BY completed_at DESC LIMIT 1`,
      [submissionId],
    );

    const dynamicRows = await this.db.query<{
      result: Record<string, unknown> | null;
    }>(
      `SELECT result FROM analysis_jobs
       WHERE submission_id = $1 AND job_type = 'dynamic_analysis' AND status = 'completed'
       ORDER BY completed_at DESC LIMIT 1`,
      [submissionId],
    );

    const staticResult = staticRows.rows[0]?.result ?? null;
    const dynamicResult = dynamicRows.rows[0]?.result ?? null;

    if (!staticResult && !dynamicResult) return null;

    return buildBehaviorVector(
      staticResult as Parameters<typeof buildBehaviorVector>[0],
      dynamicResult as Parameters<typeof buildBehaviorVector>[1],
    );
  }
}

// ── Helper functions ───────────────────────────────────────────────────────

/**
 * Calculate the confidence that a specific submission belongs to a cluster,
 * based on its similarity to the cluster centroid.  Returns a value in
 * [0, 100].
 */
function calculateMemberConfidence(
  cluster: ClusterResult,
  _submissionId: string,
): number {
  // For a singleton cluster the member *is* the cluster
  if (cluster.members.length <= 1) return 100;

  // Use cohesion as a proxy for membership confidence
  // (higher cohesion = tighter cluster = higher confidence)
  return Math.round(cluster.cohesion * 100);
}

/**
 * Generate a descriptive name from the behavioural characteristics of the
 * cluster centroid when no TI label is available.
 */
function generateBehavioralName(centroid: BehaviorVector): string {
  const fragments: string[] = [];

  for (const { check, fragment } of BEHAVIOR_NAME_FRAGMENTS) {
    if (check(centroid)) {
      fragments.push(fragment);
    }
    // Limit to 3 fragments for readability
    if (fragments.length >= 3) break;
  }

  if (fragments.length === 0) {
    fragments.push('Generic');
  }

  // Append a short hex suffix derived from the centroid's technique list
  // to disambiguate families with similar behaviours.
  const hashInput = centroid.techniques.join(',') + centroid.imports.join(',');
  let hash = 0;
  for (let i = 0; i < hashInput.length; i++) {
    const ch = hashInput.charCodeAt(i);
    hash = ((hash << 5) - hash + ch) | 0;
  }
  const suffix = Math.abs(hash).toString(16).slice(0, 4).toUpperCase().padStart(4, '0');

  return `${fragments.join('.')}.${suffix}`;
}
