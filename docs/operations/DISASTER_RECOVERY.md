# FraudVault Disaster Recovery Plan

## Overview

This document defines the disaster recovery procedures for the FraudVault malware analysis platform. The platform handles sensitive security data and must maintain availability for SOC operations.

## Recovery Objectives

| Metric | Target | Justification |
|--------|--------|---------------|
| RTO (Recovery Time) | 4 hours | SOC can use manual analysis during outage |
| RPO (Recovery Point) | 1 hour | Hourly PostgreSQL backups |
| MTTR (Mean Time to Repair) | 2 hours | Automated restore procedures |

## Data Classification

| Data Store | Criticality | Backup Frequency | Retention |
|------------|-------------|-------------------|-----------|
| PostgreSQL | Critical | Hourly incremental, daily full | 90 days |
| MinIO (artifacts) | High | Daily | 365 days |
| Elasticsearch | Medium | Rebuildable from PostgreSQL | N/A |
| Redis | Low | Ephemeral (queues rebuild) | N/A |

## Backup Procedures

### PostgreSQL

```bash
# Automated daily backup (add to cron)
0 * * * * docker compose exec -T postgres pg_dump -U scanboy -Fc scanboy > /backup/scanboy-$(date +%Y%m%d-%H%M).dump

# Verify backup integrity
pg_restore --list /backup/scanboy-latest.dump
```

### MinIO Artifacts

```bash
# Sync to backup location (requires backup destination configured in mc)
docker compose exec minio mc mirror /data /backup
```

### Configuration

```bash
# Backup all configuration
tar czf /backup/scanboy-config-$(date +%Y%m%d).tar.gz \
  .env \
  docker-compose.yml \
  nginx/ \
  docs/database/migrations/
```

## Disaster Scenarios

### Scenario 1: Single Service Failure

**Impact:** Partial functionality loss
**Recovery:** Automatic restart via Docker Compose

```bash
docker compose restart [service-name]
```

### Scenario 2: Database Corruption

**Impact:** Full platform outage
**Recovery Time:** 1-2 hours

1. Stop all services:
   ```bash
   docker compose stop api-gateway orchestrator
   ```

2. Restore database:
   ```bash
   docker compose exec -T postgres dropdb -U scanboy scanboy
   docker compose exec -T postgres createdb -U scanboy scanboy
   docker compose exec -T postgres pg_restore -U scanboy -d scanboy < /backup/latest.dump
   ```

3. Restart services:
   ```bash
   docker compose start api-gateway orchestrator
   ```

4. Rebuild Elasticsearch indexes:
   ```bash
   curl -X POST https://localhost/api/v1/admin/reindex -H "Authorization: Bearer $TOKEN"
   ```

### Scenario 3: Complete Infrastructure Loss

**Impact:** Total platform outage
**Recovery Time:** 3-4 hours

1. Provision a fresh Linux server with Docker and Docker Compose installed

2. Restore configuration from backup (`.env`, `docker-compose.yml`, `nginx/`)

3. Build and start all services:
   ```bash
   docker compose build && docker compose up -d
   ```

4. Restore PostgreSQL from offsite backup:
   ```bash
   docker compose exec -T postgres pg_restore -U scanboy -d scanboy < /backup/latest.dump
   ```

5. Restore MinIO artifacts from offsite backup

6. Verify all services healthy:
   ```bash
   docker compose ps
   ```

7. Resume analysis pipeline

### Scenario 4: Sandbox Compromise

**Impact:** Security incident, potential data exposure
**Recovery Time:** 2-4 hours

1. Isolate sandbox network immediately
2. Stop all sandbox containers:
   ```bash
   docker ps --filter name=scanboy-sandbox -q | xargs docker stop
   ```
3. Audit all analysis results from affected period
4. Review host system integrity
5. Rebuild sandbox image from clean source:
   ```bash
   docker compose build dynamic-analysis
   ```
6. Recreate dynamic-analysis service:
   ```bash
   docker compose restart dynamic-analysis
   ```
7. Resume with enhanced monitoring

## Communication Plan

| Stakeholder | Notification Method | Timing |
|-------------|-------------------|--------|
| SOC Team | Slack/PagerDuty | Immediate |
| Security Engineering | Email + Slack | Within 15 min |
| CISO | Email | Within 1 hour |
| Affected Analysts | Platform banner | On recovery |

## Testing Schedule

| Test Type | Frequency | Description |
|-----------|-----------|-------------|
| Backup Restore | Monthly | Restore PostgreSQL to test environment |
| Service Failover | Quarterly | Kill random service, verify recovery |
| Full DR | Annually | Complete infrastructure rebuild from backup |

## Post-Incident Review

After every DR event:
1. Document timeline of events
2. Identify root cause
3. Calculate actual RTO/RPO achieved
4. Update procedures based on lessons learned
5. File report with security leadership
