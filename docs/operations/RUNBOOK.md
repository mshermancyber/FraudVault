# FraudVault Operations Runbook

## Incident Response Procedures

### Service Degradation

**Symptoms:** Slow API responses, job queue backup, timeouts

1. Check service health:
   ```bash
   curl -k https://localhost/health
   ```

2. Check resource utilization:
   ```bash
   docker stats
   ```

3. Check queue depth:
   ```bash
   docker compose exec redis redis-cli -a "$REDIS_PASSWORD" LLEN bull:submission-intake:wait
   ```

4. Check PostgreSQL connections:
   ```bash
   docker compose exec postgres psql -U scanboy -c "SELECT count(*) FROM pg_stat_activity;"
   ```

5. Restart affected service:
   ```bash
   docker compose restart [service-name]
   ```

### Database Connection Exhaustion

**Symptoms:** "too many clients" errors, connection timeouts

1. Check connection count:
   ```bash
   docker compose exec postgres psql -U scanboy \
     -c "SELECT count(*), state FROM pg_stat_activity GROUP BY state;"
   ```

2. Kill idle connections:
   ```bash
   docker compose exec postgres psql -U scanboy \
     -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE state = 'idle' AND query_start < now() - interval '10 minutes';"
   ```

3. Restart API gateway to reset pool:
   ```bash
   docker compose restart api-gateway
   ```

### Elasticsearch Index Issues

**Symptoms:** Search failures, indexing errors

1. Check cluster health:
   ```bash
   docker compose exec elasticsearch curl -u elastic:$ELASTICSEARCH_PASSWORD localhost:9200/_cluster/health?pretty
   ```

2. Check index status:
   ```bash
   docker compose exec elasticsearch curl -u elastic:$ELASTICSEARCH_PASSWORD localhost:9200/_cat/indices?v
   ```

3. If red status, check unassigned shards:
   ```bash
   docker compose exec elasticsearch curl -u elastic:$ELASTICSEARCH_PASSWORD localhost:9200/_cat/shards?v | grep UNASSIGNED
   ```

### Queue Backup

**Symptoms:** Jobs stuck in queued state, growing queue depth

1. Check queue depths:
   ```bash
   docker compose exec redis redis-cli -a "$REDIS_PASSWORD" KEYS "bull:*:wait" | xargs -I{} docker compose exec redis redis-cli -a "$REDIS_PASSWORD" LLEN {}
   ```

2. Check for stuck workers:
   ```bash
   docker compose logs orchestrator --tail 100
   ```

3. Check for failed jobs:
   ```bash
   docker compose exec redis redis-cli -a "$REDIS_PASSWORD" LLEN bull:submission-intake:failed
   ```

4. Retry failed jobs (via API):
   ```bash
   curl -k -X POST https://localhost/api/v1/admin/queues/retry-failed \
     -H "Authorization: Bearer $TOKEN"
   ```

### Sandbox Escape Detection

**Symptoms:** Unexpected network traffic from sandbox containers, host process anomalies, unexpected containers running

**CRITICAL: This is a security incident.**

1. Immediately stop the suspect sandbox container:
   ```bash
   docker stop <container-name-or-id>
   ```

2. Check for unexpected containers (sandbox containers should be short-lived and named `scanboy-sandbox-*`):
   ```bash
   docker ps --filter "ancestor=scanboy-sandbox:latest"
   docker ps -a --format '{{.Names}} {{.Status}} {{.CreatedAt}}' | grep sandbox
   ```

3. Review docker.sock access (sandbox-manager and dynamic-analysis have read-only mounts):
   ```bash
   docker inspect scan-boy-sandbox-manager-1 --format '{{.Mounts}}' | grep docker.sock
   docker inspect scan-boy-dynamic-analysis-1 --format '{{.Mounts}}' | grep docker.sock
   ```

4. Kill all running sandbox containers immediately:
   ```bash
   docker ps --filter "ancestor=scanboy-sandbox:latest" -q | xargs -r docker stop
   docker ps --filter "ancestor=scanboy-sandbox:latest" -q | xargs -r docker rm -f
   ```

5. Capture forensic evidence:
   ```bash
   docker compose exec postgres pg_dump -U scanboy scanboy > incident-backup.sql
   ```

6. Review audit logs:
   ```bash
   docker compose exec postgres psql -U scanboy \
     -c "SELECT * FROM audit_log WHERE created_at > now() - interval '1 hour' ORDER BY created_at DESC;"
   ```

7. Engage incident response team.

### Disk Space Issues

**Symptoms:** Service crashes, write failures

1. Check disk usage:
   ```bash
   docker system df
   df -h
   ```

2. Clean old Docker images:
   ```bash
   docker image prune -a --filter "until=168h"
   ```

3. Clean old analysis artifacts (if not needed):
   ```bash
   docker compose exec minio mc rm --recursive --older-than 30d local/scanboy-artifacts/
   ```

## Routine Operations

### Daily

- Check service health endpoint
- Review failed analysis jobs
- Monitor queue depths
- Check disk space

### Weekly

- Review audit logs for anomalies
- Check Elasticsearch index sizes
- Review sandbox utilization
- Verify backup integrity
- Verify YARA rules refresh completed (vuln-feeds service refreshes weekly from 4 GitHub sources)

### Monthly

- Rotate TLS certificates (if approaching expiry)
- Review user access and disable inactive accounts
- Update threat intel API key quotas
- Check for service version updates

## Scaling

### Scaling Workers (Docker Compose)

Scale services by running multiple replicas:
```bash
docker compose up -d --scale static-analysis=3 --scale dynamic-analysis=2
```

To adjust resource limits, edit the service's section in `docker-compose.yml` and restart:
```bash
docker compose restart [service-name]
```

**Note:** All services run via Docker Compose on a single host. There is no Kubernetes or multi-node orchestration.

## Disaster Recovery

### Recovery Time Objective (RTO): 4 hours
### Recovery Point Objective (RPO): 1 hour

### Recovery Steps

1. Provision infrastructure (Docker Compose)
2. Restore PostgreSQL from backup
3. Restore MinIO artifacts from backup
4. Rebuild Elasticsearch indexes from PostgreSQL data
5. Verify service connectivity
6. Run health checks
7. Resume analysis pipeline
