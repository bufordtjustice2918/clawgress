# Clawgress CI/CD Plan (MVP)

## Goals
- Build images on every change
- Run automated smoke tests (RPZ, policy apply, bind9, firewall)
- Publish artifacts (ISO/OVA/QCOW2)
- Promote through staging → production with approval gates

## Pipeline Stages

### 1) Build (CI)
**Trigger (recommended):** manual dispatch or scheduled (nightly) builds
**Optional:** build on merge to `main` (not every push)
**Actions:**
- Build ISO (required)
- Build OVA/QCOW2 (optional)
- Upload artifacts + checksums

### 2) Automated Smoke Tests
**Run in QEMU** against the built ISO:
- Boot to login prompt
- Verify bind9 running (`systemctl is-active bind9`)
- Apply policy.json → RPZ generation
- Allowlist/denylist DNS behavior (positive + negative queries)
- Verify logging is produced
- Verify firewall rules exist

### 3) Publish Artifacts
- GitHub Release + SHA256 checksums
- (Optional) push AMI/QCOW2 to cloud registry

### 4) Staging Deployment
- Auto‑update staging Clawgress
- Run live smoke checks (health + DNS allow/deny)
- Capture logs/metrics

### 5) Production Promotion
- Manual approval gate
- Rollout with canary option

## Suggested GitHub Actions Workflow
- `build-images.yml`: build + upload artifacts
- `smoke-tests.yml`: QEMU boot + tests
- `release.yml`: create release + publish assets

## Notes
- Prefer self‑hosted runners for stable builds
- Store secrets in GitHub Actions (for releases and cloud uploads)
- Consider Packer for AMI/GCP/Azure image publishing
