# Local Docker Build

Build Clawgress ISO locally using Docker (vyos-build container).

## Prerequisites

```bash
# Install Docker
sudo apt-get install docker.io

# Add user to docker group (logout/login required)
sudo usermod -aG docker $USER
```

## Quick Start

```bash
# Clone and setup
git clone https://github.com/bufordtjustice2918/clawgress.git
cd clawgress

# Build ISO (30-60 minutes)
./scripts/build-local.sh

# Test ISO
./scripts/test-iso.sh
```

## How It Works

The Docker build uses the **official VyOS build container** with our modifications:

1. **Container**: `vyos/vyos-build:current` (Debian-based with build tools)
2. **Modifications** (already in `vyos-build-modifications/`):
   - `build.conf` — Version set to `1.5.0-clawgress`
   - `50-clawgress-bind9.chroot` — Enables bind9 on first boot
   - `config/clawgress/policy.json` — Default empty policy
3. **Mount**: Your local `vyos-build` directory is mounted into the container
4. **Output**: ISO appears in `/home/kavan/.openclaw/clawgress-iso/`

## No Dockerfile Changes Needed

The VyOS Docker image works as-is because:
- Our changes are in the **build directory** (hooks, configs)
- The container just runs `build-vyos-image` which reads those files
- No custom packages need to be installed in the container

## Troubleshooting

### Permission denied
```bash
sudo usermod -aG docker $USER
# Log out and back in
```

### ISO not created
Check logs in: `/home/kavan/.openclaw/vyos/vyos-build/build/`

### Out of disk space
Build needs ~10GB free. Check: `df -h`

## vs GitHub Actions

| | Local Docker | GitHub Actions |
|--|--------------|----------------|
| **Speed** | Same | Same |
| **Convenience** | Run anytime | Triggered by schedule/tags |
| **Artifacts** | Local ISO | Download from GitHub |
| **Smoke test** | Manual QEMU | Automated in workflow |

Use local for development, GitHub for releases.
