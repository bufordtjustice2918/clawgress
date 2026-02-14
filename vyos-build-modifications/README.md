# Clawgress Build Configuration

This directory contains modifications to vyos-build for Clawgress.

## Files Added/Modified

### build.conf
Version configuration for Clawgress 1.5.0

### data/live-build-config/hooks/live/50-clawgress-bind9.chroot
Enables bind9 service on first boot and creates /config/clawgress directory

### data/live-build-config/includes.chroot/config/clawgress/policy.json
Default empty policy.json

## How to Use

These files should be applied to a fork of vyos-build or maintained as patches:

```bash
# Option 1: Fork vyos-build and apply these changes
git clone https://github.com/bufordtjustice2918/vyos-build.git
cd vyos-build
git checkout -b clawgress-1.5.0
# Copy these files into place
git add .
git commit -m "Clawgress 1.5.0 build configuration"
```

## Build Command

```bash
sudo ./build-vyos-image \
  --build-by github-actions \
  --architecture amd64 \
  --build-type release \
  --version 1.5.0-clawgress \
  generic
```
