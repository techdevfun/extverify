#!/bin/bash
# Pin-then-verify workflow: trust a version once, catch silent repackaging.
# 1. Verify first (decide if you trust the listing at all):
node dist/cli.js verify esbenp.prettier-vscode
# 2. Pin the version you approved:
node dist/cli.js pin esbenp.prettier-vscode@12.4.0
# 3. Later, verify again — a repackaged same-version now DENYs:
node dist/cli.js verify esbenp.prettier-vscode@12.4.0
