#!/bin/bash

# Non-interactive script to delete all releases and workflow runs
# Use with caution!

set -e

REPO="boringcache/cli"

echo "=== Cleaning up all GitHub releases and workflow runs ==="
echo "Repository: $REPO"
echo ""

# Delete all releases
echo "Deleting all releases..."
gh release list --repo $REPO --limit 1000 | cut -f3 | while read -r tag; do
    if [ -n "$tag" ]; then
        echo "  Deleting release: $tag"
        gh release delete "$tag" --repo $REPO --yes
    fi
done
echo "✓ Releases deleted"
echo ""

# Delete all workflow runs
echo "Deleting all workflow runs..."
gh run list --repo $REPO --limit 1000 --json databaseId -q '.[].databaseId' | while read -r run_id; do
    if [ -n "$run_id" ]; then
        echo "  Deleting run: $run_id"
        gh run delete $run_id --repo $REPO || true
    fi
done
echo "✓ Workflow runs deleted"
echo ""

echo "=== Cleanup complete ==="