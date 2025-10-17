#!/bin/bash

set -e

REPO="boringcache/cli"

echo "=== GitHub Repository Cleanup Script ==="
echo "Repository: $REPO"
echo ""

# Function to delete all releases
delete_releases() {
    echo "Fetching all releases..."
    releases=$(gh release list --repo $REPO --limit 1000 | cut -f3)
    
    if [ -z "$releases" ]; then
        echo "No releases found."
        return
    fi
    
    count=$(echo "$releases" | wc -l | tr -d ' ')
    echo "Found $count releases to delete."
    echo ""
    
    for tag in $releases; do
        echo "Deleting release: $tag"
        gh release delete "$tag" --repo $REPO --yes
    done
    
    echo "✓ All releases deleted."
    echo ""
}

# Function to delete all workflow runs
delete_workflow_runs() {
    echo "Fetching all workflow runs..."
    
    # Get all run IDs
    run_ids=$(gh run list --repo $REPO --limit 1000 --json databaseId -q '.[].databaseId')
    
    if [ -z "$run_ids" ]; then
        echo "No workflow runs found."
        return
    fi
    
    count=$(echo "$run_ids" | wc -l | tr -d ' ')
    echo "Found $count workflow runs to delete."
    echo ""
    
    # Delete each run
    for run_id in $run_ids; do
        echo "Deleting workflow run: $run_id"
        gh run delete $run_id --repo $REPO || echo "  (already deleted or error)"
    done
    
    echo "✓ All workflow runs deleted."
    echo ""
}

# Function to delete all git tags (optional)
delete_tags() {
    echo "Fetching all tags..."
    tags=$(git tag -l)
    
    if [ -z "$tags" ]; then
        echo "No tags found."
        return
    fi
    
    count=$(echo "$tags" | wc -l | tr -d ' ')
    echo "Found $count tags to delete."
    echo ""
    
    echo "Deleting local tags..."
    git tag -l | xargs git tag -d
    
    echo "Deleting remote tags..."
    for tag in $tags; do
        echo "Deleting remote tag: $tag"
        git push --delete origin "$tag" || echo "  (already deleted or error)"
    done
    
    echo "✓ All tags deleted."
    echo ""
}

# Main menu
echo "What would you like to clean up?"
echo "1. Delete all releases"
echo "2. Delete all workflow runs"
echo "3. Delete all git tags"
echo "4. Delete everything (releases, runs, and tags)"
echo "5. Exit"
echo ""
read -p "Enter your choice (1-5): " choice

case $choice in
    1)
        echo ""
        read -p "Are you sure you want to delete ALL releases? (yes/no): " confirm
        if [ "$confirm" = "yes" ]; then
            delete_releases
        else
            echo "Cancelled."
        fi
        ;;
    2)
        echo ""
        read -p "Are you sure you want to delete ALL workflow runs? (yes/no): " confirm
        if [ "$confirm" = "yes" ]; then
            delete_workflow_runs
        else
            echo "Cancelled."
        fi
        ;;
    3)
        echo ""
        read -p "Are you sure you want to delete ALL git tags? (yes/no): " confirm
        if [ "$confirm" = "yes" ]; then
            delete_tags
        else
            echo "Cancelled."
        fi
        ;;
    4)
        echo ""
        echo "WARNING: This will delete ALL releases, workflow runs, and git tags!"
        read -p "Are you absolutely sure? Type 'DELETE ALL' to confirm: " confirm
        if [ "$confirm" = "DELETE ALL" ]; then
            delete_releases
            delete_workflow_runs
            delete_tags
        else
            echo "Cancelled."
        fi
        ;;
    5)
        echo "Exiting..."
        exit 0
        ;;
    *)
        echo "Invalid choice."
        exit 1
        ;;
esac

echo ""
echo "=== Cleanup Complete ==="