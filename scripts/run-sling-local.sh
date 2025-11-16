#!/bin/bash
# Run Sling Starter locally without Docker
# Usage: ./scripts/run-sling-local.sh [port] [global-store-url]
# Example: ./scripts/run-sling-local.sh 4502 http://localhost:8091
#
# Defaults:
#   Port: 4502 (AEM author port)
#   Global Store URL: http://localhost:8091 (first validator)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

# Configuration
SLING_PORT="${1:-4502}"
GLOBAL_STORE_URL="${2:-http://localhost:8091}"
WORK_DIR="${SLING_WORK_DIR:-$PROJECT_ROOT/launcher}"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🚀 Starting Sling Starter Locally"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Configuration:"
echo "  Port: $SLING_PORT"
echo "  Global Store URL: $GLOBAL_STORE_URL"
echo "  Work Directory: $WORK_DIR"
echo ""

# Check if project is built
if [ ! -d "target/dependency/org.apache.sling.feature.launcher" ]; then
    echo "❌ Error: Sling Starter not built yet"
    echo "   Run: mvn clean package -DskipTests"
    exit 1
fi

# Check for oak_blockchain feature file
FEATURE_FILE="target/slingfeature-tmp/feature-oak_blockchain.json"
if [ ! -f "$FEATURE_FILE" ]; then
    echo "❌ Error: Feature file not found: $FEATURE_FILE"
    echo "   Run: mvn clean package -DskipTests"
    echo "   This generates the feature files in target/slingfeature-tmp/"
    exit 1
fi

# Check if validators are running (optional check)
if ! curl -s "$GLOBAL_STORE_URL/health" > /dev/null 2>&1; then
    echo "⚠️  Warning: Cannot reach global store at $GLOBAL_STORE_URL"
    echo "   Make sure validators are running:"
    echo "   cd blockchain-aem-infra/scripts/local-development"
    echo "   ./run-validators-local.sh start"
    echo ""
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Create work directory
mkdir -p "$WORK_DIR"

# Set environment variables
export OAK_GLOBAL_STORE_URL="$GLOBAL_STORE_URL"

# Set Java options - use JAVA_TOOL_OPTIONS which Java reads automatically
# This is safer than JAVA_OPTS which the launcher might not handle correctly
if [ -z "$JAVA_TOOL_OPTIONS" ]; then
    export JAVA_TOOL_OPTIONS="-Xmx2g -XX:MaxMetaspaceSize=512m"
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📋 Launching Sling..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Feature: $FEATURE_FILE"
echo "Port: $SLING_PORT"
echo "Global Store: $GLOBAL_STORE_URL"
echo "Work Dir: $WORK_DIR"
echo ""
echo "Access Sling at: http://localhost:$SLING_PORT"
echo "Press Ctrl+C to stop"
echo ""

# Launch Sling
# Note: Port is set via framework property (-D requires space: -D key=value)
# Work directory defaults to ./launcher
exec target/dependency/org.apache.sling.feature.launcher/bin/launcher \
    -f "$FEATURE_FILE" \
    -D "org.osgi.service.http.port=$SLING_PORT"

