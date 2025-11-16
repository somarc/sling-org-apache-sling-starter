# Running Sling Locally Without Docker

This guide shows how to run Sling Starter locally without Docker, which is useful when Docker daemon is problematic or you prefer direct Java execution.

## Prerequisites

1. **Build Sling Starter:**
   ```bash
   cd sling-org-apache-sling-starter
   mvn clean package -DskipTests
   ```

2. **Start Validators** (if using Blockchain AEM):
   ```bash
   cd blockchain-aem-infra/scripts/local-development
   ./run-validators-local.sh start
   ```

## Quick Start

### Using Helper Script (Recommended)

```bash
cd sling-org-apache-sling-starter
./scripts/run-sling-local.sh
```

**Defaults:**
- Port: `4502` (AEM author port)
- Global Store URL: `http://localhost:8091` (first validator)

**Custom Port/URL:**
```bash
./scripts/run-sling-local.sh 4502 http://localhost:8091
```

### Manual Launch

```bash
cd sling-org-apache-sling-starter

# Set environment variables
export OAK_GLOBAL_STORE_URL=http://localhost:8091
export JAVA_OPTS="-Xmx2g -XX:MaxMetaspaceSize=512m"

# Launch with oak_blockchain feature
target/dependency/org.apache.sling.feature.launcher/bin/launcher \
  -f target/slingfeature-tmp/feature-oak_blockchain.json \
  -Dorg.osgi.service.http.port=4502
```

## Configuration

### Port Configuration

The port is set via system property:
```bash
-Dorg.osgi.service.http.port=4502
```

### Global Store URL

Set via environment variable:
```bash
export OAK_GLOBAL_STORE_URL=http://localhost:8091
```

This is read by `HttpPersistenceService` configuration in `oak_persistence_blockchain.json`.

### Work Directory

Sling stores its repository data in `./launcher` directory by default. To use a different location:

```bash
export SLING_WORK_DIR=/path/to/custom/launcher
./scripts/run-sling-local.sh
```

**Note:** `mvn clean` deletes the `launcher` directory, so consider using a location outside the project directory for persistence.

## Access Points

Once running, access Sling at:
- **Main:** http://localhost:4502
- **Composum Browser:** http://localhost:4502/bin/browser.html
- **Felix Console:** http://localhost:4502/system/console
  - Username: `admin`
  - Password: `admin`

## Log Files

Sling logs are written to multiple locations depending on how you start it:

### When Running Directly (`./scripts/run-sling-local.sh`)

**Terminal Output:**
- All logs go to the terminal (stdout/stderr) since it runs in foreground

**Sling Log Files** (in `launcher/logs/` directory):
- `error.log` - Main error log (all log levels)
- `access.log` - HTTP access log
- `request.log` - Request log
- `oak-composite.log` - Composite NodeStore logs (DEBUG)
- `oak-segment.log` - Segment store logs (DEBUG)
- `oak-http.log` - HTTP segment transfer logs (DEBUG)
- `oak-agentic.log` - Agentic/AI logs (INFO)

**Location:** `sling-org-apache-sling-starter/launcher/logs/`

### When Running via `build-and-run-local.sh`

**Combined Log File:**
- `$HOME/oak-chain/logs/sling-author.log` - All output (stdout + stderr)

**Sling Log Files** (same as above):
- `launcher/logs/` - Individual log files per component

**View logs:**
```bash
# Combined log (if using build-and-run-local.sh)
tail -f $HOME/oak-chain/logs/sling-author.log

# Individual Sling logs
tail -f sling-org-apache-sling-starter/launcher/logs/error.log
tail -f sling-org-apache-sling-starter/launcher/logs/oak-http.log
tail -f sling-org-apache-sling-starter/launcher/logs/oak-composite.log
```

## Troubleshooting

### "Feature file not found"

**Error:**
```
❌ Error: Feature file not found: target/slingfeature-tmp/feature-oak_blockchain.json
```

**Solution:**
```bash
mvn clean package -DskipTests
```

### "Cannot reach global store"

**Warning:**
```
⚠️  Warning: Cannot reach global store at http://localhost:8091
```

**Solution:**
1. Start validators:
   ```bash
   cd blockchain-aem-infra/scripts/local-development
   ./run-validators-local.sh start
   ```

2. Verify validators are running:
   ```bash
   curl http://localhost:8091/health
   ```

### Port Already in Use

**Error:**
```
Address already in use: BindException
```

**Solution:**
1. Use a different port:
   ```bash
   ./scripts/run-sling-local.sh 4503
   ```

2. Or find and kill the process using port 4502:
   ```bash
   lsof -ti :4502 | xargs kill -9
   ```

### InvalidFileStoreVersionException

**Error:**
```
InvalidFileStoreVersionException: Using oak-segment-tar, but oak-segment should be used
```

**Solution:**
- Ensure you're using `feature-oak_blockchain.json` (not `feature-oak_tar.json`)
- The helper script automatically uses the correct feature file

## Advantages Over Docker

1. **No Docker daemon required** - runs directly on your machine
2. **Faster startup** - no container overhead
3. **Easier debugging** - direct Java process, easier to attach debugger
4. **Simpler logs** - output directly to terminal
5. **Better IDE integration** - can debug directly from IDE

## Disadvantages

1. **Platform-specific** - requires Java installed locally
2. **Manual cleanup** - need to manually stop processes
3. **Port conflicts** - need to manage ports manually
4. **No isolation** - runs in your local environment

## Next Steps

- See [README.md](../README.md) for more Sling Starter options
- See `blockchain-aem-infra/scripts/local-development/` for validator scripts
- See `Blockchain-AEM/03-development/DOCKER-SETUP.md` for Docker-based setup

