# Victor Database Migration Strategy

## Recommendation: MIGRATE (Don't Recreate) ✅

**You are correct** - dropping and recreating the database is a bad idea for:
- ❌ Loses all conversation history
- ❌ Breaks auditability
- ❌ Requires full re-indexing (expensive)
- ❌ Not production best practice

---

## Investigation Commands

### Check Current Schema Status

```bash
# Check schema version
sqlite3 /Users/vijaysingh/code/proximaDB/.victor/project.db "SELECT * FROM schema_version;"

# Check graph_node schema
sqlite3 /Users/vijaysingh/code/proximaDB/.victor/project.db "PRAGMA table_info(graph_node);"

# Check for embeddings tables in project.db
sqlite3 /Users/vijaysingh/code/proximaDB/.victor/project.db ".tables" | grep -i embedding

# Check all tables
sqlite3 /Users/vijaysingh/code/proximaDB/.victor/project.db ".tables"
```

### Check What Needs Migration

```bash
# Find all migration files
find /Users/vijaysingh/code/codingagent -name "*migration*" -o -name "*migrate*"

# Check victor-coding installation
pip show victor-coding

# Check for pending migrations
python3 -c "
from victor.agent.conversation.migrations import MigrationRunner
from victor.config.settings import get_project_paths

paths = get_project_paths('/Users/vijaysingh/code/proximaDB')
runner = MigrationRunner(str(paths.project_db))
print(f'Current version: {runner.get_current_version()}')
print(f'Registered migrations: {len(runner.migrations)}')
for m in runner.migrations:
    print(f'  - {m.version}: {m.description}')
"
```

---

## Root Cause Analysis

The error `no such column: file` is likely in **cross-system queries**:

1. **SQLite (`project.db`)** - Has `graph_node` WITH `file` column ✅
2. **LanceDB (`embeddings.lance/`)** - Vector store
3. **ProximaDB** - New multi-model store
4. **Victor-coding plugin** - Semantic index builder

The issue is probably:
- Code trying to **join data between SQLite and LanceDB**
- The **victor-coding package** expecting a different schema
- A **missing migration** in the embeddings bridge

---

## Migration Strategy

### Option 1: Run Pending Migrations (Recommended)

```bash
# Backup first
cp /Users/vijaysingh/code/proximaDB/.victor/project.db \
   /Users/vijaysingh/code/proximaDB/.victor/project.db.backup.$(date +%Y%m%d_%H%M%S)

# Run migrations
python3 -c "
from victr.config.settings import get_project_paths
from victor.agent.conversation.store import ConversationStore

paths = get_project_paths('/Users/vijaysingh/code/proximaDB')
store = ConversationStore(db_path=paths.project_db)
print('Migrations complete')
"
```

### Option 2: Rebuild Only Embeddings (Conversation-safe)

```bash
# Keep conversation history, rebuild embeddings
rm -rf /Users/vijaysingh/code/proximaDB/.victor/embeddings/embeddings.lance

# Let victor rebuild embeddings on next search
# This preserves conversations but requires re-embedding
```

### Option 3: Check Victor-Coding Version

```bash
# Check if victor-coding needs update
pip show victor-coding

# Update if needed
pip install --upgrade victor-coding

# Check for schema fixes in changelog
```

---

## Diagnostic Queries

### Check if file column exists in all relevant tables

```bash
sqlite3 /Users/vijaysingh/code/proximaDB/.victor/project.db <<'SQL'
SELECT 'graph_node' as table_name, COUNT(*) as has_file FROM pragma_table_info('graph_node') WHERE name='file'
UNION ALL
SELECT 'graph_edge', COUNT(*) FROM pragma_table_info('graph_edge') WHERE name='file'
UNION ALL
SELECT 'messages', COUNT(*) FROM pragma_table_info('messages') WHERE name='file'
UNION ALL
SELECT 'files', COUNT(*) FROM pragma_table_info('files') WHERE name='file';
SQL
```

### Check for orphaned or missing tables

```bash
# Tables that should exist
sqlite3 /Users/vijaysingh/code/proximaDB/.victor/project.db "
SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;
"
```

---

## Testing Migration

### Test on Copy First

```bash
# Create test copy
TEST_DB="/tmp/test_proxima_$(date +%s).db"
sqlite3 "$TEST_DB" ".read /dev/stdin" <<'SQL'
.dump
SQL

# Test migration on copy
python3 -c "
from victor.agent.conversation.store import ConversationStore
store = ConversationStore(db_path='$TEST_DB')
print('Test migration successful')
"

# If successful, run on production
```

---

## Monitoring Migration

### Watch for These Errors

1. ✅ **"no such column: file"** - Schema mismatch
2. ✅ **"no such table: embeddings"** - Missing table
3. ✅ **"database is locked"** - Concurrent access
4. ✅ **"OperationalError"** - Migration failure

### Success Indicators

- ✅ Schema version updated
- ✅ All tables present
- ✅ No errors in logs
- ✅ code_search works without fallback

---

## Post-Migration Verification

```bash
# 1. Check schema version
sqlite3 /Users/vijaysingh/code/proximaDB/.victor/project.db "SELECT * FROM schema_version ORDER BY version DESC LIMIT 1;"

# 2. Verify tables exist
sqlite3 /Users/vijaysingh/code/proximaDB/.victor/project.db ".tables" | grep -E "graph_node|graph_edge|embeddings"

# 3. Test code_search
cd /Users/vijaysingh/code/proximaDB
victor chat -p . <<< "code_search(query='test', mode='text', k=5)"

# 4. Check for errors
tail -50 ~/.victor/logs/victor.log | grep -i "error\|warning"
```

---

## Rollback Plan

If migration fails:

```bash
# Restore from backup
cp /Users/vijaysingh/code/proximaDB/.victor/project.db.backup.YYYYMMDD_HHMMSS \
   /Users/vijaysingh/code/proximaDB/.victor/project.db

# Or restore entire .victor directory
rm -rf /Users/vijaysingh/code/proximaDB/.victor
cp -r /path/to/backup/.victor /Users/vijaysingh/code/proximaDB/.victor
```

---

## Summary

| Action | Risk | Recommendation |
|--------|------|----------------|
| **Migrate database** | Low | ✅ **DO THIS** |
| **Rebuild embeddings only** | Low | ✅ Safe fallback |
| **Drop and recreate** | High | ❌ **AVOID** |
| **Update victor-coding** | Low | ✅ Worth trying |

**Best approach**:
1. ✅ Backup current database
2. ✅ Run pending migrations
3. ✅ If errors, rebuild embeddings only
4. ✅ Never drop project.db unless absolutely necessary
