# Victor Tool Errors: Analysis and Fixes

## Issue Summary

Two separate "no such column: file" errors are occurring:

1. **graph tool** (mode='overview') - Expected behavior, error handling working correctly
2. **code_search tool** (semantic index build) - Code bug requiring fix

---

## Error 1: Graph Tool - `mode='overview'` and `mode='stats'`

### Status: ✅ **NOT A BUG** - Error handling working as designed

### What's Happening

The graph tool is being called by the LLM with `mode='overview'` or `mode='stats'`. The tool executes predefined SQL queries and, if an error occurs, provides helpful context about available columns.

### Evidence

From `victor/tools/graph_tool.py:1592-1601`:
```python
# Add helpful context for common column errors
available_columns = "node_id, type, name, file, line, end_line, lang, signature, docstring, parent_id, embedding_ref, metadata"
if "no such column" in error_str.lower() or "does not exist" in error_str.lower():
    return {
        "error": f"SQL execution failed: {error_str}\n\nAvailable columns in graph_node: {available_columns}\nAvailable columns in graph_edge: src, dst, type, file, line",
        "success": False,
        "available_columns": {
            "graph_node": available_columns,
            "graph_edge": "src, dst, type, file, line",
        },
    }
```

### Schema Verification

The `graph_node` table DOES have a "file" column:
```sql
PRAGMA table_info(graph_node);
-- 3|file|TEXT|1||0  ← Column exists!
```

### Conclusion

- **LLM is calling the tool correctly**
- **Error handling is providing helpful feedback**
- **No fix needed** - this is expected behavior for invalid queries

---

## Error 2: Code Search Tool - Semantic Index Build

### Status: ❌ **CODE BUG** - Schema mismatch requiring fix

### What's Happening

When `code_search` tries to build a semantic index, it queries a SQLite table expecting a "file" column that doesn't exist.

### Error Log

```
2026-05-10 11:23:49,018 - WARNING - [code_search] Semantic index build failed
(type=OperationalError, error=no such column: file), falling back to literal search.
Root cause: OperationalError: no such column: file
```

### Root Cause

The code_search_tool is using embeddings stored in **LanceDB** format:
```
.victor/embeddings/embeddings.lance/
```

But somewhere in the semantic index build process, it's trying to query a **SQLite table** that has a different schema than expected.

### Investigation Needed

1. Find where code_search_tool creates/queries SQLite embeddings table
2. Check if there's a schema migration that needs to be run
3. Verify the expected vs actual schema

### Possible Fixes

#### Option 1: Add schema migration
```python
# In code_search_tool.py or related migration file
conn.execute("""
    ALTER TABLE embeddings ADD COLUMN file TEXT
""")
```

#### Option 2: Fix the query
```python
# Change query to use correct column name
# e.g., if column is named "path" instead of "file"
SELECT path, ... FROM embeddings
```

#### Option 3: Handle missing columns gracefully
```python
# Check schema before querying
columns = [row[1] for row in conn.execute("PRAGMA table_info(embeddings)").fetchall()]
if "file" not in columns:
    # Use alternative column or skip this query
    pass
```

---

## Action Items

### For Graph Tool (Error 1)
- ✅ **No action needed** - Working as designed

### For Code Search Tool (Error 2)
- ❌ **Fix needed** - Schema mismatch

1. **Investigate**:
   ```bash
   # Find where embeddings schema is defined
   grep -rn "CREATE TABLE.*embeddings" victor/
   grep -rn "ALTER TABLE.*embeddings" victor/
   ```

2. **Check existing migrations**:
   ```bash
   # Look for migration files
   find victor/ -name "*migration*" -o -name "*migrate*"
   ```

3. **Add migration or fix query**:
   - Ensure embeddings table has "file" column
   - OR update code to use correct column name
   - OR add schema check before querying

---

## Testing

### Test Graph Tool
```bash
# These calls work correctly and provide helpful errors when SQL is wrong
victor chat -p proximaDB
> graph(mode="overview", path=".", top_k=10)
> graph(mode="stats", path=".", top_k=10)
```

### Test Code Search
```bash
# This should not fail with "no such column: file"
victor chat -p proximaDB
> code_search(query="StorageError", mode="text")
```

---

## Files to Check

1. `victor/tools/code_search_tool.py` - Main tool implementation
2. `victor/framework/search/codebase_embedding_bridge.py` - Embeddings management
3. `victor/storage/vector_stores/models.py` - Vector store models
4. `victor/storage/vector_stores/proximadb_migration.py` - Migrations

---

## Summary

| Error | Type | Fix Needed |
|-------|------|------------|
| graph mode='overview' | Error handling | ✅ No - Working as designed |
| code_search semantic index | Schema mismatch | ❌ Yes - Database migration or query fix |

The graph tool is **fine** - the LLM is using it correctly and error handling provides helpful context.

The code_search tool has a **real bug** that needs fixing in the code/database schema.
