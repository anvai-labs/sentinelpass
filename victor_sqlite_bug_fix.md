# Victor "no such column: file" Bug - ROOT CAUSE FOUND

**Date**: 2026-05-10
**File**: `/Users/vijaysingh/code/codingagent/victor/storage/graph/sqlite_store.py`
**Lines**: 294-299, 330, 336
**Severity**: 🔴 CRITICAL - Blocks all file editing operations

---

## Root Cause

The `sqlite_store.py` file contains SQL queries that reference a non-existent 'file' column in the `graph_edge` table.

### Schema Reality

**graph_edge table** (ACTUAL schema):
```sql
CREATE TABLE graph_edge (
    src TEXT,
    dst TEXT,
    type TEXT,
    weight REAL,
    metadata TEXT
    -- NO 'file' column!
);
```

**graph_node table** (HAS file column):
```sql
CREATE TABLE graph_node (
    node_id TEXT,
    type TEXT,
    name TEXT,
    file TEXT,  -- ✅ This table HAS 'file'
    line INTEGER,
    ...
);
```

---

## Bug Locations

### Bug 1: INSERT Edge with File Column (Line 294-299)

```python
def _upsert_edges_rows(
    self,
    conn: sqlite3.Connection,
    rows: List[tuple[Any, ...]],
) -> None:
    """Write edge rows using the provided connection."""
    conn.executemany(
        f"""
        INSERT INTO {_EDGE_TABLE}(src, dst, type, weight, file, metadata)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(src, dst, type) DO UPDATE SET
            weight=excluded.weight,
            file=excluded.file,  # ❌ BUG: column doesn't exist
            metadata=excluded.metadata
        """,
        rows,
    )
```

**Error**:
```
sqlite3.OperationalError: no such column: file
```

**Fix Required**:
1. Remove 'file' from INSERT columns
2. Remove 'file' from UPDATE SET
3. Remove 'file' from VALUES tuple (5 params → 4 params)

---

### Bug 2: DELETE Edges by File (Line 330)

```python
def _delete_by_file_conn(self, conn: sqlite3.Connection, file: str) -> None:
    """Delete all nodes, edges, and mtimes for a specific file.

    Uses the file column on edges for efficient deletion (single query).
    Falls back to node-based deletion for edges without file metadata.
    """
    file_variants = self._file_path_variants(file)
    file_placeholders = ",".join("?" for _ in file_variants)

    # Delete edges with file metadata directly (efficient single query)
    conn.execute(
        f"DELETE FROM {_EDGE_TABLE} WHERE file IN ({file_placeholders})",  # ❌ BUG
        file_variants,
    )

    # For edges without file metadata, delete via node lookup (fallback)
    cur = conn.execute(
        f"SELECT node_id FROM {_NODE_TABLE} WHERE file IN ({file_placeholders})",
        file_variants,
    )
    node_ids = [row[0] for row in cur.fetchall()]

    if node_ids:
        placeholders = ",".join("?" for _ in node_ids)
        conn.execute(f"DELETE FROM {_EDGE_TABLE} WHERE src IN ({placeholders})", node_ids)
        conn.execute(f"DELETE FROM {_EDGE_TABLE} WHERE dst IN ({placeholders})", node_ids)
        ...
```

**Problems**:
1. First DELETE query fails (graph_edge has no 'file' column)
2. Comment says "Uses the file column on edges" but that's false
3. The "fallback" code is actually the CORRECT approach

**Fix Required**:
1. Remove the first DELETE query (lines 329-332)
2. Keep only the node-based deletion (the "fallback")
3. Update docstring to reflect reality

---

## Why Edit Tool Fails

### Execution Flow

1. **User calls edit tool**: `edit(ops=[...])`
2. **File is modified**: `src/lib.rs` is changed on disk
3. **File watcher triggers**: `FileWatcherService` detects change
4. **GraphManager notified**: Marks graph as stale, schedules refresh
5. **Background refresh**: Tries to update graph database
6. **SQL query fails**: `DELETE FROM graph_edge WHERE file IN (...)`
7. **SQLite error**: `no such column: file`
8. **Tool execution fails**: Error wrapped as TOOL_EXECUTION error
9. **Edit appears broken**: User sees "no such column: file"

### Why It's Silent

The error happens in the **background refresh**, not during the tool execution itself. The tool succeeds in modifying the file, but the post-processing fails.

---

## Impact Assessment

### Affected Operations

| Operation | Impact | Frequency |
|-----------|--------|-----------|
| **Edit tool** | ❌ Blocked | Every edit |
| **Write tool** | ❌ Blocked | Every write |
| **File indexing** | ❌ Blocked | On file change |
| **Graph refresh** | ❌ Blocked | Automatic triggers |
| **Delete by file** | ❌ Blocked | Cleanup operations |

### User Experience

1. Edit tool fails with cryptic error
2. Write tool fails with same error
3. No files can be modified through Victor
4. Development workflow completely blocked

---

## Fix Strategy

### Fix 1: Remove 'file' from Edge INSERT (Line 294-299)

**Before**:
```python
conn.executemany(
    f"""
    INSERT INTO {_EDGE_TABLE}(src, dst, type, weight, file, metadata)
    VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(src, dst, type) DO UPDATE SET
        weight=excluded.weight,
        file=excluded.file,
        metadata=excluded.metadata
    """,
    rows,  # rows has 6 elements including file
)
```

**After**:
```python
conn.executemany(
    f"""
    INSERT INTO {_EDGE_TABLE}(src, dst, type, weight, metadata)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(src, dst, type) DO UPDATE SET
        weight=excluded.weight,
        metadata=excluded.metadata
    """,
    rows,  # rows must have 5 elements (NO file)
)
```

**Required Changes**:
1. ✅ Remove 'file' from INSERT column list
2. ✅ Remove 'file' from VALUES list (5 params → 4 params)
3. ✅ Remove 'file' from UPDATE SET clause
4. ✅ Update code that builds edge rows to not include file

---

### Fix 2: Fix DELETE by File (Line 319-353)

**Before**:
```python
def _delete_by_file_conn(self, conn: sqlite3.Connection, file: str) -> None:
    """Delete all nodes, edges, and mtimes for a specific file.

    Uses the file column on edges for efficient deletion (single query).
    Falls back to node-based deletion for edges without file metadata.
    """
    file_variants = self._file_path_variants(file)
    file_placeholders = ",".join("?" for _ in file_variants)

    # Delete edges with file metadata directly (efficient single query)
    conn.execute(
        f"DELETE FROM {_EDGE_TABLE} WHERE file IN ({file_placeholders})",
        file_variants,
    )

    # For edges without file metadata, delete via node lookup (fallback)
    ...
```

**After**:
```python
def _delete_by_file_conn(self, conn: sqlite3.Connection, file: str) -> None:
    """Delete all nodes, edges, and mtimes for a specific file.

    Since graph_edge table doesn't have a file column, we delete edges
    by looking up nodes in the file and removing all edges connected
    to those nodes.
    """
    file_variants = self._file_path_variants(file)
    file_placeholders = ",".join("?" for _ in file_variants)

    # Get all node_ids for nodes in this file
    cur = conn.execute(
        f"SELECT node_id FROM {_NODE_TABLE} WHERE file IN ({file_placeholders})",
        file_variants,
    )
    node_ids = [row[0] for row in cur.fetchall()]

    if node_ids:
        placeholders = ",".join("?" for _ in node_ids)
        # Delete all edges connected to these nodes
        conn.execute(f"DELETE FROM {_EDGE_TABLE} WHERE src IN ({placeholders})", node_ids)
        conn.execute(f"DELETE FROM {_EDGE_TABLE} WHERE dst IN ({placeholders})", node_ids)
        # Delete the nodes themselves
        conn.execute(
            f"DELETE FROM {_NODE_TABLE} WHERE node_id IN ({placeholders})",
            node_ids,
        )

    # Also delete from mtime table
    conn.execute(
        f"DELETE FROM {_MTIME_TABLE} WHERE file IN ({file_placeholders})",
        file_variants,
    )
```

**Required Changes**:
1. ✅ Remove the broken DELETE query (lines 329-332)
2. ✅ Update docstring to reflect actual behavior
3. ✅ Keep the node-based deletion (it's correct!)

---

## Testing Plan

### Test 1: Edit Tool After Fix

```python
# Before fix: Fails with "no such column: file"
edit(ops=[{
    "type": "replace",
    "path": "src/lib.rs",
    "old_str": "old_code",
    "new_str": "new_code"
}])

# After fix: Should succeed
```

### Test 2: Indexing After Fix

```python
# Trigger re-indexing by modifying a file
# Should succeed without "no such column: file" error
```

### Test 3: Graph Deletion After Fix

```python
# Delete a file from graph
# Should use node-based deletion (correct approach)
```

---

## Related Issues

### Previously Fixed

- ✅ Graph tool error message (commit 50b3d46a5)
  - Fixed misleading error message about available columns

### Still Broken

- ⚠️ code_search semantic index (separate issue in victor-coding)
  - Different "no such column: file" error in embeddings table

---

## Summary

**Root Cause**: `sqlite_store.py` references non-existent 'file' column in `graph_edge` table

**Impact**: Blocks all file editing operations in Victor

**Fix Required**:
1. Remove 'file' from edge INSERT/UPDATE queries
2. Use node-based deletion for edges (already implemented as fallback)
3. Update any code that builds edge rows to not include file

**Priority**: 🔴 CRITICAL - This is a complete blocker for file operations

**Estimated Fix Time**: 30-60 minutes

---

**Next Steps**:
1. Apply Fix 1 (remove file from INSERT)
2. Apply Fix 2 (fix DELETE by file)
3. Test edit tool
4. Test indexing
5. Commit and push
