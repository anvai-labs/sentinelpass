# SQLite Database Lock Fix - Victor Agent

## Issue Summary

The victor agent conversation store is experiencing `sqlite3.OperationalError: database is locked` errors under concurrent load. This occurs when multiple async tasks simultaneously try to write to the SQLite database.

### Root Cause
1. **SQLite limitation**: Only allows ONE writer at a time, even with WAL mode
2. **No serialization**: Multiple `asyncio.to_thread()` calls compete for the write lock
3. **Timeout too short**: 30-second timeout insufficient under heavy concurrent load
4. **Connection overhead**: Each write creates a new connection, increasing contention

### Error Stack Trace
```
sqlite3.OperationalError: database is locked
  File "victor/agent/conversation/store.py", line 2431, in _persist_message
    conn.execute(...)
  File "victor/agent/services/chat_service.py", line 1444, in <lambda>
    memory_manager.add_message(**add_kwargs)
```

---

## Quick Fix (1 minute)

**File**: `/Users/vijaysingh/code/codingagent/victor/agent/conversation/store.py`

**Line 273**: Increase timeout from 30 to 120 seconds:

```python
# Before:
conn = sqlite3.connect(self.db_path, timeout=30.0)

# After:
conn = sqlite3.connect(self.db_path, timeout=120.0)
conn.execute("PRAGMA busy_timeout = 120000")  # Add this line
```

---

## Recommended Fix (10 minutes)

### Step 1: Add write locks to `__init__` method

**Location**: Line 256 (after `self._provider_ids: Dict[str, int] = {}`)

**Add**:
```python
# Write serialization locks to prevent concurrent database lock errors
import asyncio
import threading
self._write_lock_async = asyncio.Lock()  # For async operations
self._write_lock_sync = threading.Lock()  # For sync operations
```

### Step 2: Update `_persist_message` method

**Location**: Line 2400-2450

**Wrap the database write in a lock**:
```python
def _persist_message(self, session_id: str, message):
    """Persist message to database.

    IMPORTANT: Uses self._write_lock_sync to serialize all write
    operations and prevent "database is locked" errors from concurrent access.
    """
    # ... [existing content truncation logic] ...

    # Sanitize metadata for JSON serialization
    meta = self._sanitize_metadata_for_json(meta)

    # CRITICAL: Use lock to serialize all write operations
    # This prevents "database is locked" errors from concurrent writes
    with self._write_lock_sync:
        # Use helper method for connection with proper timeout and WAL mode
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO messages
                (id, session_id, role, content, timestamp, token_count,
                 priority, tool_name, tool_call_id, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    message.id,
                    session_id,
                    message.role.value,
                    content,
                    message.timestamp.isoformat(),
                    message.token_count,
                    message.priority.value,
                    message.tool_name,
                    message.tool_call_id,
                    json_dumps(meta),
                ),
            )
```

### Step 3: Update `_update_session_activity` method

**Location**: Line 2452-2458

**Wrap in lock**:
```python
def _update_session_activity(self, session_id: str):
    """Update session last activity timestamp with write serialization."""
    with self._write_lock_sync:
        with sqlite3.connect(self.db_path, timeout=60.0) as conn:
            conn.execute(
                "UPDATE sessions SET last_activity = ? WHERE session_id = ?",
                (datetime.now().isoformat(), session_id),
            )
```

### Step 4: Update `add_message_async` method

**Location**: Line 2687-2723

**Wrap async writes in lock**:
```python
async def add_message_async(
    self,
    session_id: str,
    role: "MessageRole",
    content: str,
    priority: Optional["MessagePriority"] = None,
    tool_name: Optional[str] = None,
    tool_call_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
    tool_calls: Optional[List] = None,
) -> "ConversationMessage":
    """Async variant of add_message with serialized writes.

    Uses asyncio.Lock to ensure only one database write operation
    happens at a time, preventing SQLite lock contention.
    """
    import asyncio

    # Call shared implementation
    message = self._add_message_impl(
        session_id, role, content, priority, tool_name, tool_call_id, metadata, tool_calls
    )

    # CRITICAL: Serialize async writes with asyncio.Lock
    # This prevents concurrent to_thread calls from competing for DB lock
    async with self._write_lock_async:
        # Persist (async SQLite I/O - offloaded to thread pool)
        await asyncio.to_thread(self._persist_message, session_id, message)
        await asyncio.to_thread(self._update_session_activity, session_id)

    session = self._sessions.get(session_id)
    total_tokens = session.current_tokens if session else 0
    logger.debug(
        "Added %s message to %s (async). Tokens: %d, Total: %d",
        role.value,
        session_id,
        message.token_count,
        total_tokens,
    )
    return message
```

### Step 5: Update `_get_connection` method

**Location**: Line 265-277

**Add busy timeout and increase timeout**:
```python
def _get_connection(self) -> sqlite3.Connection:
    """Get a SQLite connection with optimized settings for concurrent access.

    Returns a connection with:
    - 60-second timeout for handling concurrent access (increased from 30)
    - WAL mode for better read/write concurrency
    - Busy timeout for automatic retries when locked
    - Optimized pragmas for performance
    """
    conn = sqlite3.connect(self.db_path, timeout=60.0)
    # Ensure WAL mode is set (in case it wasn't during init)
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    conn.execute("PRAGMA busy_timeout = 60000")  # 60 second busy timeout
    return conn
```

---

## Applying the Patch

### Option 1: Manual Edit
Edit the file directly at the locations specified above.

### Option 2: Apply Patch File
```bash
cd /Users/vijaysingh/code/codingagent
patch -p1 < /Users/vijaysingh/code/sentinelpass/sqlite_lock_patch.diff
```

### Option 3: Copy-Paste Implementation
1. Open `/Users/vijaysingh/code/codingagent/victor/agent/conversation/store.py`
2. Search for each location mentioned in steps above
3. Apply the code changes
4. Save the file

---

## Testing the Fix

After applying the fix:

1. **Restart your victor agent** to ensure changes take effect
2. **Run concurrent operations** that previously triggered the error
3. **Monitor logs** for any remaining lock errors:
   ```bash
   tail -f ~/.victor/logs/victor.log | grep -i "lock"
   ```
4. **Verify messages are being persisted**:
   ```bash
   sqlite3 ~/.victor/project.db "SELECT COUNT(*) FROM messages"
   ```

---

## Additional Improvements (Optional)

### 1. Connection Pool
For high-volume scenarios, implement a connection pool to reduce overhead:

```python
class SQLiteConnectionPool:
    def __init__(self, db_path: str, pool_size: int = 5):
        self.db_path = db_path
        self.pool_size = pool_size
        self._connections: list = []
        self._lock = threading.Lock()
        self._semaphore = threading.Semaphore(pool_size)

        for _ in range(pool_size):
            conn = sqlite3.connect(db_path, timeout=60.0, check_same_thread=False)
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA busy_timeout = 60000")
            self._connections.append(conn)

    @contextmanager
    def get_connection(self):
        self._semaphore.acquire()
        try:
            with self._lock:
                conn = self._connections.pop()
            try:
                yield conn
            finally:
                with self._lock:
                    self._connections.append(conn)
        finally:
            self._semaphore.release()
```

### 2. Retry Logic
Add exponential backoff for transient lock errors:

```python
def _get_connection_with_retry(self, max_retries: int = 5) -> sqlite3.Connection:
    base_timeout = 60.0

    for attempt in range(max_retries):
        try:
            timeout = base_timeout * (1.5 ** attempt)
            conn = sqlite3.connect(self.db_path, timeout=timeout)
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA busy_timeout = int(timeout * 1000)")
            return conn
        except sqlite3.OperationalError as e:
            if attempt == max_retries - 1:
                raise
            wait_time = min(0.1 * (2 ** attempt), 1.0)
            logger.warning(f"DB locked (attempt {attempt + 1}/{max_retries}), retrying in {wait_time:.1f}s")
            time.sleep(wait_time)
```

### 3. Batch Writes
For very high write volume, batch multiple writes into a single transaction.

---

## Summary of Changes

| Component | Change | Impact |
|-----------|--------|--------|
| `timeout=30.0` → `timeout=60.0` | Increase connection timeout | Reduces timeouts |
| Add `PRAGMA busy_timeout = 60000` | Automatic retries | Self-recovering |
| `threading.Lock()` for sync writes | Serialize sync operations | Prevents concurrent writes |
| `asyncio.Lock()` for async writes | Serialize async operations | Prevents concurrent writes |
| Wrap all DB writes in locks | Ensure serialization | Fixes root cause |

---

## Files Created

1. **`sqlite_lock_fix.py`** - Comprehensive fix documentation and code examples
2. **`sqlite_lock_patch.diff`** - Git patch file for easy application
3. **`SQLITE_LOCK_FIX_SUMMARY.md`** - This file (implementation guide)

---

## Questions?

If issues persist after applying the fix:
1. Check if there are multiple `ConversationStore` instances (should be singleton)
2. Verify no other processes are accessing the database
3. Check disk I/O performance (slow storage can cause timeouts)
4. Consider migrating to PostgreSQL for production high-concurrency scenarios
