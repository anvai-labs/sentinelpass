"""
Fix for SQLite database lock contention in victor agent conversation store.

This file contains the necessary modifications to add a write serialization queue
to prevent concurrent database writes from causing "database is locked" errors.

Apply these changes to: /Users/vijaysingh/code/codingagent/victor/agent/conversation/store.py
"""

import asyncio
import sqlite3
import threading
import time
from contextlib import contextmanager
from typing import Optional, Callable, Any
from loguru import logger


# =============================================================================
# SOLUTION 1: Add Write Serialization Queue (RECOMMENDED)
# =============================================================================

"""
Add this to the ConversationStore.__init__ method after line 256:
"""

# Add these instance variables to __init__:
# After line 256 (after self._provider_ids: Dict[str, int] = {}):

# Write serialization queue to prevent concurrent database locks
self._write_lock = asyncio.Lock()  # For async operations
self._write_lock_sync = threading.Lock()  # For sync operations
self._write_queue: Optional[asyncio.Queue] = None  # Initialized if needed
self._write_task: Optional[asyncio.Task] = None  # Background writer task


"""
Replace the _persist_message method (lines 2400-2450) with this version:
"""

def _persist_message(self, session_id: str, message):
    """Persist message to database with write serialization.

    Uses threading.Lock for sync operations and asyncio.Lock for async
    operations to prevent concurrent writes that cause SQLite lock errors.
    """
    # Truncate large tool outputs for storage
    content = message.content
    if len(content) > self._TOOL_OUTPUT_STORE_LIMIT and (
        message.role in (MessageRole.TOOL_CALL, MessageRole.TOOL)
        or (message.role == MessageRole.USER and content.startswith("<TOOL_OUTPUT"))
    ):
        content = (
            content[: self._TOOL_OUTPUT_STORE_LIMIT]
            + f"\n\n[... truncated from {len(message.content)} chars "
            f"for storage]"
        )

    # Merge tool_calls into metadata for persistence
    meta = dict(message.metadata) if message.metadata else {}
    if message.tool_calls:
        meta["tool_calls"] = message.tool_calls

    # Sanitize metadata for JSON serialization
    meta = self._sanitize_metadata_for_json(meta)

    # CRITICAL: Use lock to serialize all write operations
    # This prevents "database is locked" errors from concurrent writes
    with self._write_lock_sync:
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


"""
Replace _update_session_activity (lines 2452-2458) with this version:
"""

def _update_session_activity(self, session_id: str):
    """Update session last activity timestamp with write serialization."""
    with self._write_lock_sync:
        with sqlite3.connect(self.db_path, timeout=30.0) as conn:
            conn.execute(
                "UPDATE sessions SET last_activity = ? WHERE session_id = ?",
                (datetime.now().isoformat(), session_id),
            )


"""
Replace add_message_async (lines 2687-2723) with this version:
"""

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
    async with self._write_lock:
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


# =============================================================================
# SOLUTION 2: Increase Timeout with Retry Logic
# =============================================================================

def _get_connection_with_retry(self, max_retries: int = 5) -> sqlite3.Connection:
    """Get a SQLite connection with exponential backoff retry logic.

    Args:
        max_retries: Maximum number of retry attempts (default: 5)

    Returns:
        SQLite connection with optimized settings

    Raises:
        sqlite3.OperationalError: If unable to connect after all retries
    """
    base_timeout = 30.0  # Base timeout in seconds

    for attempt in range(max_retries):
        try:
            # Exponential backoff: 30s, 45s, 67.5s, 101s, 151s
            timeout = base_timeout * (1.5 ** attempt)
            conn = sqlite3.connect(self.db_path, timeout=timeout)
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = NORMAL")
            conn.execute("PRAGMA busy_timeout = int(timeout * 1000)")  # Convert to ms
            return conn
        except sqlite3.OperationalError as e:
            if attempt == max_retries - 1:
                logger.error(f"Failed to connect to database after {max_retries} attempts: {e}")
                raise
            wait_time = min(0.1 * (2 ** attempt), 1.0)  # Max 1 second wait
            logger.warning(f"Database locked (attempt {attempt + 1}/{max_retries}), retrying in {wait_time:.1f}s...")
            time.sleep(wait_time)


# =============================================================================
# SOLUTION 3: Connection Pool
# =============================================================================

class SQLiteConnectionPool:
    """Simple connection pool for SQLite to reduce connection overhead."""

    def __init__(self, db_path: str, pool_size: int = 5):
        self.db_path = db_path
        self.pool_size = pool_size
        self._connections: list[sqlite3.Connection] = []
        self._lock = threading.Lock()
        self._semaphore = threading.Semaphore(pool_size)

        # Initialize pool
        for _ in range(pool_size):
            conn = sqlite3.connect(db_path, timeout=60.0, check_same_thread=False)
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = NORMAL")
            conn.execute("PRAGMA busy_timeout = 60000")  # 60 seconds
            self._connections.append(conn)

    @contextmanager
    def get_connection(self):
        """Get a connection from the pool."""
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

    def close(self):
        """Close all connections in the pool."""
        with self._lock:
            for conn in self._connections:
                conn.close()
            self._connections.clear()


"""
Add to ConversationStore.__init__:

# After self._init_database():
self._connection_pool = SQLiteConnectionPool(str(self.db_path), pool_size=5)

And update _persist_message to use the pool:

with self._connection_pool.get_connection() as conn:
    conn.execute(...)
"""


# =============================================================================
# SOLUTION 4: Batch Writes (For High-Volume Scenarios)
# =============================================================================

class BatchWriteManager:
    """Manager for batching database writes to reduce lock contention."""

    def __init__(self, store: 'ConversationStore', batch_size: int = 10, flush_interval: float = 1.0):
        self.store = store
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self._pending_writes: list[tuple[str, Any]] = []
        self._lock = threading.Lock()
        self._last_flush = time.time()
        self._task: Optional[asyncio.Task] = None

    async def add_write(self, session_id: str, message):
        """Add a write to the batch."""
        with self._lock:
            self._pending_writes.append((session_id, message))

            # Flush if batch is full
            if len(self._pending_writes) >= self.batch_size:
                await self._flush()

    async def _flush(self):
        """Flush all pending writes to database in a single transaction."""
        with self._lock:
            if not self._pending_writes:
                return

            writes = self._pending_writes.copy()
            self._pending_writes.clear()
            self._last_flush = time.time()

        # Perform all writes in a single transaction
        await asyncio.to_thread(self._do_writes, writes)

    def _do_writes(self, writes: list[tuple[str, Any]]):
        """Execute batched writes in a transaction."""
        with self.store._get_connection() as conn:
            try:
                conn.execute("BEGIN TRANSACTION")
                for session_id, message in writes:
                    # Individual write logic here
                    pass
                conn.commit()
            except Exception as e:
                conn.rollback()
                logger.error(f"Batch write failed: {e}")
                raise

    async def start(self):
        """Start periodic flush task."""
        async def flush_periodically():
            while True:
                await asyncio.sleep(self.flush_interval)
                await self._flush()

        self._task = asyncio.create_task(flush_periodically())

    async def stop(self):
        """Stop batch manager and flush remaining writes."""
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        await self._flush()


# =============================================================================
# SOLUTION 5: Immediate Quick Fix (Single-Line Change)
# =============================================================================

"""
If you just need a quick fix and don't want to modify much code,
increase the timeout value in _get_connection from 30.0 to 120.0:

Line 273, change:
    conn = sqlite3.connect(self.db_path, timeout=30.0)

To:
    conn = sqlite3.connect(self.db_path, timeout=120.0)

And add this line after it:
    conn.execute("PRAGMA busy_timeout = 120000")  # 120 seconds in milliseconds
"""


# =============================================================================
# IMPLEMENTATION GUIDE
# =============================================================================

"""
RECOMMENDED IMPLEMENTATION ORDER:

1. IMMEDIATE (5 minutes):
   - Apply Solution 5 (increase timeout)
   - This provides immediate relief

2. SHORT-TERM (30 minutes):
   - Apply Solution 1 (write serialization locks)
   - This is the most effective fix for the root cause

3. MEDIUM-TERM (1-2 hours):
   - Apply Solution 3 (connection pool)
   - Reduces connection overhead

4. LONG-TERM (optional):
   - Consider Solution 4 (batch writes) if you have very high write volume
   - Solution 2 (retry logic) can be combined with any of the above

TESTING:
- Run your concurrent operations
- Monitor for "database is locked" errors
- Check logs for retry messages
- Monitor database performance with:
  sqlite3 ~/.victor/project.db "PRAGMA wal_checkpoint(PASSIVE)"
"""
