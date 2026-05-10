#!/usr/bin/env python3
"""
Simple concurrent write test for SQLite database lock fix.
"""

import asyncio
import tempfile
from pathlib import Path
import shutil
import sys

sys.path.insert(0, str(Path(__file__).parent.parent / "codingagent"))

from victor.agent.conversation.store import ConversationStore
from victor.agent.conversation.types import MessageRole, MessagePriority


async def test_concurrent_writes(num_concurrent_writes: int = 50):
    """Test concurrent database writes."""
    # Create a temporary database for testing
    temp_dir = tempfile.mkdtemp(prefix="victor_db_test_")
    db_path = Path(temp_dir) / "test.db"

    print(f"🧪 Testing concurrent database writes...")
    print(f"   Database: {db_path}")
    print(f"   Concurrent writes: {num_concurrent_writes}")

    try:
        # Initialize store
        store = ConversationStore(db_path=db_path)
        session = store.create_session(project_path="/test/project")

        # Launch all concurrent writes simultaneously
        print(f"\n⚡ Launching {num_concurrent_writes} concurrent write operations...")

        import time
        start_time = time.time()

        tasks = [
            store.add_message_async(
                session_id=session.session_id,
                role=MessageRole.USER,
                content=f"Test message {i} from concurrent task",
                priority=MessagePriority.MEDIUM,
            )
            for i in range(num_concurrent_writes)
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        end_time = time.time()
        duration = end_time - start_time

        # Count results
        success_count = sum(1 for r in results if isinstance(r, tuple) or not isinstance(r, Exception))
        error_count = sum(1 for r in results if isinstance(r, Exception))
        lock_errors = [
            r for r in results
            if isinstance(r, Exception) and "locked" in str(r).lower()
        ]

        # Report results
        print(f"\n📊 Results:")
        print(f"   ✅ Successful writes: {success_count}/{num_concurrent_writes}")
        print(f"   ❌ Errors: {error_count}")
        print(f"   🔒 Lock errors: {len(lock_errors)}")
        print(f"   ⏱️  Duration: {duration:.2f}s")
        print(f"   📈 Throughput: {success_count/duration:.1f} writes/sec")

        if lock_errors:
            print(f"\n❌ FAILED: Database lock errors detected!")
            for err in lock_errors[:5]:
                print(f"   - {err}")
            return False
        else:
            print(f"\n✅ SUCCESS: All concurrent writes completed without lock errors!")
            return True

    finally:
        # Cleanup
        if db_path.exists():
            shutil.rmtree(temp_dir, ignore_errors=True)
            print(f"\n🧹 Cleaned up test database")


async def main():
    """Run all tests."""
    print("="*70)
    print("SQLite Database Lock Fix - Concurrent Write Test")
    print("="*70)
    print("\nThis test simulates the concurrent write condition that was")
    print("causing 'database is locked' errors in production.\n")

    print("─"*70)
    success = await test_concurrent_writes(num_concurrent_writes=100)

    print("\n" + "="*70)
    print("FINAL RESULT")
    print("="*70)
    if success:
        print("✅ TEST PASSED - Database lock fix is working!")
        return 0
    else:
        print("❌ TEST FAILED - Database lock errors detected")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
