#!/usr/bin/env python3
"""
Concurrent write test for SQLite database lock fix.

This test simulates the condition that was causing "database is locked" errors
by running multiple concurrent database writes through asyncio.to_thread().
"""

import asyncio
import tempfile
import shutil
from pathlib import Path
from datetime import datetime
import sys
import os

# Add the victor package to path
sys.path.insert(0, str(Path(__file__).parent.parent / "codingagent"))

from victor.agent.conversation.store import ConversationStore
from victor.agent.conversation.types import MessageRole, MessagePriority


async def test_concurrent_writes(num_concurrent_writes: int = 50):
    """
    Test concurrent database writes to verify the lock fix.

    This simulates the actual error condition where multiple async tasks
    try to write to the database simultaneously via asyncio.to_thread().

    Args:
        num_concurrent_writes: Number of concurrent write operations

    Returns:
        bool: True if all writes succeeded without database lock errors
    """
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

        # Track results using thread-safe counters
        from threading import Lock
        results_lock = Lock()
        success_count = [0]
        lock_error_count = [0]
        other_errors = []

        async def write_message(message_id: int):
            """Write a single message to the database."""
            try:
                # This is the critical path that was causing lock errors
                result = await store.add_message_async(
                    session_id=session.session_id,
                    role=MessageRole.USER,
                    content=f"Test message {message_id} from concurrent task",
                    priority=MessagePriority.NORMAL,
                )
                with results_lock:
                    success_count[0] += 1
            except Exception as e:
                error_msg = str(e)
                import traceback
                traceback.print_exc()
                with results_lock:
                    if "database is locked" in error_msg.lower() or "locked" in error_msg.lower():
                        lock_error_count[0] += 1
                    other_errors.append(f"Message {message_id}: {type(e).__name__}: {error_msg}")

        # Launch all concurrent writes simultaneously
        print(f"\n⚡ Launching {num_concurrent_writes} concurrent write operations...")
        start_time = datetime.now()

        tasks = [write_message(i) for i in range(num_concurrent_writes)]
        await asyncio.gather(*tasks)

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        # Report results
        print(f"\n📊 Results:")
        print(f"   ✅ Successful writes: {success_count[0]}/{num_concurrent_writes}")
        print(f"   ❌ Lock errors: {lock_error_count[0]}")
        print(f"   ⏱️  Duration: {duration:.2f}s")
        if duration > 0:
            print(f"   📈 Throughput: {success_count[0]/duration:.1f} writes/sec")

        if lock_error_count[0] > 0:
            print(f"\n❌ FAILED: Database lock errors detected!")
            print(f"\nFirst few errors:")
            for error in other_errors[:5]:
                print(f"   - {error}")
            return False
        else:
            print(f"\n✅ SUCCESS: All concurrent writes completed without lock errors!")
            return True

    finally:
        # Cleanup
        if db_path.exists():
            shutil.rmtree(temp_dir, ignore_errors=True)
            print(f"\n🧹 Cleaned up test database")


async def test_stress_concurrent_writes():
    """
    Stress test with varying levels of concurrency.
    """
    print("\n" + "="*70)
    print("🔥 STRESS TEST: Multiple concurrency levels")
    print("="*70)

    concurrency_levels = [10, 25, 50, 100]
    results = {}

    for concurrency in concurrency_levels:
        print(f"\n--- Testing with {concurrency} concurrent writes ---")
        success = await test_concurrent_writes(num_concurrent_writes=concurrency)
        results[concurrency] = success

        # Small delay between tests
        await asyncio.sleep(0.5)

    # Summary
    print("\n" + "="*70)
    print("📋 STRESS TEST SUMMARY")
    print("="*70)
    for concurrency, success in results.items():
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"   {concurrency:3d} concurrent writes: {status}")

    all_passed = all(results.values())
    if all_passed:
        print(f"\n🎉 All stress tests passed!")
    else:
        print(f"\n⚠️  Some stress tests failed")

    return all_passed


async def main():
    """Run all tests."""
    print("="*70)
    print("SQLite Database Lock Fix - Concurrent Write Test")
    print("="*70)
    print("\nThis test simulates the concurrent write condition that was")
    print("causing 'database is locked' errors in production.\n")

    # Run basic concurrent write test
    print("─"*70)
    basic_test_passed = await test_concurrent_writes(num_concurrent_writes=50)

    # Run stress test
    print("\n")
    stress_test_passed = await test_stress_concurrent_writes()

    # Final result
    print("\n" + "="*70)
    print("FINAL RESULT")
    print("="*70)
    if basic_test_passed and stress_test_passed:
        print("✅ ALL TESTS PASSED - Database lock fix is working!")
        return 0
    else:
        print("❌ TESTS FAILED - Database lock errors still present")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
