#!/usr/bin/env python3
"""
Comprehensive stress test for SQLite database lock fix.
Tests various concurrency levels to ensure the fix is robust.
"""

import asyncio
import tempfile
from pathlib import Path
import shutil
import sys

sys.path.insert(0, str(Path(__file__).parent.parent / "codingagent"))

from victor.agent.conversation.store import ConversationStore
from victor.agent.conversation.types import MessageRole, MessagePriority


async def test_concurrency_level(num_writes: int, concurrency: int):
    """Test a specific concurrency level."""
    temp_dir = tempfile.mkdtemp(prefix="victor_stress_")
    db_path = Path(temp_dir) / "test.db"

    try:
        store = ConversationStore(db_path=db_path)
        session = store.create_session(project_path="/test/project")

        import time

        start_time = time.time()

        # Create batches of concurrent writes
        batch_size = concurrency
        total_writes = num_writes
        all_success = True
        lock_errors = []

        for batch_start in range(0, total_writes, batch_size):
            batch_size = min(batch_size, total_writes - batch_start)

            tasks = [
                store.add_message_async(
                    session_id=session.session_id,
                    role=MessageRole.USER,
                    content=f"Message {i} (batch {batch_start//concurrency + 1})",
                    priority=MessagePriority.MEDIUM,
                )
                for i in range(batch_start, batch_start + batch_size)
            ]

            results = await asyncio.gather(*tasks, return_exceptions=True)

            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    all_success = False
                    if "locked" in str(result).lower():
                        lock_errors.append(result)

        end_time = time.time()
        duration = end_time - start_time

        return {
            "success": all_success,
            "lock_errors": len(lock_errors),
            "duration": duration,
            "throughput": total_writes / duration if duration > 0 else 0,
        }

    finally:
        if db_path.exists():
            shutil.rmtree(temp_dir, ignore_errors=True)


async def main():
    """Run comprehensive stress tests."""
    print("=" * 70)
    print("SQLite Database Lock Fix - Comprehensive Stress Test")
    print("=" * 70)

    test_configs = [
        ("Low concurrency", 100, 10),  # 100 writes, 10 concurrent
        ("Medium concurrency", 200, 50),  # 200 writes, 50 concurrent
        ("High concurrency", 300, 100),  # 300 writes, 100 concurrent
        ("Very high concurrency", 500, 200),  # 500 writes, 200 concurrent
    ]

    results = []

    for name, total_writes, concurrency in test_configs:
        print(f"\n{'─'*70}")
        print(f"📊 Test: {name}")
        print(f"   Total writes: {total_writes}")
        print(f"   Concurrency: {concurrency}")

        result = await test_concurrency_level(total_writes, concurrency)
        results.append((name, result))

        if result["success"]:
            print("   ✅ PASSED")
            print(f"   ⏱️  Duration: {result['duration']:.2f}s")
            print(f"   📈 Throughput: {result['throughput']:.1f} writes/sec")
            print(f"   🔒 Lock errors: {result['lock_errors']}")
        else:
            print("   ❌ FAILED")
            print(f"   🔒 Lock errors: {result['lock_errors']}")

    # Summary
    print("\n" + "=" * 70)
    print("📋 SUMMARY")
    print("=" * 70)

    all_passed = all(r[1]["success"] for r in results)

    for name, result in results:
        status = "✅ PASS" if result["success"] else "❌ FAIL"
        throughput = result["throughput"]
        print(f"   {name:25s}: {status} ({throughput:6.1f} writes/sec)")

    print("\n" + "=" * 70)
    if all_passed:
        print("🎉 ALL TESTS PASSED!")
        print("   The database lock fix is working correctly across all")
        print("   concurrency levels. No 'database is locked' errors detected.")
        return 0
    else:
        print("❌ SOME TESTS FAILED")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
