# Victor Tool Analysis & Enhancement Plan

## Console Transcript Analysis

### Tools Called Successfully ✅

| Tool | Status | Notes |
|------|--------|-------|
| **ls** | ✅ Working | File system listing |
| **read** | ✅ Working | File reading |
| **codeSearch** | ⚠️ Degraded | Semantic fails, falls back to literal (working) |
| **docsCoverage** | ✅ Working | Documentation coverage analysis |

### Tools Failed ❌

| Tool | Error | Root Cause |
|------|-------|------------|
| **graph** | "no such column: file" | SQL query schema mismatch |
| **edit** | ❌ **NOT CALLED** | Missing from tool registry |

### Warnings ⚠️

| Warning | Impact |
|---------|--------|
| "Migration SQL failed: no such table: graph_edge" | Harmless (idempotent check) |
| "Semantic index build failed (no such column: file)" | Falls back to literal search |

---

## Critical Issue: Edit Tool Not Available

### Problem

The LLM created a **29-step plan** to fix architectural issues:

```
┃ #   ┃ Type         ┃ Description
┡━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
│ 12  │ feature      │ Phase 1A — Implement unified error...
│ 18  │ refactor     │ Phase 2A — Split core/config.rs...
│ 21  │ refactor     │ Phase 3A — Split storage/traits.rs...
```

**The LLM never called the edit tool once!**

### Why This Matters

1. ❌ **LLM cannot make code changes** - Only can read/analyze
2. ❌ **Plan is useless** - 29-step plan with no execution capability
3. ❌ **Victor appears broken** - User sees "Plan mode" but no follow-through
4. ❌ **Workflow interruption** - User must manually implement all changes

### Root Cause

The `edit` tool exists in `victor/tools/file_editor_tool.py` but is **not registered** in the tool registry for this chat session.

---

## Graph Tool "no such column: file" Error

### Status: ⚠️ PARTIALLY FIXED

We fixed the **error message** (commit 50b3d46a5), but the **underlying issue** remains:

1. ✅ **Error message fixed** - Now shows correct columns
2. ❌ **graph mode='overview' still failing** - LLM-generated queries fail
3. ❌ **graph mode='stats' still failing** - Stats queries fail

### Actual Root Cause

The error is **NOT from graph_tool.py queries** - those are correct.

The "no such column: file" error is from **code_search semantic index build**:

```
2026-05-10 11:23:49,018 - code_search - WARNING - Semantic index build failed
(error=no such column: file), falling back to literal search
```

This is a **separate bug** in the victor-coding package or embedding bridge.

---

## Migration SQL Warning

### Warning Message

```
2026-05-10 11:17:04,669 - victor.core.database - WARNING - Migration SQL failed
(may be idempotent): no such table: graph_edge
```

### Analysis

✅ **Harmless** - This is expected behavior

The migration system runs SQL during startup:
1. Checks if `graph_edge` table exists
2. If not, migration fails (gracefully)
3. Graph tables are created later by indexing system

**No action needed** - This is working as designed.

---

## Enhancement Recommendations

### Priority 1: Enable Edit Tool (CRITICAL)

**Problem**: LLM cannot make code changes

**Solution**:
```python
# Register file_editor_tool in tool registry
from victor.tools.file_editor_tool import edit

# Ensure tool is available to LLM
tool_registry.register(edit)
```

**Impact**:
- ✅ LLM can actually implement its plans
- ✅ "Plan mode" becomes useful
- ✅ Victor provides end-to-end assistance

### Priority 2: Fix code_search Semantic Index

**Problem**: "no such column: file" in embedding queries

**Solution**:
1. Find where victor-coding queries embeddings table
2. Fix the SQL to use correct column names
3. OR add migration to ensure 'file' column exists

**Impact**:
- ✅ Semantic search works properly
- ✅ No fallback to literal search
- ✅ Better code search results

### Priority 3: Improve Graph Tool Robustness

**Problem**: graph(mode='overview') and graph(mode='stats') failing

**Solution**:
1. Check if graph tables are populated before running queries
2. Provide better error messages if graph is empty
3. Add fallback to "no graph available" message

**Impact**:
- ✅ Better UX when graph not yet indexed
- ✅ Clearer error messages
- ✅ Graceful degradation

### Priority 4: Tool Availability Indicators

**Problem**: User doesn't know which tools are available

**Solution**: Add tool status command
```bash
You> /tools
Available tools:
  ✅ ls          - File system listing
  ✅ read        - File reading
  ✅ codeSearch  - Code search (literal mode)
  ⚠️ graph       - Graph analysis (needs indexing)
  ⚠️ edit        - File editing (disabled in this session)
  ❌ write       - File creation (not available)
```

**Impact**:
- ✅ User knows what tools they can use
- ✅ Clear indication when tools are missing
- ✅ Better debugging experience

---

## Implementation Plan

### Phase 1: Enable Edit Tool (Immediate)

```bash
# 1. Check current tool registration
cd /Users/vijaysingh/code/codingagent
grep -rn "file_editor_tool" victor/agent/

# 2. Add to tool registry if missing
# 3. Test edit tool availability
victor chat -p test <<< "/tools"
```

### Phase 2: Fix code_search Semantic Index (1-2 days)

```bash
# 1. Find embeddings table schema
sqlite3 ~/.victor/project.db ".schema" | grep -i embedding

# 2. Find victor-coding queries
grep -rn "SELECT.*file.*embeddings" victor/

# 3. Fix SQL or add migration
```

### Phase 3: Improve Graph Tool (1 day)

```bash
# 1. Add graph table check before queries
# 2. Provide better empty graph message
# 3. Add "index needed" hint
```

### Phase 4: Tool Status Display (1 day)

```bash
# 1. Implement /tools command
# 2. Show tool availability
# 3. Add tool health checks
```

---

## Testing Checklist

After implementing fixes:

- [ ] Edit tool available and working
- [ ] Graph tool works without "no such column" errors
- [ ] code_search semantic mode works (no fallback)
- [ ] /tools command shows accurate status
- [ ] All tools have clear error messages
- [ ] LLM can successfully use edit tool
- [ ] Plan mode followed by execution

---

## Summary

| Issue | Priority | Est. Time | Status |
|-------|----------|-----------|--------|
| **Edit tool not available** | 🔴 CRITICAL | 1-2 hours | Not started |
| **code_search semantic index** | 🟠 HIGH | 1-2 days | Not started |
| **Graph tool robustness** | 🟡 MEDIUM | 1 day | Partially fixed |
| **Tool status display** | 🟢 LOW | 1 day | Not started |

**Most Critical**: Enable edit tool so LLM can actually implement its 29-step plan!

Without the edit tool, Victor is **read-only** - great for analysis, **cannot execute changes**.
