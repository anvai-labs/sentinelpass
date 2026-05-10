# Victor Tool Behavior - Complete Analysis

## Executive Summary

**Is this correct behavior?** ✅ **YES, this is expected behavior**

**Are enhancements needed?** ✅ **YES, improvements are possible**

---

## Issue Analysis

### 1. Edit Tool "Missing" - EXPECTED BEHAVIOR ✅

**What's Happening**: The LLM is NOT calling the edit tool

**Why**: Victor has **three operational modes** with different permissions:

| Mode | Purpose | Edit Tool Access | Other Restrictions |
|------|---------|------------------|-------------------|
| **BUILD** | Taking action, implementing changes | ✅ Unrestricted | None |
| **PLAN** | Analysis and planning | ⚠️ Restricted to `.victor/sandbox/` | Cannot edit production files |
| **EXPLORE** | Understanding and navigating | ⚠️ Restricted to `.victor/sandbox/` | Read-heavy exploration |

**Current Session**: LLM is in **PLAN mode** (created a 29-step plan but couldn't execute it)

**Evidence**:
```python
# From file_editor_tool.py:287-288
"""
In EXPLORE/PLAN modes, edits are restricted to .victor/sandbox/.
Use /mode build to enable unrestricted file edits.
"""
```

**Solution**: User needs to switch to BUILD mode:
```bash
You> /mode build
# OR
You> /build
```

### 2. Graph Tool "no such column: file" - TWO SEPARATE ISSUES

#### Issue A: Graph Tool Error Message ✅ FIXED

**Status**: Fixed in commit 50b3d46a5

The error handler was claiming `graph_edge` has columns it doesn't have.

#### Issue B: code_search Semantic Index ⚠️ STILL BROKEN

**Error**:
```
2026-05-10 11:23:49,018 - WARNING - [code_search] Semantic index build failed
(error=no such column: file), falling back to literal search.
```

**Root Cause**: The victor-coding package's semantic index builder is querying a table with a `file` column that doesn't exist.

**Impact**: Semantic search disabled, falling back to literal search (still works, just degraded)

**Fix Needed**:
1. Find embeddings table schema in victor-coding
2. Fix SQL query or add migration for missing column

### 3. Migration SQL Warning ⚠️ HARMLESS

```
2026-05-10 11:17:04,669 - WARNING - Migration SQL failed
(may be idempotent): no such table: graph_edge
```

**Status**: ✅ **Expected behavior, not a bug**

**Explanation**:
1. Victor starts up
2. Migration system tries to run migrations
3. Checks if `graph_edge` exists (it doesn't yet)
4. Fails gracefully (log says "may be idempotent")
5. Graph indexing system creates tables later

**No action needed** - This is working as designed.

---

## Tools Available in Each Mode

### BUILD Mode (Full Access)

✅ **All tools available**:
- edit (unrestricted)
- write
- shell
- git
- refactor_*
- codeSearch (semantic + literal)
- graph
- ls, read
- All other tools

### PLAN Mode (Analysis & Planning)

⚠️ **Restricted access**:
- edit (sandbox only: `.victor/sandbox/`)
- write (sandbox only)
- shell (disabled)
- git (read-only)
- refactor_* (disabled)
- codeSearch (literal only, semantic degraded)
- graph (may fail if not indexed)
- ls, read ✅
- docsCoverage ✅

### EXPLORE Mode (Read-Heavy Navigation)

⚠️ **Restricted access**:
- Same as PLAN mode
- Focus on understanding and exploration
- Heavier tool limits for file reading

---

## Current Session State

### What Mode Was The LLM In?

**Evidence**: LLM created a detailed 29-step plan but **never called edit**

**Conclusion**: LLM was in **PLAN mode**

**Indicators**:
1. ✅ Read-only tools called (ls, read, docsCoverage)
2. ❌ Edit tool NOT called
3. ✅ 29-step plan created (typical PLAN mode behavior)
4. ⚠️ codeSearch degraded (semantic failed)

### Why The LLM Didn't Use Edit

**Reason**: In PLAN mode, the LLM knows:
- Edit tool is restricted to `.victor/sandbox/`
- User's project files are NOT in sandbox
- Edit calls would fail with permission errors
- Better to plan first, then user switches to BUILD mode

**This is correct behavior!** The LLM is being smart about mode restrictions.

---

## Solutions & Enhancements

### For User: Enable Edit Tool

**Option 1: Switch to BUILD mode** (Recommended)
```bash
You> /mode build
# OR
You> /build
```

**Option 2: Execute the plan**
```bash
You> /mode build
You> Please implement step 1 of the plan
```

**Option 3: Use sandbox for edits**
```bash
# Edit will work in .victor/sandbox/
# But won't work for project files in PLAN mode
```

### For Victor Developers: Improvements

#### Priority 1: Better Mode Indication (HIGH)

**Problem**: User doesn't know what mode they're in

**Solution**: Add mode indicator to prompt
```bash
[PLAN] You> Review the codebase...
# OR
[⚙️ BUILD] You> Fix the architecture...
```

**Implementation**:
```python
# victor/ui/commands/chat.py
def _get_mode_indicator():
    mode = get_mode_controller().current_mode
    return f"[{mode.value.upper()}] "
```

#### Priority 2: Tool Availability Command (MEDIUM)

**Problem**: User doesn't know which tools are available

**Solution**: Add `/tools` command
```bash
You> /tools
Current mode: PLAN

Available tools:
  ✅ ls, read          - File operations (read-only)
  ✅ codeSearch       - Code search (literal mode)
  ✅ docsCoverage     - Documentation analysis
  ⚠️ graph           - Graph analysis (needs indexing)
  ⚠️ edit            - File editing (sandbox only)
  ❌ shell, git      - Disabled in PLAN mode

For unrestricted access: /mode build
```

#### Priority 3: Fix code_search Semantic Index (HIGH)

**Problem**: "no such column: file" in embeddings query

**Solution**: Investigate victor-coding embedding schema

```bash
# 1. Find embeddings schema
cd /Users/vijaysingh/code/codingagent
find victor-coding -name "*.py" -exec grep -l "embeddings" {} \;

# 2. Check for 'file' column
grep -rn "CREATE TABLE.*embeddings" victor-coding/

# 3. Fix query or add migration
```

#### Priority 4: Better Error Messages (LOW)

**Problem**: Graph errors not helpful

**Solution**: Already fixed! ✅ (commit 50b3d46a5)

---

## Testing the Fix

### After Enabling BUILD Mode:

```bash
# 1. Switch to BUILD mode
You> /mode build

# 2. Test edit tool
You> edit(ops=[{"type": "replace", "path": "src/lib.rs",
              "old_str": "old_code", "new_str": "new_code"}])

# 3. Should see edit working!
```

### After Fixing code_search:

```bash
# 1. Clear failure cache
rm -rf ~/.victor/index_build_failure_cache/*

# 2. Test semantic search
You> code_search(query="StorageError", mode="semantic", k=5)

# 3. Should work without fallback!
```

---

## Summary

| Issue | Status | Fix |
|-------|--------|-----|
| **Edit tool not available** | ✅ Expected (PLAN mode) | Use `/mode build` |
| **Graph tool error** | ✅ Fixed | Error message corrected |
| **code_search semantic** | ⚠️ Broken | Fix victor-coding query |
| **Migration SQL warning** | ✅ Expected | No action needed |

---

## Recommendations

### For Users:

1. ✅ **Use `/mode build`** to enable edit tool
2. ✅ **Read mode messages** to understand restrictions
3. ✅ **Check with `/mode`** to see current mode

### For Developers:

1. 🔴 **Fix code_search semantic index** (HIGH priority)
2. 🟡 **Add mode indicator to prompt** (MEDIUM priority)
3. 🟢 **Add `/tools` command** (LOW priority)
4. 🟢 **Better tool availability docs** (LOW priority)

---

## Final Answer

**Is this correct behavior?**
> ✅ **YES** - Edit tool restricted in PLAN/EXPLORE modes by design

**Are enhancements needed?**
> ✅ **YES** - But NOT for the reason you think!

**Enhancement priorities**:
1. 🔴 Fix code_search semantic index (actual bug)
2. 🟡 Add mode indicator to prompt (UX improvement)
3. 🟢 Add `/tools` command (information visibility)

**NOT a bug**: Edit tool not being called in PLAN mode - this is working as designed!

**TO USE EDIT TOOL**: Run `/mode build` first!
