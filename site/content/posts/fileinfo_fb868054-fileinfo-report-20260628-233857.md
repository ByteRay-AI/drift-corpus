Title: fileinfo.sys — No security-relevant change (RB-tree root pointer-encoding completed, but encoding is disabled on every reachable path)
Date: 2026-06-28
Slug: fileinfo_fb868054-fileinfo-report-20260628-233857
Category: Corpus
Author: Argus
Summary: KB5078752

## 1. Overview

| Field | Value |
|---|---|
| Unpatched binary | `fileinfo_unpatched.sys` |
| Patched binary   | `fileinfo_patched.sys` |
| Overall similarity | **0.9854** |
| Matched / changed / identical | 173 / 4 / 169 |
| Unmatched (unpatched → patched) | 0 / 0 |

**Verdict:** The patch teaches four related functions to XOR-decode the *root* pointer of a red-black (RB) tree, matching the encoded-pointer handling that both builds already apply to the tree's *child* pointers. The encoding is a feature of the standard `RTL_RB_TREE` (`RtlRbInsertNodeEx`) that is only active when the tree's `Encoded` flag is set. In this driver every one of these trees is a zero-initialized, per-call local stack structure whose `Encoded` flag is never set, so both the pre-existing child-decode branch and the newly added root-decode branch are dead code that never executes at run time. There is no dangling pointer, no lifetime bug, and no reachable use-after-free. This is a dormant defense-in-depth / correctness-completion change, not a security fix.

---

## 2. Vulnerability Summary

### Finding #1 — RB-tree root pointer now XOR-decoded (dormant; encoding never enabled)

- **Severity:** None (defense-in-depth / no reachable impact)
- **Class:** No security-relevant change. The mechanism relates to pointer-encoding hardening (defense in depth); it does not correspond to a demonstrable CWE-416 use-after-free.
- **Affected functions:** `FIPfOpenListNotifyConflictStart` (RB-tree search/insert; `@0x1C0013D34` unpatched, `@0x1C0013D04` patched) and the three callers that build and tear down these trees: `FIPfFileFSOpStart` (`@0x1C000C9D0` / `@0x1C000C1F0`), `FIPfVolumeRundownFilePrefetchStart` (`@0x1C000FBEC` / `@0x1C00110CC`), and `FIPfVolumeRundownAllPrefetchStart` (`@0x1C001462C` / `@0x1C001461C`).

**What the code does.** `fileinfo.sys` builds a small RB tree keyed by an `int64` at node offset `+0x18`. Tree nodes are `0x30`-byte `NonPagedPoolNx` allocations tagged `'FINc'` (`0x634E4946`), allocated inside `FIPfOpenListNotifyConflictStart` and inserted with the standard kernel routine `RtlRbInsertNodeEx`. The tree header is an `RTL_RB_TREE`: field `+0x00` is `Root`, and the second pointer-sized field at `+0x08` is the `Min`/`Encoded` union. The standard RB-tree routines support an *encoded* mode in which stored pointers are XOR-obfuscated against the address of their containing slot; the driver mirrors that decode when it walks the tree by hand.

**What actually changed.** In the unpatched build the by-hand walk decodes *child* pointers (`node->left`/`node->right`) but reads the *root* pointer plainly. The patch adds, at every root read, `if (Encoded && root) root ^= &tree_header`, so the root is decoded the same way the children already were. The direction is correct (the patched build is the stricter one).

**Why it is not a vulnerability.**

1. **These trees are per-call local stack structures.** In all three callers the `RTL_RB_TREE` header lives in a stack slot (`P`) that is zero-initialized, populated, and fully torn down within the *same* function call. It is not a shared, long-lived object, so the report's premise of "another file context still holds the same node pointer" does not hold — there is no cross-call or cross-context sharing of these trees.

2. **Encoding is never enabled, so the decode never runs.** The `Encoded` gate is bit 0 of the `RTL_RB_TREE` field at `+0x08`. The driver zero-initializes each tree header and never sets the `Encoded` bit (there is no `RtlRbInitializeTree` call and no write to `tree+0x08` anywhere in the driver — that field is only ever written by `RtlRbInsertNodeEx`, which stores the `Min` node, an 8-byte-aligned pointer whose bit 0 is 0). Consequently `Encoded` is always 0, the pre-existing child-decode branch is never taken, and the newly added root-decode branch is never taken either. The patch is a behavioral no-op on every reachable path.

3. **Pointer encoding is a mitigation, not a lifetime fix.** Even if encoding were enabled, XOR-obfuscating a pointer does not fix any use-after-free; it is defense in depth that only matters *after* an attacker already has an independent memory-corruption primitive. The unpatched code has no premature free, no missing reference count, and no missing null-out: the root it reads belongs to the live local tree the same function is about to walk and free.

---

## 3. Pseudocode Diff

### `FIPfOpenListNotifyConflictStart` — root pointer read #1 (search-loop entry)

```c
// ---- UNPATCHED ----
uint8_t flag = *(uint8_t*)(arg4 + 8) & 1;  // Encoded bit (always 0 for these trees)
int64_t* node = *arg4;                     // root read (no decode)
// walk: child pointers ARE decoded when flag is set (flag is never set)

// ---- PATCHED ----
uint8_t flag = *(uint8_t*)(arg4 + 8) & 1;
int64_t* node = *arg4;
if (flag && node)                          // NEW: gate on Encoded bit
    node ^= arg4;                          // NEW: decode root (dead: flag == 0)
```

### `FIPfOpenListNotifyConflictStart` — root pointer read #2 (insert-position traversal)

```c
// ---- UNPATCHED ----
int64_t* node = *arg4;                     // root read (no decode)
uint8_t flag = *(uint8_t*)(arg4 + 8) & 1;

// ---- PATCHED ----
uint8_t flag = *(uint8_t*)(arg4 + 8);
int64_t* node = *arg4;
if ((flag & 1) && node)                    // NEW
    node ^= arg4;                          // NEW (dead: flag == 0)
```

### Callers (`FIPfFileFSOpStart`, `FIPfVolumeRundownFilePrefetchStart`, `FIPfVolumeRundownAllPrefetchStart`)

Each caller ends with a by-hand teardown walk that frees every node via `FIPfNotifiedContextsDelete` (`@0x1C0013CFC` / `@0x1C0013CCC` → `ExFreePoolWithTag`). The unpatched teardown reads the local tree's root plainly and decodes child links when the (never-set) flag is on; the patch adds the same `if (Encoded) root ^= &tree` decode to the root before the walk. Same dead-branch pattern, same local tree.

---

## 4. Assembly Analysis

### Unpatched `FIPfOpenListNotifyConflictStart @ 0x1C0013D34`

```asm
; tree header = r15 (arg4). Only reads of the header; it is never written by the driver.
00000001C0013DE2  movzx   edx, byte ptr [r15+8]     ; Encoded/Min union byte
00000001C0013DEB  and     edx, 1                     ; flag = bit 0  (always 0 here)
00000001C0013DFA  mov     rax, [r15]                 ; root read #1 — used as-is (no XOR)
00000001C0013DFD  mov     r9, [rsi+8]                ; search key
00000001C0013E01  jmp     short loc_1C0013E28

00000001C0013E28  test    rax, rax
00000001C0013E2B  jnz     short loc_1C0013E03
00000001C0013E03  mov     rcx, [rax+18h]             ; node key
00000001C0013E07  cmp     rcx, r9
00000001C0013E0A  ja      short loc_1C0013E14

; child pointer decode — present in BOTH builds, gated on the (never-set) flag:
00000001C0013E14  mov     rcx, [rax]                 ; raw child pointer
00000001C0013E17  test    edx, edx                   ; flag?
00000001C0013E19  jz      short loc_1C0013E25        ; flag==0 -> use raw child (this path taken)
00000001C0013E1B  test    rcx, rcx
00000001C0013E1E  jz      short loc_1C0013E25
00000001C0013E20  xor     rax, rcx                   ; decode child (dead: flag==0)
00000001C0013E25  mov     rax, rcx

; root read #2 (insert position) — used as-is:
00000001C0013E9C  movzx   ecx, byte ptr [r15+8]
00000001C0013EA1  mov     rdx, [r15]                 ; root read #2 (no XOR)
00000001C0013EA4  and     ecx, 1
00000001C0013EA7  test    rdx, rdx
00000001C0013EAA  jz      short loc_1C0013EE8

; node allocation and insert:
00000001C0013E4C  mov     edx, 30h                   ; size 0x30
00000001C0013E51  mov     ecx, 200h                  ; NonPagedPoolNx
00000001C0013E58  mov     r8d, 634E4946h             ; tag 'FINc'
00000001C0013E62  call    cs:__imp_ExAllocatePoolWithTag
00000001C0013EEE  call    cs:__imp_RtlRbInsertNodeEx ; rcx=r15 (tree), r9=new node
```

Note that the driver writes the tree header only via `RtlRbInsertNodeEx`; within this function the only explicit stores are to the freshly allocated node (`mov [rdi+18h], r9` at `0x1C0013E8F`), never to `[r15+8]`. The `Encoded` bit therefore stays 0.

### Patched `FIPfOpenListNotifyConflictStart @ 0x1C0013D04` — root now decoded

```asm
; root read #1 (search-loop entry) — decode added:
00000001C0013DB2  mov     rcx, [rdi+8]               ; flag byte (rdi = arg4 = tree)
00000001C0013DC6  mov     rax, [rdi]                 ; root
00000001C0013DCD  test    cl, 1                      ; if (Encoded)
00000001C0013DD0  jz      short loc_1C0013DDA
00000001C0013DD2  test    rax, rax
00000001C0013DD5  jz      short loc_1C0013DDA
00000001C0013DD7  xor     rax, rdi                   ; NEW: root ^= &tree (dead: flag==0)

; root read #2 (insert position) — decode added:
00000001C0013E76  mov     rax, [rdi+8]               ; flag byte
00000001C0013E7A  mov     rdx, [rdi]                 ; root
00000001C0013E7D  test    al, 1                      ; if (Encoded)
00000001C0013E7F  jz      short loc_1C0013E89
00000001C0013E81  test    rdx, rdx
00000001C0013E84  jz      short loc_1C0013E89
00000001C0013E86  xor     rdx, rdi                   ; NEW: root ^= &tree (dead: flag==0)
```

The only behavioral delta between the builds is the two new `xor reg, &tree` blocks (and the analogous one in each caller's teardown walk), each guarded by `test <flagbyte>, 1`. Because that flag is bit 0 of an aligned `Min` pointer in a never-encoded tree, the guard is never satisfied and the new code is never reached.

---

## 5. Trigger Conditions

The code path is reachable during normal file I/O: `FIPfFileFSOpPostCreate` (`@0x1C000DF80`) — reached on `IRP_MJ_CREATE` post-operation — calls `FIPfFileFSOpStart` (`0x1C000E257`) and `FIPfVolumeRundownFilePrefetchStart` (`0x1C000E31A`), and `FIPfVolumeRundownAllPrefetchStart` calls `FIPfVolumeRundownFilePrefetchStart`; all three build and tear down a local RB tree via `FIPfOpenListNotifyConflictStart`. Reaching this code, however, does not produce any memory-safety fault or attacker primitive: the tree is created, searched/inserted, and freed within a single call, and the `Encoded` decode branches are never taken. There is no trigger that turns this into a use-after-free or a controlled dereference.

---

## 6. Exploit Primitive & Development Notes

No exploit primitive exists. The change does not fix a use-after-free and does not create or remove one; it adds a conditional pointer-decode that is never executed because the `RTL_RB_TREE.Encoded` flag is never set for these trees. The RB-tree nodes carry only a key (`+0x18`), two child pointers (`+0x00`/`+0x08`), and a 16-byte data blob (`+0x20`); they hold no function pointer. The one indirect call on this path (`0x1C0013E46`, `__guard_dispatch_icall_fptr`) takes its target from the input work-item (`rsi = [rbx+0x28]`), not from any tree node, and is kCFG-validated. There is no pool-spray/reclaim window, no info leak, and no code-execution or data-only primitive attributable to this change.

---

## 7. Debugger Reference

Symbols: `.reload /f fileinfo.sys` (PDB `fileinfo.pdb`). The addresses below locate the actual (dormant) code for inspection; none of them represents a reachable fault site.

### Breakpoints

```text
bp fileinfo!FIPfOpenListNotifyConflictStart            ; RB-tree search/insert entry
bp fileinfo+0x13dfa                                    ; unpatched root read #1 (mov rax,[r15])
bp fileinfo+0x13ea1                                    ; unpatched root read #2 (mov rdx,[r15])
bp fileinfo+0x13e62                                    ; ExAllocatePoolWithTag(NonPagedPoolNx, 0x30, 'FINc')
bp fileinfo+0x13eee                                    ; RtlRbInsertNodeEx
bp fileinfo!FIPfNotifiedContextsDelete                 ; per-node free (ExFreePoolWithTag)
```

### What to inspect

| Stop | Register / memory | Why |
|---|---|---|
| `fileinfo+0x13dfa` | `r15` = tree header; `r15[0]` = root; `byte [r15+8]` = `Encoded`/`Min` union | Confirms `Encoded` bit is 0: `db (@r15+8) L1` shows an 8-byte-aligned `Min` pointer, bit 0 clear. The root read is used as-is only because encoding is off. |
| `fileinfo+0x13e62` | `edx=0x30`, `ecx=0x200`, `r8d=0x634E4946` | Allocation parameters for the `'FINc'` nodes. |
| `FIPfNotifiedContextsDelete` | `rcx` = node being freed | The teardown frees every node of the local tree within the same call; no node outlives the walk. |

### Structure layout

```text
RTL_RB_TREE (arg4 / r15):
  +0x00  Root                     (read plainly in unpatched; decoded in patched only if Encoded)
  +0x08  Min / Encoded union      bit 0 = Encoded (always 0 here: aligned Min pointer)

RB-tree node (0x30 bytes, tag 'FINc'):
  +0x00  Left child   (XOR-encoded only when Encoded is set — never here)
  +0x08  Right child  (XOR-encoded only when Encoded is set — never here)
  +0x18  Key (int64)
  +0x20  Data (16 bytes)

Input work-item (list element, rbx):
  +0x28  Callback record (rsi = [rbx+0x28]):
           [0x00] fn ptr (called via kCFG at 0x1C0013E46)
           [0x08] key
```

---

## 8. Changed Functions — Full Triage

| Function | Similarity | Change type | Note |
|---|---|---|---|
| `FIPfOpenListNotifyConflictStart` (`@0x1C0013D34` → `@0x1C0013D04`) | 0.8892 | not security-relevant | Adds two `if (Encoded) root ^= &tree` decode blocks at the two root reads, mirroring the child decode already present in both builds. Dead branch: `Encoded` is never set. Remaining delta is register reallocation. |
| `FIPfFileFSOpStart` (`@0x1C000C9D0` → `@0x1C000C1F0`) | 0.8261 | not security-relevant | Same root-decode added in the local-tree teardown walk. Local stack tree; `Encoded` never set. |
| `FIPfVolumeRundownFilePrefetchStart` (`@0x1C000FBEC` → `@0x1C00110CC`) | 0.9305 | not security-relevant | Same root-decode added in its teardown walk; minor local-variable layout shuffle. Local stack tree; `Encoded` never set. |
| `FIPfVolumeRundownAllPrefetchStart` (`@0x1C001462C` → `@0x1C001461C`) | 0.9109 | not security-relevant | Same root-decode added in its teardown walk; minor local-variable layout shuffle. Local stack tree; `Encoded` never set. |

All four changes are the same edit applied consistently: extend the encoded-RB-tree decode to the root pointer. The local-variable shuffles in the callers are compiler side-effects of the added block and carry no behavioral significance.

---

## 9. Unmatched Functions

None. The patch neither adds nor removes functions; it is a localized four-function edit.

---

## 10. Confidence & Caveats

- **Confidence:** High that this is not a security fix. The added code is guarded by bit 0 of the `RTL_RB_TREE` `Min`/`Encoded` field; that field is only written by `RtlRbInsertNodeEx` (storing an 8-byte-aligned `Min` node, bit 0 = 0) and is never explicitly set to enable encoding. The trees are zero-initialized per-call local stack structures, so both the pre-existing child decode and the new root decode are unreachable.
- **Verified facts:**
  - Exactly four functions differ; every difference is the same root-decode addition plus register/layout churn.
  - The tree header is passed to `RtlRbInsertNodeEx` as its first argument, confirming it is an `RTL_RB_TREE` (`Root` at `+0x00`, `Min`/`Encoded` union at `+0x08`).
  - The driver never writes `tree+0x08`; there is no `RtlRbInitializeTree` and no `RtlRbRemoveNode` in either build (teardown is by hand), and the only `RtlRbInsertNodeEx` call is inside `FIPfOpenListNotifyConflictStart`.
  - Node allocation: `ExAllocatePoolWithTag(NonPagedPoolNx, 0x30, 'FINc'=0x634E4946)` at `0x1C0013E62`.
  - The indirect call at `0x1C0013E46` targets a work-item callback (`[rbx+0x28]`), not a tree node, and is kCFG-guarded.
- **Bottom line:** Correct-direction, dormant defense-in-depth / correctness-completion of the RB-tree root pointer-encoding. No reachable use-after-free and no attacker primitive. Not security-relevant.
