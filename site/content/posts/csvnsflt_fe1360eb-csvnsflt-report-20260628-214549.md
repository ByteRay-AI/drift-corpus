Title: csvnsflt.sys — Use-After-Free race from unlocked global reads in CsvCamSetSecurityInfo (CWE-416, CWE-362) fixed
Date: 2026-06-28
Slug: csvnsflt_fe1360eb-csvnsflt-report-20260628-214549
Category: Corpus
Author: Argus
Summary: KB5078752
Severity: High
KBDate: 2026-03-10

## 1. Overview

* **Unpatched Binary:** `csvnsflt_unpatched.sys`
* **Patched Binary:** `csvnsflt_patched.sys`
* **Overall Similarity:** 0.9912
* **Diff Statistics:** 137 matched functions, 1 changed function, 136 identical functions, 0 unmatched functions in either direction.
* **Verdict:** The patch fixes a use-after-free that is caused by a lock imbalance in `CsvCamSetSecurityInfo`. Two code regions in the unpatched build read and update global objects with no lock, while other regions of the same function free and replace those objects while holding `SigningLock` exclusive. The patch adds a shared-lock acquire/release around both previously-unlocked regions so readers are serialized against the exclusive writer.

## 2. Vulnerability Summary

* **Severity:** High
* **Vulnerability Class:** Use-After-Free caused by a data race / missing synchronization (CWE-416, CWE-362)
* **Affected Function:** `CsvCamSetSecurityInfo @ 0x1C0013304`

**Root Cause:**
`CsvCamSetSecurityInfo` manages two process-wide objects, both protected by the same lock `SigningLock` (an `RWLock` wrapping an `ERESOURCE`):

* `EncryptionManager`, a pointer to an `Encryption` object. This is a `0x28`-byte PagedPool allocation (tag `0x41435643`) that holds BCrypt algorithm/key/hash handles and buffers. It is freed by `Encryption::\`scalar deleting destructor'`, which also releases its embedded BCrypt handles and buffers.
* `ReplayCacheManagerObject`, a `0x1010`-byte PagedPool allocation (tag `0x41435643`) that holds the global sequence-number state. It is freed by `ExFreePoolWithTag`.

In the unpatched build two regions of this function touch these globals with no lock held:

1. At `0x1C0013332` the function reads `EncryptionManager` into a register with no lock, then dereferences the captured pointer at `+0x20` (`0x1C0013341`) and `+0x18` (`0x1C0013348`) and passes the `+0x18` field to `memcmp`.
2. At `0x1C0013617` the sequence-number update loop reads `ReplayCacheManagerObject` with no lock, dereferences it at `+0x18`/`+0x10`/`+0x4`, and writes it with `xchg [rbx+0x20]` (`0x1C001363F`) and `lock cmpxchg [rbx+0x18]` (`0x1C0013645`).

Meanwhile, the replacement paths in the same function acquire `SigningLock` **exclusive** (`ExAcquireResourceExclusiveLite`) before freeing the old object and installing a new one: the old `EncryptionManager` is freed at `0x1C0013401`; the old `ReplayCacheManagerObject` is freed at `0x1C001359F`. Because the reader regions hold no lock, a second concurrent invocation can free the object between the moment the pointer is captured and the moment its fields are read or written. The region 1 race is a use-after-free **read** of a freed `Encryption` object; the region 2 race is a use-after-free **write** (interlocked update) into a freed `ReplayCacheManager` object.

The `memcmp` at `0x1C0013353` compares user-supplied bytes against the object's `+0x18` buffer and returns only an equal / not-equal boolean (`memcmp(...) == 0`); it does not return the compared bytes to the caller, so this path is not an information-disclosure channel.

The patch wraps both previously-unlocked regions in `KeEnterCriticalRegion` + `ExAcquireResourceSharedLite(SigningLock)` ... `ExReleaseResourceLite` + `KeLeaveCriticalRegion`, so the reads and the interlocked writes are serialized against the exclusive writer that frees the objects.

**Attacker-Reachable Entry Point & Data Flow:**
1. **User-Mode API:** A caller sends a message with `FilterSendMessage(hPort, buffer, ...)` to the minifilter communication port.
2. **Message Notify Callback:** The registered callback `NfltMessage @ 0x1C0005F60` receives the message. It validates the length, allocates a pool copy (tag `0x634D664E`), `ProbeForRead`s the input, copies it with `memmove`, and switches on the first DWORD.
3. **Opcode Dispatch:** When the first DWORD equals `6` and the message length is `>= 0x14`, the callback calls `CsvCamSetSecurityInfo(buffer+4)` at `0x1C0006299`.
4. **Vulnerable Region:** `CsvCamSetSecurityInfo` performs the unlocked global reads/updates described above.

## 3. Pseudocode Diff

```c
// === UNPATCHED CsvCamSetSecurityInfo @ 0x1C0013304 (region 1: unlocked read) ===
if ( a1[2] != 0 )
{
    v3 = 1;
    // EncryptionManager is read and dereferenced with NO lock held:
    if ( EncryptionManager != nullptr
      && ((v6 = *((_DWORD *)EncryptionManager + 8), a1[2] != v6)          // deref +0x20
            ? (v7 = false)
            : (v7 = memcmp(a1 + 3, *((const void **)EncryptionManager + 3), v6) == 0),  // deref +0x18, boolean result
          v7) )
    {
        v3 = 0;
    }
    else
    {
        // allocate + Encryption::Initialize, then under EXCLUSIVE lock free the old object:
        KeEnterCriticalRegion();
        ExAcquireResourceExclusiveLite(*SigningLock, 1u);
        if ( EncryptionManager != nullptr )
            Encryption::`scalar deleting destructor'(EncryptionManager);   // FREE old object
        EncryptionManager = v9;                                            // install new object
        ExReleaseResourceLite(*SigningLock);
        KeLeaveCriticalRegion();
    }
}
// ... region 2: the sequence-number loop reads/writes ReplayCacheManagerObject with NO lock ...

// === PATCHED CsvCamSetSecurityInfo @ 0x1C0013304 (region 1 now locked) ===
if ( a1[2] > 0 )
{
    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(*SigningLock, 1u);          // NEW: shared lock before the read
    if ( EncryptionManager != nullptr )
    {
        v6 = *((_DWORD *)EncryptionManager + 8);
        if ( a1[2] != v6 )
            v7 = false;
        else
            v7 = memcmp(a1 + 3, *((const void **)EncryptionManager + 3), v6) == 0;
        // ...
    }
    ExReleaseResourceLite(*SigningLock);                    // NEW: release after the read
    KeLeaveCriticalRegion();
}
// ... region 2: the sequence-number loop is likewise wrapped in a shared lock ...
```

## 4. Assembly Analysis

### Unpatched — region 1: unlocked read of `EncryptionManager`
```assembly
00000001C001331C  mov     eax, [rcx+8]                                  ; eax = arg1[2] (user-supplied size field)
00000001C001332A  test    eax, eax
00000001C001332C  jz      loc_1C001342F
00000001C0013332  mov     rdx, cs:?EncryptionManager@@3PEAVEncryption@@EA ; read global with NO lock held
00000001C001333C  test    rdx, rdx
00000001C001333F  jz      short loc_1C001336D
00000001C0013341  mov     ecx, [rdx+20h]                                ; deref of possibly-freed object
00000001C0013344  cmp     eax, ecx
00000001C0013346  jnz     short loc_1C001335F
00000001C0013348  mov     rdx, [rdx+18h]                                ; Buf2 = pointer field of possibly-freed object
00000001C001334C  mov     r8d, ecx                                      ; Size
00000001C001334F  lea     rcx, [rsi+0Ch]                                ; Buf1 = user data
00000001C0013353  call    memcmp                                        ; returns equal/not-equal only (boolean)
```

### Unpatched — the exclusive-lock free that region 1 races
```assembly
00000001C00133D1  mov     rbx, cs:?SigningLock@@3PEAVRWLock@@EA
00000001C00133D8  call    cs:__imp_KeEnterCriticalRegion
00000001C00133E9  call    cs:__imp_ExAcquireResourceExclusiveLite       ; EXCLUSIVE
00000001C00133F5  mov     rcx, cs:?EncryptionManager@@3PEAVEncryption@@EA
00000001C00133FF  jz      short loc_1C0013406
00000001C0013401  call    ??_GEncryption@@QEAAPEAXI@Z                    ; frees old EncryptionManager
00000001C001340D  mov     cs:?EncryptionManager@@3PEAVEncryption@@EA, rdi ; install new object
00000001C0013417  call    cs:__imp_ExReleaseResourceLite
00000001C0013423  call    cs:__imp_KeLeaveCriticalRegion
```

### Unpatched — region 2: unlocked read/update of `ReplayCacheManagerObject`
```assembly
00000001C0013617  mov     edi, [rsi+4]
00000001C001361A  mov     rbx, cs:?ReplayCacheManagerObject@@3PEAV...    ; read global with NO lock held
00000001C0013621  mov     esi, [rbx+18h]                                ; deref of possibly-freed object
00000001C001363F  xchg    rax, [rbx+20h]                                ; write into possibly-freed object
00000001C0013645  lock cmpxchg [rbx+18h], edi                           ; interlocked write into possibly-freed object
```
The old `ReplayCacheManagerObject` is freed under the exclusive lock at `0x1C001359F` (`ExFreePoolWithTag`), which region 2 can race.

### Patched — shared lock added around region 1
```assembly
00000001C001333A  mov     rbx, cs:?SigningLock@@3PEAVRWLock@@EA
00000001C0013344  call    cs:__imp_KeEnterCriticalRegion                ; NEW
00000001C0013356  call    cs:__imp_ExAcquireResourceSharedLite          ; NEW shared lock before the read
00000001C0013362  mov     rdx, cs:?EncryptionManager@@3PEAVEncryption@@EA
00000001C001336E  mov     eax, [rdx+20h]
00000001C0013376  mov     rdx, [rdx+18h]
00000001C0013381  call    memcmp
00000001C00133A4  call    cs:__imp_ExReleaseResourceLite                ; NEW release after the read
00000001C00133B0  call    cs:__imp_KeLeaveCriticalRegion                ; NEW
```

### Patched — shared lock added around region 2
```assembly
00000001C0013641  mov     rbx, cs:?SigningLock@@3PEAVRWLock@@EA
00000001C0013648  call    cs:__imp_KeEnterCriticalRegion                ; NEW
00000001C0013659  call    cs:__imp_ExAcquireResourceSharedLite          ; NEW shared lock before the loop
00000001C0013668  mov     rbx, cs:?ReplayCacheManagerObject@@3PEAV...
00000001C001366F  mov     esi, [rbx+18h]
00000001C001368D  xchg    rax, [rbx+20h]
00000001C0013693  lock cmpxchg [rbx+18h], edi
00000001C00136DD  call    cs:__imp_ExReleaseResourceLite                ; NEW release after the loop
00000001C00136E9  call    cs:__imp_KeLeaveCriticalRegion                ; NEW
```

## 5. Trigger Conditions

1. **Session Establishment:** Obtain a handle to the minifilter communication port via `FilterConnectCommunicationPort`.
2. **Payload Formatting:** Construct a message of at least `0x14` bytes. The first DWORD is the opcode and must equal `6`. Starting at offset `+0x4` the callback passes the buffer to `CsvCamSetSecurityInfo`, which reads its fields at `+0x8` (the size compared against `EncryptionManager+0x20`) and `+0xC` (the bytes passed to `memcmp`).
3. **Race Execution:** Issue concurrent opcode-6 messages.
   * **Reader interleaving:** A message whose size/data match the current `EncryptionManager` keeps execution on the unlocked read path (region 1), and the follow-on sequence-number update (region 2) reads/writes `ReplayCacheManagerObject` unlocked.
   * **Writer interleaving:** A message whose size or data mismatch drives the allocation/replace path, which acquires the exclusive lock and frees the old object before installing a new one.
4. **Timing:** The writer must free the object during the window between the reader capturing the global pointer and dereferencing it (region 1) or performing the interlocked update (region 2).
5. **Observable Effect:** Dereferencing or writing the freed PagedPool object can raise an unhandled kernel exception (for example a page fault when the freed page is unmapped or reclaimed), leading to a bugcheck.

## 6. Impact

* **Primitive:** Kernel use-after-free on PagedPool objects (tag `0x41435643`). Region 1 is a stale **read** of a freed `Encryption` object (fields `+0x20` and `+0x18`, with the `+0x18` value used as a buffer pointer for `memcmp`). Region 2 is a stale **write** (`xchg` and `lock cmpxchg`) into a freed `ReplayCacheManager` object.
* **Not an information-disclosure channel:** The `memcmp` on the region-1 path returns only a boolean equal/not-equal result and does not return the compared memory contents to the caller. The unlocked reads do not surface object bytes to user mode.
* **Reachable impact:** Memory corruption (a stale read of, and stale interlocked writes into, freed pool). The demonstrable consequence is kernel instability / bugcheck (denial of service). Turning this race into privilege escalation would require reclaiming the freed allocation with controlled contents within the race window; that further exploitation is not demonstrated here and depends on pool state and timing not established from the static diff.
* **Reachability caveats:** The trigger assumes a caller can open and send messages to the driver's communication port; the port's security descriptor and the driver's presence (it loads on Cluster Shared Volumes nodes) determine who can reach the code. These should be confirmed on the target configuration.

## 7. Debugger Playbook

This section lists real instruction addresses in the unpatched binary for observing the race. Assume the analysis image base `0x1C0000000`; adjust for the runtime load base.

### Breakpoints
```text
bp csvnsflt_unpatched!NfltMessage                 ; 0x1C0005F60 — message dispatch entry
bp csvnsflt_unpatched!CsvCamSetSecurityInfo       ; 0x1C0013304 — function entry
bp 0x1C0013332                                    ; region 1: unlocked capture of EncryptionManager
bp 0x1C0013341                                    ; region 1: first deref of the captured pointer
bp 0x1C0013401                                    ; exclusive-lock free of the old EncryptionManager
bp 0x1C001361A                                    ; region 2: unlocked read of ReplayCacheManagerObject
bp 0x1C001359F                                    ; exclusive-lock free of the old ReplayCacheManagerObject
```

### What to Inspect
1. **At `NfltMessage` (`0x1C0005F60`):** `rdx` points to the user message; after the internal `memmove` copy, the first DWORD selects the opcode. Confirm opcode `6` routes to `CsvCamSetSecurityInfo`.
2. **At `0x1C0013332` (region-1 capture):** `rdx` receives the current `EncryptionManager` value with no lock held. Set a write breakpoint on the `EncryptionManager` global to observe when a concurrent thread replaces it.
3. **At `0x1C0013401` (free):** `rcx` holds the object being freed. If it equals the value captured at `0x1C0013332` in the racing thread, the region-1 use-after-free is imminent.
4. **At `0x1C0013341` (deref):** A fault here on a freed/unmapped page confirms the region-1 use-after-free fired.
5. **At `0x1C001361A` / `0x1C001363F` (region 2):** Observe the unlocked read and the `xchg`/`lock cmpxchg` writes; racing the free at `0x1C001359F` corrupts freed pool.

### Struct & Offset Notes
* **Message layout:** `[+0x0] opcode` (`6`); the struct at `+0x4` is passed to `CsvCamSetSecurityInfo` as `arg1`, with `arg1[2]` (`+0x8`) the size and `arg1[3]` (`+0xC`) the compared bytes.
* **`Encryption` object:** `+0x20` is the size compared against the user size; `+0x18` is the buffer pointer passed to `memcmp`.
* **`ReplayCacheManager` object:** `+0x18` and `+0x20` are the sequence-number fields updated by the interlocked operations.

## 8. Changed Functions — Full Triage

* **`CsvCamSetSecurityInfo @ 0x1C0013304`** (Similarity: 0.9045 | Change Type: Security Relevant)
  * **Changes:** Added `KeEnterCriticalRegion` + `ExAcquireResourceSharedLite(SigningLock)` ... `ExReleaseResourceLite` + `KeLeaveCriticalRegion` around the `EncryptionManager` read/compare region (previously fully unlocked) and around the `ReplayCacheManagerObject` sequence-number update loop (previously fully unlocked). The exclusive-lock free/replace paths were already locked in the unpatched build; the change closes the reader side of the lock imbalance. The remaining differences are register-allocation shifts caused by the added blocks.

## 9. Unmatched Functions

* **Added:** None.
* **Removed:** None.

## 10. Confidence & Caveats

* **Confidence Level:** High that the change is a genuine synchronization fix. The unpatched build clearly reads and updates `EncryptionManager` and `ReplayCacheManagerObject` without holding `SigningLock`, while the free/replace paths hold it exclusive; the patched build adds a matching shared lock around both regions. Direction is correct (patched is stricter).
* **What is demonstrated:** A reachable kernel use-after-free (stale read of a freed `Encryption` object and stale interlocked writes into a freed `ReplayCacheManager` object) driven by racing concurrent port messages.
* **What is not demonstrated:** A full privilege-escalation chain. The region-1 `memcmp` result is only a boolean and is not an information-leak channel. Converting the use-after-free into controlled memory corruption would require reclaiming the freed pool with attacker-controlled contents inside the race window, which is not established from the static diff.
* **To verify on a live target:** the communication port name and its security descriptor (who may send messages), the exact object sizes for pool reclaim, and the presence of the driver on the target (Cluster Shared Volumes nodes).

DONE
