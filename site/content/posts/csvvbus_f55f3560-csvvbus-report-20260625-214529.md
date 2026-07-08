Title: csvvbus.sys — Use-after-free from unsynchronized EncryptionManager access (CWE-416) fixed
Date: 2026-06-25
Slug: csvvbus_f55f3560-csvvbus-report-20260625-214529
Category: Corpus
Author: Argus
Summary: KB5073723
Severity: High

## 1. Overview

*   **Unpatched Binary:** `csvvbus_unpatched.sys`
*   **Patched Binary:** `csvvbus_patched.sys`
*   **Overall Similarity Score:** 0.959
*   **Diff Statistics:**
    *   Matched Functions: 256
    *   Changed Functions: 7
    *   Identical Functions: 249
    *   Unmatched Functions: 0 (both directions)
*   **Verdict:** The patch changes two areas of the Windows Cluster Shared Volume (CSV) Bus Driver. The security-significant fix is a Time-of-Check to Time-of-Use (TOCTOU) race condition that could lead to a Use-After-Free (UAF) of the `EncryptionManager` object, now fixed by acquiring `SigningLock` in shared mode before the access (High). The second change is a CWE-190 integer overflow in the IOCTL property-parsing bounds check; it is a bounds-check bypass only, because the same oversized value that overflows the check is also the allocation size and forces a failing allocation, so no memory corruption is reachable from this path. That second change is therefore a low-severity hardening fix, not a reachable memory-safety bug.

## 2. Vulnerability Summary

### Finding 1: Integer Overflow in Property-Parsing Bounds Check (Hardening)
*   **Severity:** Low
*   **Vulnerability Class:** CWE-190 (Integer Overflow or Wraparound) - bounds-check bypass
*   **Affected Function:** `VxVolumerSetStorageProp` (unpatched @ `0x1C0009D54`, patched @ `0x1C0009DAC`)
*   **Root Cause:** The `VxVolumerSetStorageProp` function processes variable-length property arrays from IOCTL input. The loop contains a bounds check that verifies if the remaining input buffer can hold the current entry: `if (remaining < size + 8) break;`. The `size + 8` computation is performed using 32-bit arithmetic without overflow detection (`add eax, 8` at `0x1C0009FD4`, and again in the do-while continuation at `0x1C000A1F8`). If an attacker supplies a `size` value >= `0xFFFFFFF8` at offset `+0xC` of the structure, the addition wraps to a small integer (`0` to `7`), bypassing the bounds check.
*   **Exploitability:** The same `size` value that triggers the overflow (>= `0xFFFFFFF8`) is also passed to `WdfMemoryCreate` as the allocation size, so that ~4GB allocation fails (`js 0x1C000A204`) before the `memset`/`memmove` at `0x1C000A064`/`0x1C000A078` run; the loop advance is separately bounds-checked. The demonstrable effect is a bounds-check bypass, not a directly reachable pool overflow. This is a genuine CWE-190 hardening gap that the patch closes with an explicit overflow guard.
*   **Entry Point & Data Flow:**
    1. Attacker sends `IOCTL 0x7780064` via `DeviceIoControl` to `\Device\CSVVolume%d` or `\Device\VClusBus`.
    2. The WDF callback `VxVolumeEvtIoDeviceControl` handles the request.
    3. Execution is dispatched to `VxVolumerSetStorageProp`.
    4. The function parses the malicious input buffer and bypasses the remaining-bytes bounds check; the subsequent allocation of the same oversized value fails, so no copy occurs.

### Finding 2: TOCTOU Race Leading to Use-After-Free (UAF)
*   **Severity:** High
*   **Vulnerability Class:** CWE-367 (Time-of-Check Time-of-Use) leading to CWE-416 (Use-After-Free)
*   **Affected Function:** `CsvCamSetSecurityInfoSafe`
*   **Root Cause:** The function reads and dereferences the global `EncryptionManager` pointer without holding the `SigningLock`. A concurrent thread can trigger an exclusive lock path that frees the `EncryptionManager` object and replaces it. The unprotected thread may then attempt to dereference a dangling (freed) pointer.
*   **Exploitability:** If a concurrent thread frees `EncryptionManager` during the unsynchronized read, the victim thread dereferences a freed pool object (reading `+0x20` and the `+0x18` pointer). Should the freed allocation be reclaimed before the dereference, the values read come from whatever reoccupied the block, so the impact ranges from a kernel crash to information disclosure via the `memcmp`. A reliable read/write primitive is not demonstrated and would depend on paged-pool reclaim reliability.
*   **Entry Point & Data Flow:**
    1. An attacker opens concurrent handles to `\Device\VClusBus`.
    2. Thread A sends an IOCTL triggering `VxBusControlEvtIoDeviceControl`, which routes to `CsvCamSetSecurityInfoSafe` with a non-zero encryption type. This enters the unprotected read path.
    3. Thread B simultaneously triggers the `EncryptionManager` replacement path (exclusive lock).
    4. Thread A dereferences the now-freed `EncryptionManager` pointer, causing the UAF.

## 3. Pseudocode Diff

### Finding 1: `VxVolumerSetStorageProp`
*Highlighted lines show the missing integer overflow check and the resulting dangerous `memcpy`.*

```c
// --- UNPATCHED (Vulnerable) ---
do {
    uint32_t remaining = end_ptr - current_ptr;
    uint32_t attacker_size = *(uint32_t*)(current_ptr + 0xC);
    
    // *** MISSING INTEGER OVERFLOW CHECK ***
    if (remaining < attacker_size + 8) 
        break; 

    // allocation uses attacker_size (>= 0xFFFFFFF8 to overflow) -> ~4GB alloc FAILS here,
    // so the copy below is not reached for overflow-triggering sizes
    WdfMemoryCreate(..., attacker_size, &arg_18, &arg_8);
    memset(arg_8, 0, attacker_size);
    memmove(arg_8, current_ptr + 8, attacker_size);

} while ( ... );

// --- PATCHED (Fixed) ---
do {
    uint32_t remaining = end_ptr - current_ptr;
    uint32_t attacker_size = *(uint32_t*)(current_ptr + 0xC);
    
    uint32_t required = attacker_size + 8;
    if (required < attacker_size) { // *** OVERFLOW DETECTED ***
        return STATUS_INTEGER_OVERFLOW; // 0xC0000095
    }
    if (remaining < required) 
        break; 
        
    WdfMemoryCreate(..., attacker_size, &arg_18, &arg_8);
    memset(arg_8, 0, attacker_size);
    memmove(arg_8, current_ptr + 8, attacker_size);

} while ( ... );
```

### Finding 2: `CsvCamSetSecurityInfoSafe`
*Highlighted lines show the unprotected dereference in the unpatched version and the added locks in the patched version.*

```c
// --- UNPATCHED (Vulnerable) ---
if (encryption_type_nonzero) {
    // *** NO LOCK HELD ***
    void* enc_manager = EncryptionManager; 
    if (enc_manager) {
        // *** RACE WINDOW / UAF ***
        uint32_t size = *(uint32_t*)(enc_manager + 0x20); 
        if (input_type == size) {
            memcmp(input_data, *(void**)(enc_manager + 0x18), size);
        }
    }
}

// --- PATCHED (Fixed) ---
if (encryption_type_nonzero) {
    KeEnterCriticalRegion();
    // *** LOCK ACQUIRED ***
    ExAcquireResourceSharedLite(SigningLock, TRUE); 
    
    void* enc_manager = EncryptionManager; 
    if (enc_manager) {
        // *** SAFE DEREF ***
        uint32_t size = *(uint32_t*)(enc_manager + 0x20); 
        if (input_type == size) {
            memcmp(input_data, *(void**)(enc_manager + 0x18), size);
        }
    }
    ExReleaseResourceLite(SigningLock);
    KeLeaveCriticalRegion();
}
```

## 4. Assembly Analysis

### Finding 1: `VxVolumerSetStorageProp`
The vulnerability exists in the loop bounds check. The unpatched code relies on a naive `add eax, 0x8` which wraps in 32-bit arithmetic.

```assembly
; --- UNPATCHED (loop-top bounds check) ---
0x1c0009fd0: mov     eax, [r8+0xc]     ; Load attacker-controlled size
0x1c0009fd4: add     eax, 0x8          ; *** VULNERABLE: wraps if size >= 0xFFFFFFF8 ***
0x1c0009fd7: cmp     r15d, eax         ; Compare remaining buffer vs wrapped size+8
0x1c0009fda: jb      0x1c000a237       ; Bypassed! (same naive add repeats at 0x1c000a1f8)

; --- PATCHED (single guarded check at 0x1c000a02b) ---
0x1c000a02b: mov     ecx, [r8+0xc]     ; Load attacker-controlled size
0x1c000a02f: or      edx, 0xffffffff   ; Sentinel = MAX_UINT
0x1c000a032: lea     eax, [rcx+0x8]    ; Compute size + 8
0x1c000a035: cmp     eax, ecx          ; *** OVERFLOW CHECK: is result < original? ***
0x1c000a037: cmovnb  edx, eax          ; Only use result if no overflow
0x1c000a03a: sbb     edi, edi          ; Capture carry flag for STATUS_INTEGER_OVERFLOW
0x1c000a03c: and     edi, 0xc0000095   ; Return error if wrap occurred
0x1c000a044: jb      0x1c000a2a6       ; overflow -> STATUS_INTEGER_OVERFLOW
```

### Finding 2: `CsvCamSetSecurityInfoSafe`
The unpatched code reads the global pointer and dereferences it *before* the `SigningLock` is acquired.

```assembly
; --- UNPATCHED (fn @ 0x1c0018450) ---
0x1c00184a4: mov     rdx, cs:EncryptionManager ; *** VULNERABLE: read EncryptionManager WITHOUT LOCK ***
0x1c00184ae: test    rdx, rdx
0x1c00184b1: je      0x1c00184e0
0x1c00184b3: mov     eax, [rdx+0x20]           ; *** deref +0x20 without lock (UAF read) ***
0x1c00184bb: mov     rdx, [rdx+0x18]           ; deref +0x18 (Buf2)
0x1c00184c6: call    memcmp
; (exclusive-lock free/replace of EncryptionManager is at 0x1c0018544)

; --- PATCHED (fn @ 0x1c00172d0) ---
0x1c001732d: mov     rbx, cs:SigningLock
0x1c0017337: call    KeEnterCriticalRegion
0x1c0017343: mov     rcx, [rbx]
0x1c0017346: mov     dl, r15b                  ; Wait=1
0x1c0017349: call    ExAcquireResourceSharedLite ; *** LOCK ADDED before the read ***
0x1c0017355: mov     rdx, cs:EncryptionManager ; NOW safely read EncryptionManager
0x1c0017361: mov     eax, [rdx+0x20]           ; safe deref
0x1c001738e: mov     rcx, cs:SigningLock
0x1c0017398: call    ExReleaseResourceLite
0x1c00173a4: call    KeLeaveCriticalRegion
```

## 5. Trigger Conditions

### Finding 1: Integer Overflow Bounds-Check Bypass
1. Obtain a handle to the CSV VBus device (e.g., `\Device\CSVVolume0` or `\Device\VClusBus`).
2. Craft an input buffer of at least `0x10` bytes. 
3. The buffer must be structured as a property entry array:
    *   Offset `0x0`: `PropertyType` (DWORD) - set to a valid type (e.g., `0x4`).
    *   Offset `0x4`: `NextEntryOffset` (DWORD) - set to `0x0` (or `0x18` to force loop continuation).
    *   Offset `0x8`: `Reserved` (DWORD) - `0x0`.
    *   Offset `0xC`: `DataSize` (DWORD) - **Set this to `0xFFFFFFF8`**.
    *   Offset `0x10`: `Data` (bytes).
4. Send the buffer via `DeviceIoControl` using `dwIoControlCode = 0x7780064` (`METHOD_BUFFERED`).
5. The bounds check `size + 8` wraps to `0` and is bypassed. The subsequent `WdfMemoryCreate` is then called with the full `0xFFFFFFF8` size, which fails (allocation too large), so the function returns `STATUS_INSUFFICIENT_RESOURCES` rather than corrupting memory. The observable effect is the bypassed remaining-bytes check.

### Finding 2: TOCTOU Race Condition (UAF)
1. Open two concurrent handles to `\Device\VClusBus`.
2. **Thread A:** Send an IOCTL that routes to `CsvCamSetSecurityInfoSafe`. The input buffer (`arg1`) must be `>= 0x10` bytes, and `arg1[2]` (the encryption type) must be non-zero to enter the vulnerable code path.
3. **Thread B:** Repeatedly trigger the IOCTL or internal function that replaces the `EncryptionManager` object (the exclusive lock path). This frees the old object.
4. Execute both threads in a tight loop, manipulating thread priorities and CPU affinities to widen the race window.
5. The bug is triggered when Thread B frees `EncryptionManager` exactly between Thread A's read of the pointer and Thread A's dereference of `+0x18`/`+0x20`. 

## 6. Exploit Primitive & Development Notes

### Finding 1 Primitive: Bounds-Check Bypass (CWE-190)
*   **Primitive:** Defeating the `remaining < size + 8` guard. In this code path, however, the allocation size is `DataSize` itself (not `size + 8`), and to overflow the check `DataSize` must be >= `0xFFFFFFF8`. That same value is passed to `WdfMemoryCreate`, so the ~4GB allocation fails (`js 0x1C000A204` -> `STATUS_INSUFFICIENT_RESOURCES`) and the `memset`/`memmove` never execute. The loop advance by `NextEntryOffset` is separately bounds-checked against the buffer end.
*   **Weaponization:** Note that `DataSize` values such as `0xFFFFFFF9` do NOT produce a small allocation - only `size + 8` wraps small; the allocation still uses the full `DataSize` (~4GB) and fails. A controlled out-of-bounds read/write is therefore not directly reachable from this function; the observable result is a bypassed remaining-bytes check followed by a failed allocation.
*   **Mitigations:** The patch adds an explicit overflow guard at `0x1C000A02B` returning `STATUS_INTEGER_OVERFLOW`. This is a hardening fix rather than a fix for a demonstrated corruption primitive.

### Finding 2 Primitive: Use-After-Free (UAF)
*   **Primitive:** Kernel UAF. The `EncryptionManager` object is a `0x28`-byte paged-pool allocation (tag `0x41435643`, from `ExAllocatePoolWithTag` at `0x1C00184E5`). A dereference of the object after a concurrent free reads freed pool memory at `+0x20` (a size) and `+0x18` (a pointer subsequently passed to `memcmp`).
*   **Demonstrable impact:** If the freed allocation is reclaimed before the dereference, the values read at `+0x20`/`+0x18` are no longer the original object's, so the outcome ranges from a kernel crash (page fault / verifier bugcheck) to reading data from whatever reoccupied the freed block. A specific, reliable read/write primitive is not demonstrated here and would depend on reclaim reliability for paged pool.
*   **Mitigations:** The patch closes the window by taking `SigningLock` shared before the read, which is mutually exclusive with the exclusive-lock replace path that frees the object.

## 7. Debugger PoC Playbook

### Finding 1: `VxVolumerSetStorageProp`
*   **Breakpoints:**
    *   `bp csvvbus_unpatched!VxVolumerSetStorageProp` (Entry point. Inspect `rcx` for IRP/WDF Request).
    *   `ba e1 0x1c0009fd0` (The vulnerable bounds check).
*   **What to inspect:**
    *   At `0x1c0009fd0`: Inspect `eax` after the `mov`. It will hold the attacker-controlled `DataSize` (`0xFFFFFFF8`).
    *   After `add eax, 0x8` (`0x1c0009fd4`): `eax` will wrap to `0x00000000`.
    *   Check `r15d` (remaining buffer size). The `cmp r15d, eax` (`0x1c0009fd7`) check will pass since `r15d > 0`.
*   **Key instructions/offsets:**
    *   `0x1c0009fd4`: The vulnerable `add eax, 0x8` instruction (repeated at `0x1c000a1f8`).
    *   `0x1c000a048`: `WdfMemoryCreate` call - fails for the oversized `DataSize`.
    *   `0x1c000a078`: The `memmove` (only reached if that allocation succeeds, which it does not for overflow-triggering sizes).
*   **Trigger setup:** Send an IRP via `DeviceIoControl` to the CSV device handle. IOCTL = `0x7780064`. Input buffer length `>= 0x10`. Byte offset `0xC` must be `0xF8FFFFFF` (Little Endian `0xFFFFFFF8`).
*   **Expected observation:** Upon hitting `0x1c0009fd0` and stepping over, `eax` wraps and the break is not taken. Execution proceeds to `WdfMemoryCreate` (`0x1c000a048`) with size `0xFFFFFFF8`, which fails; `js 0x1c000a204` is taken, `esi = 0xC000009A`, and the function returns without reaching the copy.

### Finding 2: `CsvCamSetSecurityInfoSafe`
*   **Breakpoints:**
    *   `ba e1 0x1c00184a4` (the lock-less read of `EncryptionManager`).
    *   `ba e1 0x1c00184b3` (the dereference point).
*   **What to inspect:**
    *   At `0x1c00184a4`: `rdx` holds the pointer read from the global `EncryptionManager`.
    *   At `0x1c00184b3`: `rdx` is being dereferenced (`+0x20`, then `+0x18`). Execute `!address rdx` or `!pool rdx` to check if the pool has been freed.
*   **Key instructions/offsets:**
    *   `0x1c00184a4`: The unprotected `mov rdx, cs:EncryptionManager`.
    *   `0x1c00184b3`: The `mov eax, [rdx+0x20]` instruction that triggers the UAF read.
*   **Trigger setup:** Multi-threaded environment. Thread A enters `CsvCamSetSecurityInfoSafe` with a valid `>= 0x10` buffer and `arg1[2] != 0`. Thread B triggers the exclusive lock cleanup path that frees the pool.
*   **Expected observation:** With Driver Verifier (Special Pool) enabled on `csvvbus.sys`, if `EncryptionManager` is freed between the read at `0x1c00184a4` and the dereference at `0x1c00184b3`, that dereference of the freed allocation triggers a `0xC4` (DRIVER_VERIFIER_DETECTED_VIOLATION) or `0x50` (PAGE_FAULT_IN_NONPAGED_AREA) BugCheck, confirming the Use-After-Free.

## 8. Changed Functions — Full Triage

### Security Relevant
*   **`CsvCamSetSecurityInfoSafe`** (Sim: 0.9202, High): TOCTOU race condition - unpatched reads/derefs `EncryptionManager` with no `ERESOURCE` held (`0x1C00184A4`); patched wraps the read in `ExAcquireResourceSharedLite` (`0x1C0017349`). The `if (!r15)` Global-Seq branch also gains a lock in the patched build.
*   **`VxVolumerSetStorageProp`** (Sim: 0.9173, Low): CWE-190 integer overflow in the IOCTL property-parsing bounds check (`add eax, 8` at `0x1C0009FD4`); patched with an overflow guard at `0x1C000A02B`. In this path the overflow-triggering size also forces a failing allocation, so it is a bounds-check bypass / hardening fix rather than a reachable pool overflow.

### Behavioral / Minor Changes
*   **`VxVolumeEvtIoDeviceControl`** (Sim: 0.8521): Dispatch/switch tree reordered and WPP trace GUIDs updated. The handler functions (VxVolumerActivateNetworkPath, VxVolumerEnableCache, VxVolumerDisableCache, VxVolumerPurgeCache, VxVolumerCacheConfig) are NOT removed - each still has a function header in both binaries, so any apparent case removal is a reordering/relocation. No direct security impact.
*   **`RtlUnicodeStringPrintf`** (Sim: 0.6089): Inlined the RTL string validation logic rather than calling it externally. Functionally equivalent.

### Cosmetic / Optimization (Collapsed)
The following functions exhibited only minor register allocation shifts, variable renaming, or hardcoded memory address relocations due to build environment differences. These do not present security surfaces:
*   `VxVolumeSetTargetPath` (Sim: 0.9425)
*   `AddChildPdoCallback` (Sim: 0.9749)
*   `RtlStringLengthWorkerW` (Sim: 0.9890)

## 9. Unmatched Functions

There were no unmatched functions added or removed in this diff (`unmatched_unpatched: 0`, `unmatched_patched: 0`). All mitigations were applied inline to existing functions.

## 10. Confidence & Caveats

*   **Confidence:** **High**. The assembly clearly identifies the lack of overflow arithmetic (`add eax, 0x8` bypassing bounds) and the missing `ExAcquireResourceSharedLite` call prior to global pointer dereferencing. The vulnerability classes are standard and well-understood.
*   **Assumptions/Caveats:**
    *   The IOCTL codes (e.g., `0x7780064`) and exact memory addresses are derived from the provided diff context. Base addresses will shift depending on the loaded module base (`csvvbus.sys`), so relative offsets (e.g., `+0x23c`) should be used in debuggers rather than absolute addresses.
    *   Exploiting these vulnerabilities requires a system to be configured as a Cluster Shared Volume (CSV) node, or at least having the `csvvbus.sys` driver loaded and exposed to non-administrative or malicious local users.
    *   The exact path to trigger the `EncryptionManager` free (Thread B) in Finding 2 was inferred from standard driver teardown/replacement patterns; an analyst will need to trace cross-references to the `SigningLock` global to identify the exact exclusive-lock IOCTL trigger required for reliable PoC execution.
