Title: bowser.sys — Uninitialized paged-pool memory disclosure to user mode (CWE-908, CWE-200) in BowserAllocateName / AddBowserName / AsyncCreateTransportName fixed
Date: 2026-06-25
Slug: bowser_d18adee0-bowser-report-20260625-203554
Category: Corpus
Author: Argus
Summary: KB5073723
Severity: Medium
KBDate: 2026-01-13

### 1. Overview
- **Unpatched Binary:** `bowser_unpatched.sys`
- **Patched Binary:** `bowser_patched.sys`
- **Overall Similarity:** 0.9923
- **Diff Statistics:** 279 matched functions, 276 identical, 3 changed, 0 unmatched in either direction.
- **Verdict:** The patch fixes an uninitialized kernel pool memory disclosure by adding a `memset` to zero each newly allocated `BROWSER_NAME` structure in three functions. In the unpatched build a 4-byte alignment gap inside the name `UNICODE_STRING` is left uninitialized and is later copied to a user-mode output buffer by the name-enumeration path, leaking paged-pool residue.

### 2. Vulnerability Summary
- **Severity:** Medium
- **Vulnerability Class:** Uninitialized Memory / Kernel Information Disclosure (CWE-908, CWE-200)
- **Affected Functions:** `BowserAllocateName`, `AddBowserName`, `AsyncCreateTransportName`
- **Root Cause:** The unpatched driver allocates pool memory for the `BROWSER_NAME` structure via `ExAllocatePoolWithTag(PagedPool, NameLength + 0x42, 'LBbn')` but does not zero the allocation before initializing selected fields (dword at `0x00`, dword at `0x04`, list linkage at `0x08`/`0x10`, list head at `0x18`/`0x20`, the name `UNICODE_STRING` at `0x28` — `Length` at `0x28`, `MaximumLength` at `0x2a`, `Buffer` at `0x30` — a dword at `0x38`, and the inline name buffer at `0x40`). Two gaps are never written: the 4-byte `UNICODE_STRING` alignment padding at `0x2C-0x2F` (between `MaximumLength` at `0x2a` and `Buffer` at `0x30`), and the 4-byte gap at `0x3C-0x3F` (between the dword at `0x38` and the inline buffer at `0x40`). Both retain stale paged-pool contents. When a name is later enumerated, the worker copies the 16-byte name `UNICODE_STRING` block at offsets `0x28-0x37` verbatim into each output record; that 16-byte copy includes the uninitialized `0x2C-0x2F` bytes, which are then forwarded to the caller's output buffer. The `0x3C-0x3F` gap is not read by the enumeration path and is not shown to reach user mode. The patch inserts `memset(buffer, 0, NameLength + 0x42)` immediately after each allocation, so the disclosed bytes read as zero.
- **Attacker Entry Point:** `\Device\LanmanDatagramReceiver` via NtDeviceIoControlFile.
- **Call Chain:**
  1. User-mode process opens `\Device\LanmanDatagramReceiver` and calls `DeviceIoControl` / `NtDeviceIoControlFile`.
  2. `BowserFsdDeviceIoControlFile` (0x1c0010ad0) receives the `IRP_MJ_DEVICE_CONTROL` IRP.
  3. `BowserCommonDeviceIoControlFile` (0x1c0010b60) computes `IoControlCode - 0x130007` at `0x1c0010f86` and performs the indirect switch jump at `0x1c0010fa9`.
  4. IoControlCode `0x13000C` reaches the `AddBowserName` case at `0x1c00111e1` and calls `AddBowserName` (0x1c0012330) at `0x1c0011253`, which allocates the structure and leaves the gaps uninitialized. The same allocation-without-zeroing pattern exists in `BowserAllocateName` (0x1c0017718) and `AsyncCreateTransportName` (0x1c000f4d0).
  5. IoControlCode `0x130017` reaches the `EnumNames` case at `0x1c0011197` and calls `EnumNames` (0x1c0019e50) at `0x1c00111bf` → `BowserEnumerateNamesInDomain` (0x1c0017a7c) → `EnumerateNamesTransportNameWorker` (0x1c0017bf0), which copies the name `UNICODE_STRING` (including the `0x2C-0x2F` gap) into the user-mode output buffer.

### 3. Pseudocode Diff
Below is the core allocation logic in the vulnerable functions. The unpatched version selectively writes to a newly allocated buffer, whereas the patched version inserts a `memset` before writing.

```c
// UNPATCHED BowserAllocateName @ 0x1C0017718 (decompilation)
PoolWithTag = ExAllocatePoolWithTag(PagedPool, SourceString->Length + 66LL, 0x6E62424Cu);
Name = (__int64)PoolWithTag;
if (PoolWithTag != nullptr) {
    // *** MISSING: no memset(PoolWithTag, 0, SourceString->Length + 66) here ***
    *PoolWithTag = 4194310;                        // offset 0x00 (0x400006)
    PoolWithTag[1] = 1;                            // offset 0x04
    // ... list linkage at 0x08/0x10, list head at 0x18/0x20 ...
    *(_DWORD *)(Name + 56) = a2;                   // offset 0x38
    *(_QWORD *)(Name + 48) = Name + 64;            // offset 0x30 -> inline buffer at 0x40
    *(_WORD *)(Name + 42) = SourceString->Length + 2; // offset 0x2a (MaximumLength)
    RtlCopyUnicodeString((PUNICODE_STRING)(Name + 40), SourceString); // sets Length@0x28, name@0x40
    // UNICODE_STRING padding at 0x2C-0x2F and the gap at 0x3C-0x3F are never written
}

// PATCHED BowserAllocateName @ 0x1C0017738 (decompilation)
PoolWithTag = ExAllocatePoolWithTag(PagedPool, SourceString->Length + 66LL, 0x6E62424Cu);
Name = (__int64)PoolWithTag;
if (PoolWithTag != nullptr) {
    memset(PoolWithTag, 0, SourceString->Length + 66LL); // *** NEW: zeros entire allocation ***
    *(_DWORD *)Name = 4194310;
    *(_DWORD *)(Name + 4) = 1;
    // ... identical field initialization follows ...
}
```

### 4. Assembly Analysis
The vulnerability is evident in the assembly of `BowserAllocateName` @ `0x1c0017718`. The function requests pool memory and immediately begins initializing fields without zeroing it.

**Unpatched Vulnerable Assembly:**
```assembly
0x1c0017788  movzx   edx, word [rsi]           ; edx = NameLength (UNICODE_STRING.Length)
0x1c001778b  mov     r8d, 0x6e62424c           ; r8d = pool tag 'LBbn'
0x1c0017791  add     rdx, 0x42                 ; rdx = NameLength + 0x42 (total alloc size)
0x1c0017795  mov     ecx, edi                  ; ecx = PoolType
0x1c0017797  call    qword [rel 0x1c000c018]   ; ExAllocatePoolWithTag(PagedPool, rdx, 'LBbn')
0x1c001779e  nop     dword [rax+rax]
0x1c00177a3  mov     rbx, rax                  ; rbx = allocated buffer
0x1c00177a6  test    rax, rax
0x1c00177a9  jne     0x1c00177b5               ; If success, jump to initialization

; ===== VULNERABILITY: NO memset HERE =====================
0x1c00177b5  mov     dword [rax], 0x400006     ; [buf+0x00] initialized
0x1c00177bb  lea     rdx, [rel 0x1c00094a0]    
0x1c00177c2  mov     dword [rax+0x4], edi      ; [buf+0x04] initialized
0x1c00177c5  lea     rcx, [rbx+0x8]            
0x1c00177c9  add     rax, 0x18                 
0x1c00177cd  mov     qword [rax+0x8], rax      ; [buf+0x20] initialized
0x1c00177d1  mov     qword [rax], rax          ; [buf+0x18] initialized
0x1c00177d4  mov     dword [rbx+0x38], r15d    ; [buf+0x38] initialized
; Padding at offsets 0x2C-0x2F and 0x3C-0x3F remains uninitialized
```

**Patched Equivalent (`BowserAllocateName` @ `0x1c0017738`):**
```assembly
0x1c00177c3  mov     rbx, rax                  ; rbx = allocated buffer
0x1c00177c6  test    rax, rax
0x1c00177c9  jne     0x1c00177d5               ; if allocated, go to init
0x1c00177d5  movzx   r8d, word [rsi]           ; r8 = NameLength
0x1c00177d9  xor     edx, edx                  ; fill value = 0
0x1c00177db  add     r8, 0x42                  ; r8 = NameLength + 0x42
0x1c00177df  mov     rcx, rbx                  ; rcx = buffer
0x1c00177e2  call    0x1c0002200               ; memset(buffer, 0, NameLength + 0x42)
0x1c00177e7  mov     dword [rbx], 0x400006     ; field initialization from a zeroed base
```
The `memset` at `0x1c00177e2` targets `memset` at `0x1c0002200`. The same insertion appears in `AsyncCreateTransportName` (call at `0x1c000f569`) and `AddBowserName` (call at `0x1c00126e5`). Of the two uninitialized gaps, only the `0x2C-0x2F` `UNICODE_STRING` padding is demonstrably copied to user mode by the enumeration worker.

### 5. Trigger Conditions
To trigger the vulnerability and leak memory, an attacker must:
1. **Obtain a Handle:** Open a handle to `\Device\LanmanDatagramReceiver`. The `AddBowserName` dispatch case is additionally gated by `BowserSecurityCheck` (at `0x1c001123e`) unless the caller is a system thread; the `EnumNames` case is not gated by `BowserSecurityCheck` in its own dispatch block.
2. **Allocate Uninitialized Structure:** Send IoControlCode `0x13000C`, which the dispatcher routes to the `AddBowserName` case. This allocates the `BROWSER_NAME` structure without zeroing it, so the `0x2C-0x2F` gap holds whatever previously occupied that paged-pool offset.
3. **Exfiltrate Data:** Send IoControlCode `0x130017`, which the dispatcher routes to the `EnumNames` case, providing a user-mode output buffer.
4. **Confirmation:** Parse the returned records in user mode. In the unpatched build the 4 bytes at record offset `+4` (copied from `BROWSER_NAME` offset `0x2C-0x2F`) contain residual paged-pool data; in the patched build they read as zero.

### 6. Exploit Primitive & Development Notes
- **Primitive:** Kernel paged-pool information disclosure.
- **Volume of Leak:** 4 bytes per enumerated name — the `UNICODE_STRING` alignment padding at offset `0x2C-0x2F`, copied into each enumeration output record by the 16-byte `movups`/`movdqu` of the name string at `0x1c0017cb3`-`0x1c0017cb7`. The disclosure size is fixed and independent of `NameLength`. The inline name buffer at `0x40` is fully written by `RtlCopyUnicodeString`, and the `Buffer` pointer field at `0x30` is overwritten in the output record with a caller-relative offset before it is returned, so it is not disclosed. The `0x3C-0x3F` gap is uninitialized in the allocation but is not read by the enumeration path and is not shown to reach user mode.
- **Content:** The disclosed bytes are whatever previously occupied that offset in the reused paged-pool block. They are a fixed 4-byte window at a structure-padding offset, not a specific pointer or object field; no reliable pointer disclosure is demonstrated from this position.

### 7. Debugger PoC Playbook
If you are attached to the unpatched target with a Kernel Debugger (KD), use the following steps to observe the vulnerability in real time.

**Breakpoints:**
- `bp bowser!BowserAllocateName` (or `bp 0x1c0017718`) — Triggered when the vulnerable allocation occurs.
- `bp bowser!BowserCommonDeviceIoControlFile` (or `bp 0x1c0010b60`) — Triggered on IOCTL entry. 
- `bp bowser!EnumNames` (or `bp 0x1c0019e50`) — Triggered when leaking data back to user mode.

**What to Inspect at Breakpoints:**
- **At `BowserAllocateName` (`0x1c0017718`):** 
  - Inspect `rsi` (pointer to `UNICODE_STRING`).
  - `dt _UNICODE_STRING @rsi` to see the `Length` (matches the `NameLength` determining the allocation size).
- **At `0x1c00177a3` (Post-Allocation):**
  - `r @rbx` holds the newly allocated buffer address.
  - Dump the memory: `db @rbx L0x42`. You will see pre-existing pool data in the uninitialized gap at `@rbx+0x2C` (and at `@rbx+0x3C`, which is uninitialized but not read by the enumeration path).
- **At `BowserCommonDeviceIoControlFile`:**
  - Check the IRP stack location to verify the IOCTL code. 
  - `dx @$curframe->Tail.Overlay.CurrentStackLocation` 
  - The dispatcher computes `IoControlCode - 0x130007` at `0x1c0010f86` and jumps at `0x1c0010fa9`; `IoControlCode 0x13000C` reaches the `AddBowserName` case and `0x130017` reaches the `EnumNames` case.

**Key Instructions / Offsets:**
- `0x1c0017797`: The `ExAllocatePoolWithTag` call. 
- `0x1c00177b5`: The beginning of field initialization. The absence of a `memset` call between `0x1c00177a9` and `0x1c00177b5` is the core vulnerability.
- `0x1c0011253`: The call into `AddBowserName` from the IOCTL dispatcher (most direct user-mode path).
- `0x1c00111bf`: The call into `EnumNames` (the sink that copies the data to user-mode).
- `0x1c0017cb3`-`0x1c0017cb7`: In `EnumerateNamesTransportNameWorker`, the 16-byte `movups`/`movdqu` copy of the name `UNICODE_STRING` (offsets `0x28-0x37`) into the output record, carrying the `0x2C-0x2F` gap.

**Trigger Setup:**
1. From user mode, open `\\.\LanmanDatagramReceiver`.
2. Send IoControlCode `0x13000C` (`AddBowserName` case) via `DeviceIoControl` with a payload containing a domain name and transport string.
3. Send IoControlCode `0x130017` (`EnumNames` case) via `DeviceIoControl` to read the memory.

**Expected Observation:**
When `EnumNames` executes, inspect the user-mode output buffer. In the unpatched build the 4 bytes at each record's `+4` offset (copied from `BROWSER_NAME` offset `0x2C-0x2F`) contain residual paged-pool data; in the patched build the same 4 bytes read as zero because of the added `memset`. 

### 8. Changed Functions — Full Triage
- **`BowserAllocateName`** (Similarity: 0.9898): Core allocation routine for browser names. **Security Relevant Change.** Added `memset` call to zero the allocated `BROWSER_NAME` structure. 
- **`AsyncCreateTransportName`** (Similarity: 0.9903): Routine for creating transport names. **Security Relevant Change.** Added `memset` call to zero the allocated `BROWSER_NAME` structure.
- **`AddBowserName`** (Similarity: 0.9921): IOCTL dispatch handler for adding browser names. **Security Relevant Change.** Added `memset` call to zero the allocated `BROWSER_NAME` structure.
*(Note: All three functions received identical structural fixes; the `memset` was inserted immediately following the `ExAllocatePoolWithTag` validation block.)*

### 9. Unmatched Functions
- **Removed:** None.
- **Added:** None.

### 10. Confidence & Caveats
- **Confidence Level:** High for the fix itself. The `memset` insertion is present in all three functions in both the disassembly and the decompilation, and the enumeration worker demonstrably copies the `0x2C-0x2F` gap to the caller's output buffer.
- **IOCTL Codes:** The dispatcher in `BowserCommonDeviceIoControlFile` computes `IoControlCode - 0x130007` at `0x1c0010f86` and jumps through a compiler-generated switch table at `0x1c0010fa9`. The `AddBowserName` case corresponds to IoControlCode `0x13000C` (call at `0x1c0011253`) and the `EnumNames` case to `0x130017` (call at `0x1c00111bf`).
- **Scope of Disclosure:** The demonstrable leak is the fixed 4-byte `UNICODE_STRING` padding at `0x2C-0x2F`, disclosed per enumerated name. The `0x3C-0x3F` gap is uninitialized in the allocation but is not read by the enumeration path.
- **Access Constraints:** The `AddBowserName` dispatch case is gated by `BowserSecurityCheck` at `0x1c001123e` (bypassed for system threads); the `EnumNames` case is not gated by `BowserSecurityCheck` in its own block. Device-object ACLs on `\Device\LanmanDatagramReceiver` further constrain who can open a handle.
