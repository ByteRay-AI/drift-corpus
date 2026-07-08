Title: msircomm.sys — Uninitialized PagedPool device-name buffer zeroed before IoGetDeviceProperty (CWE-908), defense-in-depth hardening fixed
Date: 2026-07-03
Slug: msircomm_bf0ec8a1-msircomm-report-20260703-143616
Category: Corpus
Author: Argus
Summary: KB5078752

## 1. Overview

- **Unpatched Binary:** `msircomm_unpatched.sys`
- **Patched Binary:** `msircomm_patched.sys`
- **Overall Similarity Score:** 0.9915
- **Diff Statistics:**
  - Matched Functions: 100
  - Changed Functions: 2
  - Identical Functions: 98
  - Unmatched Functions (Unpatched/Patched): 0 / 0
- **Verdict:** The patch adds two `memset` (zero-fill) calls immediately after two `ExAllocatePoolWithTag` allocations. The change in `IrCommHandleSymbolicLink` zeroes a 514-byte (`0x202`) PagedPool buffer that is only partially filled by `IoGetDeviceProperty`, a genuine but low-impact CWE-908 (Use of Uninitialized Resource) hardening. The change in `DriverEntry` zeroes the registry-path copy buffer, but that buffer is already fully initialized in both builds, so it is a redundant defense-in-depth change with no residue window. No demonstrable kernel-memory disclosure to user mode was found in either build.

---

## 2. Vulnerability Summary

### Finding 1: Uninitialized device-name pool buffer passed to IoGetDeviceProperty

- **Severity:** Low
- **Vulnerability Class:** Use of Uninitialized Resource (CWE-908)
- **Affected Function:** `IrCommHandleSymbolicLink` @ `0x1C00015C0`
- **Root Cause:** During PnP device symbolic-link setup and teardown, the routine allocates a second 514-byte (`0x202`) PagedPool buffer for `DeviceName.Buffer`. In the unpatched build this buffer is not zeroed before it is handed to `IoGetDeviceProperty(DevicePropertyPhysicalDeviceObjectName, ...)`, which writes only `ResultLength` bytes (the physical device object name, typically well under `0x200`). The remaining bytes of the allocation are left holding stale pool contents.
- **Reachability and observable impact:** The buffer is consumed only in ways that are bounded to the returned name, so the uninitialized tail is not exposed to user mode in the code as written:
  - `IoCreateSymbolicLink(&Destination, &DeviceName)` uses `DeviceName` as a counted `UNICODE_STRING` whose `Length` is set to `ResultLength - 2`, i.e. exactly the physical device object name; the residue past that length is not part of the link target.
  - `RtlWriteRegistryValue(4, "SERIALCOMM", DeviceName.Buffer, ...)` and `RtlDeleteRegistryValue(4, "SERIALCOMM", DeviceName.Buffer)` pass `DeviceName.Buffer` as a NUL-terminated value name; the read stops at the terminator `IoGetDeviceProperty` places within `ResultLength`.
  Because both consumers stop at the legitimate name, no user-mode-observable disclosure of the uninitialized bytes is demonstrable. The patch is a defense-in-depth zeroing of a partially-filled pool buffer. It is additionally reached only via PnP `AddDevice`/`IRP_MN_REMOVE_DEVICE` (device attach/detach or reinstall), not an unprivileged IOCTL surface.
- **Call Chain:**
  1. PnP `AddDevice` → `IrCommAddDevice` (`0x1C0001010`) → `IrCommHandleSymbolicLink(PDO, InterfaceName, create)`.
  2. `IRP_MJ_PNP` with `MinorFunction == 2` (`IRP_MN_REMOVE_DEVICE`) → `IrCommPnP` (`0x1C0001290`) → `IrCommHandleSymbolicLink(PDO, InterfaceName, delete)`.

### Finding 2: Redundant zero-fill of the DriverEntry registry-path buffer

- **Severity:** No security-relevant change
- **Vulnerability Class:** N/A (redundant defense-in-depth zeroing)
- **Affected Function:** `DriverEntry` @ `0x1C000C008`
- **Root Cause / Assessment:** During driver initialization a PagedPool buffer of `RegistryPath->Length + 2` bytes is allocated to hold a copy of the registry path. In **both** builds the buffer is fully initialized before use: `memmove` copies exactly `RegistryPath->Length` bytes into the first part, and the instruction `*(WORD*)(buf + Length/2) = 0` writes a NUL terminator word into the final 2 bytes, covering the whole `Length + 2` allocation. The patched build adds a `memset(buf, 0, Length + 2)` before the `memmove`, but since every byte is subsequently written, there is no uninitialized/residue window in either build. This is a redundant hardening change, not a fix for a disclosure.

---

## 3. Pseudocode Diff

### `IrCommHandleSymbolicLink` (`0x1C00015C0`)

```c
// === UNPATCHED ===
Buffer = ExAllocatePoolWithTag(PagedPool, 0x202u, 0x6F437249u);
DeviceName.Buffer = Buffer;
if (Buffer != nullptr) {
    // No zeroing of the newly allocated 0x202 buffer.
    RegistryKeyValue = IoGetDeviceProperty(
        PhysicalDeviceObject, DevicePropertyPhysicalDeviceObjectName,
        DeviceName.MaximumLength, DeviceName.Buffer, &ResultLength);
    if (RegistryKeyValue >= 0) {
        DeviceName.Length += ResultLength - 2;              // counted length = PDO name
        if (a3 != 0) {
            if (IoCreateSymbolicLink(&Destination, &DeviceName) >= 0)
                RtlWriteRegistryValue(4, L"SERIALCOMM", DeviceName.Buffer, 1,
                                      Destination.Buffer + 12, Destination.Length - 24);
            ...
        }
    }
}

// === PATCHED ===
Buffer = ExAllocatePoolWithTag(PagedPool, 0x202u, 0x6F437249u);
DeviceName.Buffer = Buffer;
if (Buffer != nullptr) {
    memset(Buffer, 0, DeviceName.MaximumLength + 2LL);     // ADDED: zero full allocation
    RegistryKeyValue = IoGetDeviceProperty(
        PhysicalDeviceObject, DevicePropertyPhysicalDeviceObjectName,
        DeviceName.MaximumLength, DeviceName.Buffer, &ResultLength);
    // ... identical to unpatched below this point ...
}
```

### `DriverEntry` (`0x1C000C008`)

```c
// === UNPATCHED ===
PoolWithTag = ExAllocatePoolWithTag(PagedPool, (WORD)(Length + 2), 0x6F437249u);
if (PoolWithTag) {
    memmove(PoolWithTag, RegistryPath->Buffer, RegistryPath->Length);
    PoolWithTag[RegistryPath->Length >> 1] = 0;   // NUL terminator fills the trailing 2 bytes
    ...
}

// === PATCHED ===
PoolWithTag = ExAllocatePoolWithTag(PagedPool, (WORD)(Length + 2), 0x6F437249u);
if (PoolWithTag) {
    memset(PoolWithTag, 0, (WORD)(Length + 2));    // ADDED, but buffer is fully written below anyway
    memmove(PoolWithTag, RegistryPath->Buffer, RegistryPath->Length);
    PoolWithTag[RegistryPath->Length >> 1] = 0;
    ...
}
```

---

## 4. Assembly Analysis

### `IrCommHandleSymbolicLink` (`0x1C00015C0`)

Unpatched build — the second allocation is used directly, with no zero-fill between the NULL check and `IoGetDeviceProperty`:

```assembly
00000001C00016B0  mov     edx, 202h                          ; NumberOfBytes = 514
00000001C00016C2  call    cs:__imp_ExAllocatePoolWithTag
00000001C00016CE  mov     [rbp+DeviceName.Buffer], rax
00000001C00016D2  test    rax, rax
00000001C00016D5  jnz     short loc_1C00016E1
; loc_1C00016E1: no memset here in the unpatched build
00000001C00016E1  movzx   r8d, [rbp+DeviceName.MaximumLength]; BufferLength
00000001C00016EF  mov     r9, rax                            ; PropertyBuffer (not zeroed)
00000001C00016F5  mov     edx, 0Bh                           ; DevicePropertyPhysicalDeviceObjectName
00000001C00016FA  call    cs:__imp_IoGetDeviceProperty
; ... DeviceName.Length = ResultLength - 2 (counted to the PDO name) ...
00000001C000172D  call    cs:__imp_IoCreateSymbolicLink      ; target bounded by DeviceName.Length
00000001C0001768  call    cs:__imp_RtlWriteRegistryValue     ; ValueName = DeviceName.Buffer (NUL-terminated)
```

Patched build — a `memset` is inserted at the NULL-check target (`loc_1C00016EC`), before `IoGetDeviceProperty`:

```assembly
00000001C00016CD  call    cs:__imp_ExAllocatePoolWithTag
00000001C00016D9  mov     [rbp+DeviceName.Buffer], rax
00000001C00016DD  test    rax, rax
00000001C00016E0  jnz     short loc_1C00016EC
00000001C00016EC  movzx   r8d, [rbp+DeviceName.MaximumLength]
00000001C00016F1  xor     edx, edx                           ; Val = 0
00000001C00016F3  add     r8, r13                            ; Size = MaximumLength + 2  (r13 = 2)
00000001C00016F6  mov     rcx, rax                           ; buffer
00000001C00016F9  call    memset                             ; *** ADDED: zero full allocation ***
00000001C00016FE  movzx   r8d, [rbp+DeviceName.MaximumLength]; BufferLength
00000001C0001718  call    cs:__imp_IoGetDeviceProperty
```

### `DriverEntry` (`0x1C000C008`)

Unpatched build — allocation, copy, and explicit NUL terminator (full coverage, no zero-fill needed):

```assembly
00000001C000C06A  call    cs:__imp_ExAllocatePoolWithTag
00000001C000C076  mov     rdi, rax
00000001C000C07C  jz      loc_1C000C254
00000001C000C082  movzx   r8d, word ptr [rsi]                ; Size = RegistryPath.Length
00000001C000C089  call    memmove                            ; copy Length bytes
00000001C000C0A0  mov     [rdi+rcx*2], r14w                  ; NUL word at offset Length -> fills last 2 bytes
```

Patched build — a redundant `memset` of `Length + 2` is inserted before the `memmove`:

```assembly
00000001C000C06C  call    cs:__imp_ExAllocatePoolWithTag
00000001C000C078  mov     rdi, rax
00000001C000C07E  jz      loc_1C000C263
00000001C000C084  mov     r8d, r14d                          ; Size = Length + 2
00000001C000C087  xor     edx, edx                           ; Val = 0
00000001C000C089  mov     rcx, rax
00000001C000C08C  call    memset                             ; *** ADDED (redundant) ***
00000001C000C091  movzx   r8d, word ptr [rsi]                ; Size = RegistryPath.Length
00000001C000C09C  call    memmove
00000001C000C0AF  mov     [rdi+rcx*2], r15w                  ; NUL word at offset Length
```

---

## 5. Trigger Conditions

For `IrCommHandleSymbolicLink` (`0x1C00015C0`):

1. `msircomm.sys` must be loaded (IR device present or force-loaded).
2. The routine runs on PnP `AddDevice` (create path, `a3 != 0`) and on `IRP_MN_REMOVE_DEVICE` (delete path, `a3 == 0`). These are driven by device attach/detach or driver reinstall, not by an unprivileged IOCTL.
3. In the unpatched build, the bytes of `DeviceName.Buffer` beyond `ResultLength` hold stale pool data at the point of the `IoGetDeviceProperty` return, but the downstream `IoCreateSymbolicLink`, `RtlWriteRegistryValue`, and `RtlDeleteRegistryValue` all operate on the bounded PDO name only, so those stale bytes are not surfaced to user mode.

`DriverEntry` (`0x1C000C008`) runs once at driver load; its registry-path buffer is fully written in both builds, so there is nothing to trigger.

---

## 6. Exploit Primitive & Development Notes

- **Primitive:** None demonstrable. The added zeroing in `IrCommHandleSymbolicLink` is defense-in-depth against a partially-filled pool buffer; the buffer's consumers are bounded to the physical device object name (counted `UNICODE_STRING` length for the symbolic link, NUL terminator for the registry value name), so the uninitialized tail does not reach a user-readable artifact in the code as written.
- No pool-grooming, KASLR-bypass, or mitigation-bypass primitive is supported by the observed code paths.

---

## 7. Analyst Notes

For an analyst examining the **unpatched** binary:

- `IrCommHandleSymbolicLink` entry: `0x1C00015C0`. `rcx` = DeviceObject, `rdx` = InterfaceName pointer, `r8b` = create (`1`) / delete (`0`) selector.
- Second `ExAllocatePoolWithTag` for `DeviceName.Buffer`: `0x1C00016C2` (unpatched). The pointer returned in `rax` is stored at `[rbp+DeviceName.Buffer]`; in the unpatched build no zero-fill follows before `IoGetDeviceProperty` at `0x1C00016FA`.
- The corresponding patched insertion point is `loc_1C00016EC` (`memset` at `0x1C00016F9`).
- Pool tag is `'IrCo'` (`0x6F437249`, little-endian).
- Callers to break on: `IrCommAddDevice` (`0x1C0001010`, create path) and `IrCommPnP` (`0x1C0001290`, delete path at `MinorFunction == 2`).

---

## 8. Changed Functions — Full Triage

- **`IrCommHandleSymbolicLink`** (`0x1C00015C0`, Similarity: 0.9854 | Type: Security-relevant, low impact)
  - *Change:* Added `memset(DeviceName.Buffer, 0, MaximumLength + 2)` immediately after the second `ExAllocatePoolWithTag` and before `IoGetDeviceProperty`. Zeroes a partially-filled PagedPool buffer (CWE-908 hardening). The register `r13` is introduced to hold the constant `2` for the size argument; the remaining differences are register renumbering from the inserted code.
- **`DriverEntry`** (`0x1C000C008`, Similarity: 0.9064 | Type: Redundant hardening)
  - *Change:* Added `memset(buf, 0, Length + 2)` after the `ExAllocatePoolWithTag` for the registry-path copy. The buffer is already fully written by the subsequent `memmove` plus NUL-terminator store in both builds, so this is redundant. The prologue gains an extra saved register (`r15`) and the size value is cached in `r14` for the new `memset`.

No other functions changed content. All remaining differences between the two builds are address shifts in relocated functions caused by the two inserted `memset` calls.

---

## 9. Unmatched Functions

- **Removed:** None.
- **Added:** None.

---

## 10. Confidence & Caveats

- **Confidence Level:** High. An independent function-by-function diff of both builds confirms exactly two content changes, both of which are `memset` insertions after pool allocations. `0x1C0006500` is the driver's `memset` thunk (called with `Val = 0`), matching a zero-fill.
- **Assessment:** Finding 1 is a genuine but low-severity CWE-908 hardening — the uninitialized tail of the device-name buffer is not exposed to user mode by the code's consumers, so no information-disclosure vulnerability is demonstrable. Finding 2 zeroes a buffer that is already fully initialized in both builds and therefore has no security effect.
