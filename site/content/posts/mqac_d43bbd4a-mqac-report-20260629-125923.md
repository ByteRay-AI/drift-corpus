Title: mqac.sys — No security-relevant change (cross-branch rebuild; validation inlined from callees)
Date: 2026-06-29
Slug: mqac_d43bbd4a-mqac-report-20260629-125923
Category: Corpus
Author: Argus
Summary: KB5075912
Severity: None

## 1. Overview
- **Unpatched Binary**: `mqac_unpatched.sys` — FileVersion 10.0.28000.2336
- **Patched Binary**: `mqac_patched.sys` — FileVersion 10.0.19041.7052
- **Overall Similarity Score**: 0.6197 (61.97%)
- **Diff Statistics**:
  - Matched Functions: 517
  - Changed Functions: 413
  - Identical Functions: 104
  - Unmatched Functions (Both Directions): 0
- **Verdict**: No security-relevant change is demonstrable. The two files are different Windows servicing branches (build 28000 vs build 19041) compiled with different toolchains and different inlining decisions, not a same-branch before/after security patch. Every bounds check, state-validation check, and handle check that a naive body diff appears to "add" in one build is in fact present in **both** builds: in one build it lives in an out-of-line callee, and in the other the compiler inlined that callee into its caller. No newly added bounds check, length/size validation, null/handle guard, integer-overflow guard, or error-return path guarding a memory operation exists in either build that is absent from the other.

---

## 2. Vulnerability Summary

### Finding 1: Bitmap write bounds check — present in both builds (inlined in one)
- **Severity**: None (No security-relevant change)
- **Vulnerability Class**: None demonstrable
- **Affected Function**: `CMMFAllocator::RestorePackets` (`0x140011814` unpatched / `0x1C00116D8` patched), free-space allocation bitmap restore
- **Finding**: The unpatched `CMMFAllocator::RestorePackets` updates the free-space bitmap by calling the out-of-line helper `CBitmap::FillBits` (`0x14000428C`). `CBitmap::FillBits` reads the bitmap capacity from the first dword of the `CBitmap` object and refuses the write when the start index exceeds capacity, when the count exceeds capacity, or when start+count exceeds capacity (logging trace codes 0xA/0xB/0xC and returning without writing). In the patched build the compiler inlined `CBitmap::FillBits` into `RestorePackets`, so the same capacity comparisons and the same 0xA/0xB/0xC trace codes appear inline. The check is identical in both builds; the patch does not add it. The report's earlier claim of an added `if (index > capacity)` guard is a compiler-inlining artifact, not a security fix.
- **Reachability note**: `RestorePackets` is reached only from the recovery path `ACDeviceControl` (`0x14000B100`) → `ACRestorePackets` (`0x140009250`) → `CPoolAllocator::RestorePackets` (`0x14001199C`) → `CMMFAllocator::RestorePackets`. The bitmap indices are derived from the persisted allocator geometry and the on-disk bitmap contents, not from a live message body. It is not on the `MQSendMessage` send path.

### Finding 2: Message-property state validation — present in both builds (inlined in one)
- **Severity**: None (No security-relevant change)
- **Vulnerability Class**: None demonstrable
- **Affected Function**: `CPacket::Create` (`0x14001620C` unpatched / `0x1C001768C` patched)
- **Finding**: The unpatched `CPacket::Create` performs its transaction/queue-state validation by calling the out-of-line helper `ValidateProperties` (`0x14001A9F8`), which returns `0xC00E0020` (MQ_ERROR_INVALID_PARAMETER) and `0xC00E0006` for the invalid state combinations. In the patched build the compiler inlined `ValidateProperties` into `CPacket::Create`, so the same conditions and the same `0xC00E0020` / `0xC00E0006` returns appear inline. The checks and the struct offsets they read (queue+0x58, sendparams+0xC0/0xE0/0x128/0x130/0x140/0x168, message-props+0x38/0x58/0x11) are identical in both builds. The patch does not add these checks.

### Finding 3: Handle sentinel check in packet build — present in both builds (inlined in one)
- **Severity**: None (No security-relevant change)
- **Vulnerability Class**: None demonstrable
- **Affected Function**: `ACpBuildPacket` (`0x140013E24` unpatched / `0x1C001663C` patched), and its caller `CPacket::Create`
- **Finding**: The `0xFFFFFFFF` handle-sentinel check that the earlier write attributed to this finding is not inside `ACpBuildPacket` at all. It lives in the accessor `CQEntry::Buffer` (`0x14000263C`): `if (*(entry+0x10) == 0xFFFFFFFF) return nullptr; else return CMMFAllocator::GetAccessibleBuffer(*(entry+0x18))`. The unpatched `CPacket::Create` obtains the packet buffer by calling `CQEntry::Buffer`; the patched `CPacket::Create` inlines that same sentinel test and the same `CMMFAllocator::GetAccessibleBuffer` (`0x1C0011468`) call. `ACpBuildPacket` itself differs between the two builds only by inlined helpers (`ProbeForRead` expanded inline, section-size overflow checks pulled in from `CalcSectionSize`, WOW64 pointer translators, etc.) with equivalent behavior; it gains no new memory-operation guard. The earlier finding also mislabeled `0xC000009A` — that status is STATUS_INSUFFICIENT_RESOURCES, not STATUS_INVALID_DEVICE_REQUEST — and the earlier patched-side address `0x1C00181B8` is a different function (`CPacket::GetProperties`), not the patched `ACpBuildPacket`.

---

## 3. Pseudocode Diff

### Bitmap restore (`CMMFAllocator::RestorePackets`)
```c
// UNPATCHED (0x140011814): bitmap update goes through the out-of-line helper,
// which itself validates the indices against capacity before writing.
CMMFAllocator::PutFreeBlock(this, v2 << 9, (v13 - v2) << 9);
CBitmap::FillBits((CBitmap *)(*((_QWORD *)this + 16) + 12LL), v2, v13 - v2, 0); // guarded inside FillBits
...
CBitmap::FillBits((CBitmap *)(*((_QWORD *)this + 16) + 12LL), v13, v2 - v13, 1); // guarded inside FillBits

// CBitmap::FillBits (0x14000428C), UNPATCHED — the guard that already exists:
void CBitmap::FillBits(CBitmap *this, unsigned int a2, unsigned int a3, int a4) {
    if (a3 != 0) {
        unsigned int cap = *(_DWORD *)this;             // bitmap capacity (bits)
        if (a2 > cap || a3 > cap) { /* trace 0xA, skip */ }
        else if (a2 + a3 < a3 || a2 + a3 <= a2) { /* trace 0xB, skip */ }
        else if (a2 + a3 <= cap) { /* perform the bit set/clear */ }
        else { /* trace 0xC, skip */ }
    }
}

// PATCHED (0x1C00116D8): the identical capacity comparisons (and the same
// 0xA/0xB/0xC trace codes) appear inline because FillBits was inlined:
v24 = *v23;                          // v23 = bitmap header + 12 -> capacity
if (v2 > *v23 || v22 > v24) { /* trace 0xA, skip */ }
else if (v21 < v22) { /* trace 0xB, skip */ }
else if (v21 <= v24) { /* perform the bit clear inline */ }
else { /* trace 0xC, skip */ }
```

### Message dispatch (`CPacket::Create`)
```c
// UNPATCHED (0x14001620C): state validation done by the out-of-line callee.
result = ValidateProperties(a2, a5, a6, a7, a10, v14);   // returns 0xC00E0020 / 0xC00E0006
if ((int)result >= 0) { /* proceed */ }
return result;

// ValidateProperties (0x14001A9F8), UNPATCHED — the checks that already exist:
if ((a5 || *(a4+88)==3)
    && (*(a2+192) && *(a3+56) && !*(a2+320)
        || a5 && *(a2+224) && *(a2+296) && (*(a2+304) || *(a3+88))))
    return 0xC00E0020;
if (a6) {
    if (*(a2+224) && *(a2+296) && (*(a2+304) || *(a3+88))) return 0xC00E0020;
    if (*(a2+360)) {
        if (*(*(a1+64)+996)) return 0xC00E0006;
        if (*(a2+64)) return (*(a3+17)&1) ? 0xC00E0006 : 0;
    }
}

// PATCHED (0x1C001768C): the identical conditions and returns appear inline,
// because ValidateProperties was inlined into CPacket::Create.
```

### Packet buffer accessor (`CQEntry::Buffer`, inlined into patched `CPacket::Create`)
```c
// UNPATCHED CQEntry::Buffer (0x14000263C): the 0xFFFFFFFF sentinel test.
struct CPacketBuffer *CQEntry::Buffer(CQEntry *this) {
    if (*((_DWORD *)this + 4) == -1)              // offset 0x10 == 0xFFFFFFFF
        return nullptr;
    return CMMFAllocator::GetAccessibleBuffer(*((_QWORD *)this + 3));   // this+0x18
}

// PATCHED CPacket::Create (0x1C001768C): same test inlined at the call site.
if (*((_DWORD *)*a1 + 4) == -1)  AccessibleBuffer = 0;
else  AccessibleBuffer = CMMFAllocator::GetAccessibleBuffer(*((_QWORD *)*a1 + 3), *((_DWORD *)*a1 + 4));
```

---

## 4. Assembly Analysis

Real instructions from the unpatched `CBitmap::FillBits` (`0x14000428C`) showing the capacity bounds check that already exists before any bitmap write:

```
000000014000428C  test    r8d, r8d          ; r8d = count; if zero, do nothing
000000014000428F  jz      locret_14000446D
00000001400042A9  mov     edi, [rcx]        ; edi = bitmap capacity (first dword of CBitmap)
00000001400042AE  mov     r9d, edx          ; r9d = start index
00000001400042B4  cmp     r9d, edi          ; start > capacity ?
00000001400042B7  ja      loc_140004421     ;   -> reject (trace 0xA), no write
00000001400042BD  cmp     r8d, edi          ; count > capacity ?
00000001400042C0  ja      loc_140004421     ;   -> reject, no write
00000001400042C6  lea     eax, [r9+r8]      ; eax = start + count
00000001400042CA  cmp     eax, r8d
00000001400042CD  jb      loc_1400043EB     ; overflow -> reject (trace 0xB)
00000001400042DC  cmp     eax, edi          ; start+count > capacity ?
00000001400042DE  jbe     short loc_14000430C ; only here does the bit fill proceed
```

The patched `CMMFAllocator::RestorePackets` (`0x1C00116D8`) contains the same comparisons inline (the compiler inlined `CBitmap::FillBits`), preceded by a load of the capacity from `[bitmap+0]` and the same 0xA/0xB/0xC trace codes. No comparison present in the patched build is absent from the unpatched build.

---

## 5. Trigger Conditions

No reachable trigger for a memory-safety defect was identified. Because the bitmap write in `CMMFAllocator::RestorePackets` is guarded by the capacity comparisons in `CBitmap::FillBits` in the unpatched build (and by the same comparisons inlined into `RestorePackets` in the patched build), an out-of-range start/count is rejected before any write in both builds. The restore path itself (`ACDeviceControl` → `ACRestorePackets` → `CPoolAllocator::RestorePackets` → `CMMFAllocator::RestorePackets`) is a persistence-recovery path whose indices come from the on-disk allocator geometry and bitmap contents, not from a live message body.

---

## 6. Exploit Primitive & Development Notes

No exploit primitive is supported. The claimed out-of-bounds pool write does not exist in either build: the bitmap manager refuses start/count values that exceed the bitmap capacity before writing. There is therefore no relative or absolute kernel-pool write to build a primitive from, and no basis for the pool-grooming, info-leak, or privilege-escalation steps that would otherwise follow. No such content is retained.

---

## 7. Debugger PoC Playbook

There is no vulnerability to reproduce. For an analyst wishing to confirm the equivalence:

- Disassemble `CBitmap::FillBits` at `mqac_unpatched.sys + 0x428C` and observe the `mov edi,[rcx]` capacity load and the `cmp r9d,edi / ja` and `cmp r8d,edi / ja` rejections at `+0x42B4`/`+0x42BD` before any bit write.
- Disassemble `CMMFAllocator::RestorePackets` at `mqac_patched.sys + 0x116D8` and observe the same capacity comparisons and the same 0xA/0xB/0xC trace codes inlined at the bitmap update sites.
- Compare the two `CPacket::Create` bodies (`+0x1620C` unpatched, `+0x1768C` patched) against `ValidateProperties` (`+0x1A9F8`, unpatched) to confirm the `0xC00E0020` / `0xC00E0006` returns are the inlined form of the same validator.

Expected result in both builds: an out-of-range bitmap index is rejected (trace 0xA/0xB/0xC) and no write occurs.

---

## 8. Changed Functions — Full Triage

- `CMMFAllocator::RestorePackets` (`0x140011814` → `0x1C00116D8`, similarity 0.4171): **No security-relevant change.** Body differs because `CBitmap::FillBits` and `CMMFAllocator::FindValidPacket` (whose `CPacket::CheckPacket` performs the CRC integrity test via `CPacket::ComputeCRC`) were inlined in the patched build. All guards are present in both builds.
- `CPacket::Create` (`0x14001620C` → `0x1C001768C`, similarity 0.6242): **No security-relevant change.** Body differs because `ValidateProperties` and `CQEntry::Buffer` were inlined in the patched build. The `0xC00E0020` / `0xC00E0006` returns and the `0xFFFFFFFF` sentinel test exist in both builds.
- `ACpBuildPacket` (`0x140013E24` → `0x1C001663C`, similarity 0.3022): **No security-relevant change.** All differences are inlined helpers (inline `ProbeForRead`/`MmUserProbeAddress` expansion, `CalcSectionSize` overflow checks, `SetProvInfoEx`, WOW64 pointer translators) with equivalent behavior; no added memory-operation guard.
- `CPacket::CompleteWriter` (`0x140015D94`, similarity 0.1472): **Behavioral / non-security.** Cross-branch restructure of IRP completion and lock release paths; no memory-safety change.
- `CStorage::GetWriteRequest` (`0x140022B8C`) and `CPacket::GetProperties` (`0x140017000`): **Cross-branch churn / non-security.** Restructured control flow and loop shapes; no logical security impact.
- Additional inlining families observed across the corpus (`drv_section_cast_safe<T>` accessors, `PtrToPtrFrom32To64`, the `CBitmap` methods used by `UpdateBitmap`) and a rename (`QUEUE_FORMAT::IsValid` → `CUserQueue::IsValidQueueFormat`) carry identical validation in both builds. WPP/ETW tracing (`WPP_SF_*`) and WIL feature-staging (`Feature_Servicing_MSMQEOP__*`, `wil_details_*`) deltas are servicing churn, not security fixes.

---

## 9. Unmatched Functions

The two files are different servicing branches, so some functions are branch-specific and have no same-name counterpart in the other build (for example the patched-only `CUserQueue::IsValidQueueFormat`, which corresponds to the unpatched `QUEUE_FORMAT::IsValid`). None of the branch-specific functions introduces a security-relevant guard that its counterpart lacks. The matched/changed/identical counts in Section 1 are the automated comparison's figures.

---

## 10. Confidence & Caveats

- **Confidence Level**: High. Every check the earlier write attributed to the patch was located, in the unpatched build, inside a named out-of-line callee (`CBitmap::FillBits`, `ValidateProperties`, `CQEntry::Buffer`, `CPacket::CheckPacket`) that the patched build inlined. The capacity bounds check is confirmed at the instruction level in `CBitmap::FillBits`.
- **Nature of the diff**: The comparison is between build 10.0.28000.2336 and build 10.0.19041.7052 — different Windows servicing branches with different toolchains (the 28000 build uses `ExAllocatePool2`; the 19041 build uses `ExAllocatePoolWithTag`) and different inlining, which accounts for the low similarity and the large number of changed function bodies.
- **Result**: No security-relevant change is demonstrable in either direction.
