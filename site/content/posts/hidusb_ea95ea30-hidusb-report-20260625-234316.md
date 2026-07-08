Title: hidusb.sys — integer underflow leading to out-of-bounds read (CWE-191, CWE-125) in HumParseHidInterface fixed
Date: 2026-06-25
Slug: hidusb_ea95ea30-hidusb-report-20260625-234316
Category: Corpus
Author: Argus
Summary: KB5073723

### 1. Overview

* **Unpatched Binary:** `hidusb_unpatched.sys`
* **Patched Binary:** `hidusb_patched.sys`
* **Overall Similarity Score:** `0.5635`
* **Diff Statistics:** 75 matched functions, 60 changed functions, 15 identical functions, and 0 unmatched functions in either direction.
* **Verdict:** The patch remediates a medium-severity integer underflow in `HumParseHidInterface` that allows a malicious USB device to trigger a kernel out-of-bounds read during enumeration.

---

### 2. Vulnerability Summary

* **Severity:** Medium
* **Vulnerability Class:** Integer Underflow leading to Out-of-Bounds Read (CWE-191 / CWE-125)
* **Affected Function:** `HumParseHidInterface`
* **Root Cause:** The unpatched `HumParseHidInterface` receives a pointer to a USB HID interface descriptor and its associated buffer size. It reads the `bLength` field from the descriptor and validates that `bLength >= 9`, but it immediately computes `remaining_size = buffer_size - bLength` **without** verifying that `bLength <= buffer_size`. 
If a malicious USB device supplies a large `bLength` (e.g., `0xFF`), the subtraction wraps to a massive unsigned value (e.g., `~0xFFFFFF00`). This bypasses all subsequent unsigned bounds checks, causing the descriptor parsing loop to iterate and read kernel pool memory far past the end of the allocated buffer. The patch resolves this by introducing a `cmp eax, edi; jbe` check to ensure `bLength` is less than or equal to the `buffer_size` before the subtraction occurs, routing oversize descriptors to a new `USB_InterfaceDescriptorOverflow` error path.
* **Attacker-Reachable Entry Point:** Physical USB port (Plug and Play enumeration).
* **Call Chain:**
  1. Malicious USB device is plugged in → PnP Manager issues `IRP_MN_START_DEVICE`.
  2. `HumPnP` routes the IRP to `HumInitDevice`.
  3. `HumInitDevice` calls `HumGetConfigDescriptor` (which calls `HumGetDescriptorRequest`) to fetch the configuration descriptor.
  4. `HumInitDevice` invokes `USBD_ParseConfigurationDescriptorEx` to locate the HID interface descriptor.
  5. `HumInitDevice` calls **`HumParseHidInterface`** with the parsed buffer, triggering the vulnerability.

---

### 3. Pseudocode Diff

The core vulnerability is an unsigned integer wraparound. The unpatched code checks the minimum size but misses the maximum size.

```c
// --- UNPATCHED (Vulnerable) ---
void HumParseHidInterface(void* dev_ext, void* desc_buf, uint32_t buf_size, void** out_ptr) {
    if (buf_size >= 9) {
        uint8_t bLength = *(uint8_t*)desc_buf;
        if (bLength >= 9) {
            // VULNERABILITY: No check that bLength <= buf_size
            uint32_t remaining = buf_size - bLength; // UNDERFLOW if bLength > buf_size
            
            if (remaining >= 2) { // Unsigned compare. ~0xFFFFFF00 >= 2 is TRUE!
                // Enters parsing loop with corrupted bounds. OOB reads occur here.
            }
        }
    }
}

// --- PATCHED (Fixed) ---
void HumParseHidInterface(void* dev_ext, void* desc_buf, uint32_t buf_size, void** out_ptr) {
    if (buf_size >= 9) {
        uint8_t bLength = *(uint8_t*)desc_buf;
        if (bLength >= 9) {
            // FIX: Validate bLength against buf_size before subtraction
            if (bLength <= buf_size) {
                uint32_t remaining = buf_size - bLength; // Safe subtraction
                if (remaining >= 2) {
                    // ... safe parsing logic ...
                }
            } else {
                // New error path: USB_InterfaceDescriptorOverflow
            }
        }
    }
}
```

---

### 4. Assembly Analysis

Below is the relevant section of the unpatched assembly demonstrating the integer underflow and the resulting out-of-bounds read.

```assembly
; --- CHECK 1: buffer_size >= 9 ---
0x1c0002fa3: cmp     edi, 0x9
0x1c0002fa6: jae     0x1c0003034           ; Proceed if buffer_size >= 9

; === VULNERABLE SECTION ===
0x1c0003034: movzx   eax, byte [r12]       ; eax = bLength (first byte of descriptor)
0x1c0003039: cmp     al, 0x9
0x1c000303b: jae     0x1c00030c9           ; Proceed if bLength >= 9

; *** BUG: Missing check that bLength <= buffer_size ***
0x1c00030c9: sub     edi, eax              ; edi = buffer_size - bLength (WRAPS IF bLength > buffer_size!)
0x1c00030cb: cmp     edi, 0x2              
0x1c00030ce: jae     0x1c000315c           ; Unsigned compare passes with the wrapped value!

; === PARSING LOOP (OOB READS) ===
0x1c000315c: mov     eax, dword [r13+0x40]
0x1c0003160: and     eax, 0xfffffffe
0x1c0003163: mov     dword [r13+0x40], eax
0x1c0003167: movzx   ebx, byte [r12]       ; rbx = bLength
0x1c000316c: add     rbx, r12              ; rbx = &descriptor_buf[bLength] -> Points past buffer!
0x1c000316f: movzx   ecx, byte [rbx]       ; *** OUT-OF-BOUNDS READ ***

; ... loop continuation ...
0x1c00032bd: movzx   edx, byte [r12+0x4]   ; edx = bNumEndpoints (loop count)
0x1c00032d0: movzx   eax, byte [rbx+0x1]   ; OOB read of next descriptor type
```

**Patch Change:**
The patched binary intercepts the flow immediately after evaluating `bLength >= 9`. At `0x140002fba` it inserts `cmp eax, edi` followed by `jbe 0x140003036` before reaching the subtraction instruction. If `bLength` exceeds `buffer_size`, it falls through to the error handler that emits the `USB_InterfaceDescriptorOverflow` event string (`0x14000302a`) instead of reaching the subtraction. Only when `bLength <= buffer_size` does control reach `0x140003036: sub edi, eax`.

---

### 5. Trigger Conditions

To trigger this vulnerability reliably, an attacker must perform the following steps:

1. Obtain a programmable USB device (e.g., Raspberry Pi Pico, Teensy, Facedancer).
2. Program the device to present a configuration descriptor valid enough to pass `HumGetConfigDescriptor` (at least 9 bytes, valid `wTotalLength`).
3. Embed an interface descriptor within that configuration with `bInterfaceClass = 3` (HID), ensuring `USBD_ParseConfigurationDescriptorEx` targets it.
4. Set the HID interface descriptor's `bLength` field to a value greater than or equal to 9, but strictly larger than the remaining buffer size (e.g., `bLength = 0xFF` where buffer remainder is ~20 bytes).
5. Set `bNumEndpoints` (offset 4 of the interface descriptor) to a non-zero value to force the vulnerable parsing loop to iterate, maximizing the out-of-bounds read distance.
6. Plug the USB device into the target Windows machine. Windows will automatically enumerate the device, triggering the flaw.
7. **Observable Effects:** A kernel crash (BSOD) with stop code `0x50` (PAGE_FAULT_IN_NONPAGED_AREA) when the out-of-bounds walk reaches an unmapped page, or `0x19` (BAD_POOL_HEADER) / `0xC2` (BAD_POOL_CALLER) under Special Pool. If the adjacent pool memory happens to be mapped, the out-of-bounds reads may complete without an observable effect (the bytes read are consumed only for descriptor parsing and are not returned to the attacker).

---

### 6. Exploit Primitive & Development Notes

* **Primitive:** Out-of-bounds (OOB) kernel pool read. The loop reads `bLength` and `bDescriptorType` bytes from unallocated memory adjacent to the pool chunk.
* **Reachable Impact (DoS):** The underflow makes the remaining-size counter a large unsigned value, so the parsing loop keeps advancing `rbx` by descriptor lengths read out of bounds until it walks off the end of mapped memory, producing a deterministic system crash (`0x50`). This denial of service is the demonstrable impact.
* **Not an information-disclosure primitive:** The bytes read out of bounds (`bLength`, `bDescriptorType`, `bNumEndpoints`) are consumed only for the parser's control-flow decisions. The only value written to the caller's output (`*a4`) is a pointer to a located descriptor, not the out-of-bounds byte contents, so no kernel memory contents are returned to the attacker along this path. An out-of-bounds read cannot corrupt the pool, so it does not provide a write or code-execution primitive.
* **Special Pool (Driver Verifier):** If Special Pool is active on `hidusb.sys`, the first read past the buffer boundary faults immediately, since the adjacent pages are marked inaccessible.

---

### 7. Debugger PoC Playbook

To validate and analyze this vulnerability on the unpatched binary, use the following WinDbg/KD commands:

**Breakpoints**
```text
bp hidusb!HumParseHidInterface
bp 0x1c00030c9 ".echo \"[!] Vulnerable Subtraction\"; r eax, edi;"
bp 0x1c000316f ".echo \"[!] First OOB Read\"; r rbx;"
```

**What to Inspect**
* At `hidusb!HumParseHidInterface` entry:
  * `r8d` contains `buffer_size`. 
  * `rdx` contains the `descriptor_buf` pointer. 
* At `0x1c00030c9` (Vulnerable Subtraction):
  * `eax` holds `bLength` (attacker-controlled). 
  * `edi` holds the original `buffer_size`. 
  * Execute `t` to step over `sub edi, eax`. Watch `edi` wrap to a massive value (e.g., `0xFFFFFF00`).
* At `0x1c000316f` (First OOB Read):
  * Inspect `rbx`. It will be calculated as `r12 + bLength`. Use `!pool rbx` to verify it points outside the original allocation.

**Trigger Setup**
* Attach a hardware USB emulator (like Facedancer). 
* Configure the device to send a HID descriptor with `bLength=0xFF` upon receiving a `GET_DESCRIPTOR(CONFIGURATION)` request.
* Plug the emulator in. The breakpoint will hit automatically during PnP enumeration.

**Key Offsets**
* `0x1c0003034`: `movzx eax, byte [r12]` (Reads attacker-controlled `bLength`).
* `0x1c00030c9`: `sub edi, eax` (The integer underflow).
* `0x1c000316f`: `movzx ecx, byte [rbx]` (The first OOB read).
* `0x1c00032bd`: `movzx edx, byte [r12+0x4]` (Reads `bNumEndpoints`, determining loop iterations).

---

### 8. Changed Functions — Full Triage

* **HumParseHidInterface** (Security Relevant): Added critical bounds check `bLength <= buffer_size` to prevent integer underflow and OOB read.
* **HumInitDevice** (Behavioral): Extracted HID interface parsing logic into a new function `HumGetHidInfo`. Telemetry reorganization.
* **HumSelectConfiguration** (Hardening): Migrated `ExAllocatePoolWithTag` to `ExAllocatePool2`.
* **HumGetDescriptorRequest** (Hardening): Migrated `ExAllocatePoolWithTag` to `ExAllocatePool2`. Restructured pool failure handling.
* **HumGetConfigDescriptor** (Behavioral): Reordered validation logic (`arg_20 < 9` check moved earlier). Added an explicit free on failure paths.
* **HumWriteReport** (Behavioral): Changed completion routine to `HumGetSetReportCompletion`. Changed pending request count check. Migrated to `ExAllocatePool2`.
* **HumGetDeviceDescriptor** & **HumReadCompletion** (Cosmetic): Control flow reordering and WPP tracing updates.
* **HumGetMsGenreDescriptor** (Hardening): Migrated to `ExAllocatePool2` and reordered URB initialization.
* **HumGetHidInfo** (Behavioral): New wrapper function encapsulating descriptor parsing logic extracted from `HumInitDevice`.

---

### 9. Unmatched Functions

There are 0 strictly unmatched functions in the diff. However, the new wrapper function **`HumGetHidInfo`** was successfully diff-matched against the logic previously inlined in `HumInitDevice`. This function does not introduce a vulnerability, but serves as an abstraction boundary for the parsing flow.

---

### 10. Confidence & Caveats

* **Confidence:** High. The mathematical logic flaw (unsigned integer underflow) is clearly visible in the assembly and pseudocode, and the patch resolves it with a direct `cmp/jbe` bounds check.
* **Assumptions:** It is assumed that the buffer size parameter (`arg3`) passed to `HumParseHidInterface` is directly tied to the overall `wTotalLength` parsed during standard USB enumeration. 
* **Verification Required:** A researcher must confirm the exact buffer size parameter value dynamically using a debugger when their specific USB emulator hardware is enumerated, to ensure the crafted `bLength` is large enough to trigger the underflow but also conforms to standard USB size expectations.
