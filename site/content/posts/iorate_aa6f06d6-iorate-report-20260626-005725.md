Title: iorate.sys — Integer overflow in I/O rate-limit accounting bypasses Storage QoS throttling (CWE-190) fixed
Date: 2026-01-13
Slug: iorate_aa6f06d6-iorate-report-20260626-005725
Category: Corpus
Author: Argus
Summary: KB5073723
Severity: Medium
KBDate: 2026-01-13

### 1. Overview
- **Unpatched Binary:** `iorate_unpatched.sys`
- **Patched Binary:** `iorate_patched.sys`
- **Similarity Score:** 98.87%
- **Diff Statistics:** 95 matched functions, 94 identical, 1 changed. 0 unmatched functions in either direction.
- **Verdict:** The patch remediates an integer overflow vulnerability (CWE-190) in the core rate-limit calculation function, which previously allowed sustained I/O operations to bypass Storage QoS controls once a large volume of data had been transferred.

### 2. Vulnerability Summary
- **Severity:** Medium 
- **Vulnerability Class:** Integer Overflow / Wraparound (CWE-190) leading to logic bypass.
- **Affected Function:** `IoRateIsRateAmountDepleted`

**Root Cause Analysis:**
The function `IoRateIsRateAmountDepleted` is responsible for determining if a process or volume has exhausted its assigned I/O rate budget (Storage QoS), returning a flag that dictates whether the I/O manager should throttle subsequent operations. To make this decision, the function accumulates I/O byte counters from various structure fields into the `r10` register. It then scales this value to 100-nanosecond time units by multiplying it by `0x989680` (10,000,000) using a standard 64-bit `imul` instruction. 

If a malicious or high-throughput process generates enough I/O that the accumulated byte counter (`r10`) exceeds ~1.8 TB (specifically, `r10 > 2^64 / 10,000,000`), the 64-bit multiplication silently overflows and wraps to a small, unpredictable value. This corrupted value is subsequently used in a comparison (`cmp r8, rcx`) against the process's allocated rate budget. Because the calculated threshold is now erroneously small, the function falsely concludes that the rate limit has not been reached ("not depleted"). Consequently, throttling is bypassed, permitting unthrottled disk I/O and enabling a Denial of Service (DoS) condition. The patch resolves this by replacing all critical additions with saturating arithmetic (clamping to `-1` on overflow) and replacing the vulnerable `imul` instructions with full 128-bit `mul` operations that saturate to a hardcoded cap (`0x3b9aca00` or `0xFFFFFFFF`) if the upper 64 bits are nonzero.

**Attacker-Reachable Entry Point & Data Flow:**
1. An I/O request packet (IRP) is issued by a user-mode application (e.g., via `ReadFile` or `WriteFile`).
2. The kernel dispatches this as `IRP_MJ_READ` or `IRP_MJ_WRITE` to `IoRateDispatchReadWrite`.
3. The IRP flows through `IoRateProcessIrpWrapper` -> `IoRateProcessIrpHelper` / `IoRateThrottleIrp`.
4. The system queries the rate limit reason via `IoRateGetReason` -> `IoRateGetRateControlsReason`.
5. `IoRateControlStateGet` queries the specific depletion state.
6. `IoRateIsRateAmountDepleted` executes the vulnerable arithmetic to determine if throttling is required.

### 3. Pseudocode Diff
The following pseudocode reflects the decompiled unpatched logic versus the patched saturating logic. `amount` is the accumulated I/O counter (`r10`), `elapsed` is the current time minus the rate-window start (`r8`, in 100ns units), and the function returns 1 (window satisfied, caller does not throttle) or 0 (window not satisfied, caller throttles this I/O).

```c
// --- UNPATCHED LOGIC ---
uint64_t amount = rate_control->counter[type];        // r10 = [rcx+type*8+0x38]

if (flags & 1)
    amount += rate_control->overflow_field[type];     // VULN: unsaturating add
if (flags & 4)
    amount += rate_control->base_field[type];         // VULN: unsaturating add

uint64_t elapsed = now - rate_control->window_start[type];  // clamped to 0 if negative

// VULN: truncating 64-bit multiply.
// 10000000 * amount wraps when amount > 2^64 / 10000000 (~1.8e12).
uint64_t required_time = 10000000 * amount / 100;

if (elapsed < required_time)
    return 0;   // window not satisfied -> caller throttles
return 1;       // window satisfied -> caller does NOT throttle
// On overflow, required_time wraps small, so 'elapsed < required_time' is
// false; the function returns 1 and throttling is skipped.


// --- PATCHED LOGIC ---
uint64_t amount = rate_control->counter[type];

if (flags & 1) {
    // FIX: saturating addition (clamps to 0xFFFFFFFFFFFFFFFF on overflow)
    amount = saturating_add(amount, rate_control->overflow_field[type]);
}

// FIX: full 128-bit multiply; check the high 64-bit half (RDX).
// If high bits != 0, cap 'required_time' at 0x3b9aca00 (1,000,000,000).
uint128_t product = (uint128_t)amount * 10000000;
uint64_t required_time = ((product >> 64) != 0) ? 0x3b9aca00 : (uint64_t)product / 100;

if (elapsed < required_time)
    return 0;   // correct throttle decision
return 1;
```

### 4. Assembly Analysis
Below is the relevant assembly sequence from the unpatched binary. The patch replaces these regions with overflow checks (e.g., `cmovnb`, `cmovb`), an `int 0x2c` assertion-failure trap, and single-operand `mul` instructions to capture the high 64 bits.

```assembly
; --- UNPATCHED INSTRUCTIONS ---
0x1c000209b: add     r10, qword [rcx+rax*8+0xb0]    ; VULN: Un saturating add #1
0x1c00020cf: add     r10, qword [rcx+0x98]           ; VULN: Un saturating add #2
0x1c00020c3: add     r10, qword [rcx+0xa0]           ; VULN: Un saturating add #3
0x1c00020ba: add     r10, qword [rcx+0xa8]           ; VULN: Un saturating add #4

; ... (context setup) ...

0x1c0002110: imul    rcx, r10, 0x989680              ; VULN: Truncating 64-bit multiply. 
                                                     ; If r10 > 1.8TB, rcx wraps to small value.
0x1c0002117: mul     rcx                             ; Used for division scaling
0x1c000211a: sub     rcx, rdx
0x1c000211d: shr     rcx, 0x1
0x1c0002120: add     rcx, rdx
0x1c0002123: shr     rcx, 0x6

0x1c0002127: cmp     r8, rcx                         ; Throttling decision logic.
                                                     ; Bypassed if rcx wrapped.
0x1c000212a: jb      0x1c00021b5

0x1c0002175: imul    r9, rax                         ; VULN: Secondary truncating multiply
```

### 5. Trigger Conditions
To trigger this logic bypass natively, the following conditions must be met:
1. The target system must be running with Storage QoS (I/O rate limits) actively enforced on a specific volume, virtual machine, or process (via `Set-StorageQoSPolicy` or similar management APIs).
2. An attacker must perform sustained, high-throughput I/O operations (read or write) against the rate-limited target. 
3. The attacker must push data through the volume until the accumulated I/O counter (the byte total the rate-control structure maintains for the bandwidth type) grows past the multiply overflow threshold. This requires sustained high-throughput I/O over an extended period.
4. Once the accumulated counter (`r10`) reaches or exceeds `2^64 / 10000000` (~`0x1AD7F29ABCA`, about 1.8×10^12), the subsequent I/O request will cause the `imul rcx, r10, 0x989680` instruction to silently overflow.
5. **Observable Effect:** The attacker's I/O throughput will cease to be throttled by the OS, exceeding the Storage QoS limitations, potentially starving other processes on the system of disk I/O.

### 6. Exploit Primitive & Development Notes
- **Primitive Provided:** This is a pure logic-bypass / policy-evasion primitive. It provides no arbitrary memory read/write or control-flow hijacking capabilities.
- **Exploitation Steps:** Exploitation simply requires writing a tool (e.g., a targeted file copy or direct disk benchmarking utility like `diskspd`) to flood the target drive. Once the internal counter overflows, the process inherits maximum priority for storage I/O.
- **Mitigations in Place:** Standard memory protections (SMEP, SMAP, kASLR, CFG) are irrelevant, as no memory corruption occurs. The only effective mitigation is patching the driver, as the overflow is inherent to the mathematical logic of the unpatched driver.

### 7. Debugger PoC Playbook
To monitor and validate this vulnerability on an unpatched target, attach WinDbg/KD locally or via network debugging.

**Breakpoints:**
Set a breakpoint on the vulnerable multiplication to monitor the `r10` register growth.
```text
bp iorate_unpatched!IoRateIsRateAmountDepleted+0x90 ".if(@r10 > 0x1AD7F29ABCA){.echo \"Overflow threshold reached!\";.printf \"r10=%p\\n\", @r10;} .else{gc}"
```
*Breakpoint justifications:*
- `0x1c0002110` (`+0x90`): The `imul` instruction. By adding a conditional script, you can monitor `r10` as it approaches the overflow limit (`2^64 / 10000000` ≈ `0x1AD7F29ABCA`, about 1.8×10^12). 
- `0x1c0002127` (`+0xA7`): The `cmp r8, rcx` instruction. You can break here to inspect the wrapped value in `rcx` after the overflow has occurred.

**What to Inspect:**
- Inspect `r10` at `0x1c0002110`. As I/O continues over several minutes, you will see `r10` grow into the terabyte range.
- Step over (`p`) the `imul` instruction at `0x1c0002110`. Inspect `rcx`. If `r10` has crossed the threshold, `rcx` will contain a wildly inaccurate, small integer.
- Continue to `0x1c0002127` and inspect `r8`. After overflow `rcx` is small, so `r8 < rcx` is false and the `jb` at `0x1c000212a` is NOT taken, even though the true (non-overflowed) `rcx` would have made `r8 < rcx` true and taken the branch to the throttle path.
- Check the return value in `eax` (`r11d`) at function return (`0x1c00021ca`). After overflow it is `1`; the caller (`IoRateControlStateGet`) then assigns rate-control reason `0` (no throttling reason for this type), so the I/O proceeds unthrottled. The correct value would have been `0`, driving a non-zero throttle reason. 

**Key Offsets:**
- `0x1c0002110`: Vulnerable scaling multiply (`imul rcx, r10, 0x989680`).
- `0x1c0002127`: Throttling decision comparison (`cmp r8, rcx`).
- `0x1c0009624`: Global data factor used in the secondary overflow multiplication path.

### 8. Changed Functions — Full Triage
- **`IoRateIsRateAmountDepleted`** (Similarity: 83.05%)
  - **Change Type:** Security Relevant.
  - **Key Changes:** The compiler replaced unsafe arithmetic operations with overflow-safe equivalents. Un saturating `add` operations were replaced with logic using `lea` and `cmovae`/`cmovb` to clamp values to `-1` upon overflow. The primary scaling `imul` instruction was heavily rewritten to perform a 128-bit `mul` and check the high `rdx` register, implementing saturation caps (`0x3b9aca00`). A defense-in-depth `int 0x2c` (assertion-failure) trap was added at `0x1c0002211` to catch a violated invariant (the output value `r9` being zero) in the depleted-state logic path.

### 9. Unmatched Functions
There are no unmatched functions in this diff. The developer strictly modified the math logic inside the pre-existing `IoRateIsRateAmountDepleted` function without requiring external helper functions.

### 10. Confidence & Caveats
- **Confidence:** High. The presence of explicit saturating math (`mul`, `cmovae`) replacing an `imul` instruction with a large constant (`0x989680`) is a classic signature of an integer overflow remediation.
- **Assumptions:** The analysis assumes the call chain documented (via `IoRateThrottleIrp`) is the primary path that exercises this logic. 
- **Manual Verification:** A researcher verifying this should manually use `diskspd` or an equivalent tool to generate massive I/O against a QoS-limited volume to prove the physical bypass of the throughput limit, as no crash will occur to passively prove the vulnerability.
