# Dangerous Windows Kernel API Reference

This document catalogs high-risk Windows kernel APIs commonly used in BYOVD attacks. These will be used in Phase 2 for capability inference.

## Categories of Dangerous Capabilities

### 1. Arbitrary Memory Read/Write

**High Risk APIs:**

#### MmMapIoSpace / MmMapIoSpaceEx
- **Purpose**: Maps physical memory to virtual address space
- **Why Dangerous**: Allows raw physical memory access, bypassing all protections
- **BYOVD Usage**: Read/write arbitrary kernel memory, patch kernel structures
- **Signature**: 
  ```c
  PVOID MmMapIoSpace(
    PHYSICAL_ADDRESS PhysicalAddress,
    SIZE_T NumberOfBytes,
    MEMORY_CACHING_TYPE CacheType
  );
  ```
- **Detection Pattern**: 
  - Call to `MmMapIoSpace` with user-controlled PhysicalAddress
  - Often preceded by IOCTL parameter parsing

#### ZwMapViewOfSection
- **Purpose**: Maps a section object into process address space
- **Why Dangerous**: Can map physical memory section (\\Device\\PhysicalMemory)
- **BYOVD Usage**: Read/write physical memory from user mode
- **Detection Pattern**:
  - Call to `ZwOpenSection` with "\\Device\\PhysicalMemory"
  - Followed by `ZwMapViewOfSection`

#### MmCopyVirtualMemory / MmCopyMemory
- **Purpose**: Copies memory between address spaces
- **Why Dangerous**: Can copy from/to arbitrary processes
- **BYOVD Usage**: Read credentials, inject code into protected processes
- **Detection Pattern**:
  - User-controlled source/destination addresses
  - No validation of target process

### 2. Physical Memory Access

#### ZwOpenSection("\\Device\\PhysicalMemory")
- **Purpose**: Opens handle to physical memory section
- **Why Dangerous**: Direct physical memory access
- **BYOVD Usage**: Foundation for memory manipulation attacks
- **Detection Pattern**:
  - String reference to "\\Device\\PhysicalMemory"
  - Call to `ZwOpenSection` with this string

#### \_\_readmsr / \_\_writemsr
- **Purpose**: Read/write Model-Specific Registers
- **Why Dangerous**: Can manipulate CPU features, disable protections
- **BYOVD Usage**: Disable SMEP/SMAP, modify system behavior
- **Detection Pattern**:
  - Intrinsic functions in disassembly
  - `rdmsr` / `wrmsr` instructions

### 3. Process Manipulation

#### ZwTerminateProcess / PsTerminateSystemThread
- **Purpose**: Terminates processes or threads
- **Why Dangerous**: Can kill security products (EDR/AV)
- **BYOVD Usage**: Blind security monitoring
- **Detection Pattern**:
  - Call with process handle from user mode
  - Target process often a security product

#### PsLookupProcessByProcessId + Direct EPROCESS Manipulation
- **Purpose**: Locates EPROCESS structure, then manipulates it
- **Why Dangerous**: Can elevate privileges, hide processes
- **BYOVD Usage**: Token stealing, process hiding (DKOM)
- **Detection Pattern**:
  - `PsLookupProcessByProcessId` call
  - Followed by writes to EPROCESS offsets (e.g., Token, ActiveProcessLinks)

#### PsCreateSystemThread
- **Purpose**: Creates kernel-mode threads
- **Why Dangerous**: Execute arbitrary kernel code
- **BYOVD Usage**: Persistent kernel execution
- **Detection Pattern**:
  - Call with user-controlled start routine
  - No validation of thread function

### 4. Callback/Hook Manipulation

#### ObRegisterCallbacks (with malicious intent)
- **Purpose**: Registers process/thread callbacks
- **Why Dangerous**: Can block access to processes, hide objects
- **BYOVD Usage**: Protect malware from termination
- **Detection Pattern**:
  - Callback that always returns STATUS_ACCESS_DENIED
  - Selective process blocking

#### Cm/Ex/Ps/ObUnregisterCallback
- **Purpose**: Unregisters callbacks
- **Why Dangerous**: Can remove security product callbacks
- **BYOVD Usage**: Blind EDR monitoring
- **Detection Pattern**:
  - Unregister callbacks not owned by driver
  - Callback handle from user mode

### 5. Driver/Module Loading

#### ZwLoadDriver
- **Purpose**: Loads kernel drivers
- **Why Dangerous**: Load additional malicious drivers
- **BYOVD Usage**: Multi-stage attacks, load unsigned drivers
- **Detection Pattern**:
  - User-controlled driver path
  - Registry key manipulation

#### MmLoadSystemImage
- **Purpose**: Loads kernel modules
- **Why Dangerous**: Bypass driver signature enforcement
- **BYOVD Usage**: Load unsigned code into kernel
- **Detection Pattern**:
  - Non-standard module loading path
  - User-controlled image name

## Detection Heuristics

### Pattern 1: IOCTL with Direct Memory Operations
```
Indicators:
- IOCTL handler receives buffer from user mode
- Buffer contains addresses (detected via pointer-sized values)
- Immediate call to MmMapIoSpace or similar
- No validation of address ranges

Risk Level: CRITICAL
```

### Pattern 2: Process Termination by Name/PID
```
Indicators:
- String comparisons (wcsstr, wcscmp) against process names
- Calls to ZwTerminateProcess
- Target names match security products ("MsMpEng", "avp", etc.)

Risk Level: HIGH
```

### Pattern 3: EPROCESS Token Manipulation
```
Indicators:
- PsLookupProcessByProcessId call
- Add offset (typically 0x360-0x4B8 on Windows 10/11)
- Write operation to calculated address
- Typical offset is Token field in EPROCESS

Risk Level: CRITICAL
```

### Pattern 4: Physical Memory Section Access
```
Indicators:
- Unicode string "PhysicalMemory" in .data or .rdata section
- ZwOpenSection with this string
- ZwMapViewOfSection following
- No IOCTL validation

Risk Level: CRITICAL
```

### Pattern 5: MSR Manipulation
```
Indicators:
- rdmsr/wrmsr instructions
- ECX register set to specific MSR values:
  - 0xC0000082 (IA32_LSTAR - SYSCALL handler)
  - 0x277 (IA32_PAT - memory types)
- User-controlled MSR values

Risk Level: CRITICAL
```

## API Call Chains

### Chain 1: Physical Memory R/W
```
ZwOpenSection("\\Device\\PhysicalMemory") 
  → ZwMapViewOfSection(user_address, user_size)
  → [Read/Write operations]
```

### Chain 2: Process Token Theft
```
PsLookupProcessByProcessId(target_pid)
  → PsLookupProcessByProcessId(system_pid) 
  → [Copy token from System to target]
```

### Chain 3: Driver Unloading/Tampering
```
[Enumerate loaded modules]
  → [Find target driver]
  → MmUnloadSystemImage or direct KLDR_DATA_TABLE_ENTRY manipulation
```

## Opcode Patterns (x64)

### Memory Mapping
```assembly
lea     rcx, [user_address]        ; Address from IOCTL
mov     rdx, [user_size]           ; Size from IOCTL
call    MmMapIoSpace
test    rax, rax                   ; Check if mapping succeeded
```

### Process Lookup
```assembly
mov     rcx, [user_pid]            ; PID from IOCTL
call    PsLookupProcessByProcessId
mov     [rbp+var_8], rax           ; Save EPROCESS pointer
```

### Token Manipulation
```assembly
mov     rax, [rbp+eprocess]        ; EPROCESS
add     rax, 360h                  ; Offset to Token field
mov     rcx, [rax]                 ; Read current token
mov     [target_eprocess+360h], rcx ; Write to target
```

## Scoring Weights (Phase 2)

Suggested risk scoring:

| Capability | Base Score | Modifiers |
|------------|-----------|-----------|
| Physical memory access | 10 | +3 if user-controlled |
| Arbitrary R/W | 9 | +2 if no validation |
| Process termination | 7 | +3 if targets security products |
| Token manipulation | 10 | +1 if copies System token |
| MSR manipulation | 8 | +2 if SMEP/SMAP related |
| Callback removal | 8 | +2 if not owned |
| Driver loading | 6 | +3 if unsigned |

**Confidence Modifiers:**
- Clear API name in imports: +2 confidence
- Clear string references: +1 confidence  
- Indirect call (computed): -1 confidence
- Incomplete disassembly: -2 confidence

## "Because" Tag Examples

For explainable output in Phase 2:

```
Risk: CRITICAL because:
  - Calls MmMapIoSpace with user-controlled address (offset +0x48 from IOCTL buffer)
  - No validation of PhysicalAddress parameter
  - Allows arbitrary physical memory access
```

```
Risk: HIGH because:
  - Terminates processes by PID from user input
  - String comparison against "MsMpEng.exe" detected
  - Likely targets Windows Defender
```

```
Risk: MEDIUM because:
  - EPROCESS structure access detected
  - Offset +0x360 written (typical Token location)
  - Could not confirm source of token value (incomplete disassembly)
```

## References for Phase 2 Implementation

1. Windows Driver Kit documentation for API signatures
2. Capstone instruction groups for categorization
3. Volatility3's symbol information for structure offsets
4. POPKORN paper for capability classification methodology
5. LOLDrivers database for known dangerous patterns

## Next Steps

Phase 2 Development:
1. Implement pattern matching for these APIs
2. Build opcode recognition engine
3. Create scoring algorithm with weights
4. Add "because" tag generation
5. Test against known BYOVD samples

---

**Note**: This is a living document. Add new APIs and patterns as you discover them during testing.
