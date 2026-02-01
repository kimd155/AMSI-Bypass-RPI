# AMSI Bypass via Remote Process Injection

A technical demonstration developed as part of my learning in MalDev Academy, exploring AMSI evasion concepts on Windows. The project examines process injection and remote memory manipulation techniques used to alter AMSI behavior in PowerShell prior to execution, strictly for educational and research purposes.

## Overview

This tool spawns a PowerShell process in a suspended state, loads the AMSI library into the target process, patches the `AmsiScanBuffer` function in remote process memory, and then resumes execution. The result is a PowerShell session with AMSI scanning disabled.

## Technical Implementation

### Architecture

The implementation uses the following Windows API techniques:

1. **Process Creation with Suspension**: PowerShell is created using `CreateProcessA` with the `CREATE_SUSPENDED` flag
2. **Remote DLL Loading**: `amsi.dll` is loaded into the target process via `CreateRemoteThread` and `LoadLibraryA`
3. **Memory Patching**: The `AmsiScanBuffer` function is patched using `WriteProcessMemory` after adjusting memory protection with `VirtualProtectEx`
4. **Process Resumption**: The main thread is resumed using `ResumeThread` after patching completes

### Patch Mechanism

The patch replaces the beginning of `AmsiScanBuffer` with the following x86-64 assembly:

```asm
xor eax, eax    ; Set return value to 0 (success)
ret             ; Return immediately
```

This causes AMSI to always return success without performing any scanning.

### Key Functions

- `PatchRemoteAMSI()`: Locates and patches the AMSI function in the remote process
- `EnumProcessModules()`: Finds the base address of `amsi.dll` in the target process
- `VirtualProtectEx()`: Modifies memory protection to allow writing to executable code
- `WriteProcessMemory()`: Writes the patch bytes to the remote process

## Build Instructions

### Requirements

- Windows 10/11 (x64)
- Microsoft Visual Studio 2022 or later
- Windows SDK

### Compilation

Using Visual Studio Developer Command Prompt:

```cmd
cl.exe /O2 /GS- /Fe:final.exe final.c Psapi.lib /link /SUBSYSTEM:WINDOWS /ENTRY:WinMainCRTStartup
```

Compiler flags:
- `/O2`: Optimize for speed
- `/GS-`: Disable buffer security checks
- `/SUBSYSTEM:WINDOWS`: Create a GUI application (no console window)
- `/ENTRY:WinMainCRTStartup`: Specify entry point

## Usage

Execute the compiled binary:

```cmd
final.exe
```

A PowerShell window will open with AMSI bypassed. You can verify by running:

```powershell
'AMSI Test Sample: 7e72c3ce-861b-4339-8740-0ac1484c1386'
```

This test string normally triggers AMSI detection but will execute without errors when AMSI is bypassed.

## Detection Considerations

This technique may be detected by:

- **Behavioral Analysis**: Process creation with suspended state followed by remote thread creation
- **Memory Scanning**: Modifications to AMSI.dll in memory
- **API Monitoring**: Calls to `VirtualProtectEx` and `WriteProcessMemory` targeting security-critical modules
- **Signature Detection**: Known patch patterns in AMSI functions

## Defensive Measures

Organizations can defend against this technique by:

1. **Protected Process Light (PPL)**: Enable PPL for PowerShell to prevent memory manipulation
2. **Code Integrity**: Use Windows Defender Application Control (WDAC) to enforce code integrity
3. **EDR Solutions**: Deploy endpoint detection and response tools that monitor process injection
4. **Logging**: Enable detailed process creation and thread creation logging
5. **Behavioral Monitoring**: Alert on suspended process creation followed by remote thread injection

## Legal Disclaimer

This tool is provided for educational and authorized security research purposes only. Unauthorized use of this tool to bypass security controls on systems you do not own or have explicit permission to test is illegal and unethical.

Users are responsible for ensuring compliance with all applicable laws and regulations. The authors assume no liability for misuse of this software.

## Research and Development Environment

For security research purposes, it is recommended to:

1. Use isolated virtual machines or dedicated test systems
2. To Compile it, you must add the research directories to antivirus exclusions:
   ```powershell
   Add-MpPreference -ExclusionPath "C:\Path\To\Research"
   ```

## Technical References

- [Microsoft AMSI Documentation](https://docs.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal)
- [Process Injection Techniques](https://attack.mitre.org/techniques/T1055/)
- [Windows API Reference](https://docs.microsoft.com/en-us/windows/win32/api/)

## Version History

- **v1.0**: Initial release with remote process injection and AMSI patching

## License

This project is released for educational purposes. Use at your own risk and only on systems you are authorized to test.
