/*
 * c0015_143_surrogate.c — benign 143.dll surrogate [LAB-SURROGATE]
 *
 * Phase-2 S8/S9 role: mirrors the C0015 "143.dll" Cobalt Strike beacon that was
 * placed on the target and executed via WMI -> rundll32 (T1047/T1218.011). Lab
 * version is benign and config-driven:
 *   - load by rundll32 (entrypoint DllRegisterServer / LabEntry)
 *   - write an execution marker (E11 proof the export ran)
 *   - spawn the session-2 beacon (C2-SIM stage=phase7-session2) from
 *     C:\C0015\config-phase7.ini
 * NO injection into svchost/system; no arbitrary shell; no secrets.
 *
 * Control path: if config is missing the export returns immediately (no side
 * effects), same discipline as payloads/dll/c0015_bootstrap_dll.c.
 *
 * Build (Kali / any mingw host):
 *   x86_64-w64-mingw32-gcc -shared -o c0015_143_surrogate.dll payloads/dll/c0015_143_surrogate.c -luser32 -lshlwapi
 * Deploy to C:\C0015\c0015_143_surrogate.dll on FS01 (see playbook S8a).
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>

static void ini_get(const char *section, const char *key, char *out, size_t outsz)
{
    GetPrivateProfileStringA(section, key, "", out, (DWORD)outsz,
                             "C:\\C0015\\config-phase7.ini");
}

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID reserved)
{
    (void)h; (void)reason; (void)reserved;
    return TRUE;
}

__declspec(dllexport) HRESULT LabEntry(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow)
{
    (void)hwnd; (void)hinst; (void)lpszCmdLine; (void)nCmdShow;

    char marker_name[128] = {0};
    char beacon_cmd[512] = {0};
    ini_get("bootstrap", "marker_name", marker_name, sizeof(marker_name));
    ini_get("beacon", "beacon_cmd", beacon_cmd, sizeof(beacon_cmd));

    if (marker_name[0] == '\0') {
        return S_FALSE; /* control path: no config -> no side effects */
    }

    /* observable 1: execution marker (E11 FileCreate) */
    char marker_path[MAX_PATH];
    wsprintfA(marker_path, "C:\\C0015\\%s", marker_name);
    HANDLE f = CreateFileA(marker_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (f != INVALID_HANDLE_VALUE) {
        const char *text = "c0015 lab benign 143 surrogate executed\n";
        DWORD written = 0;
        WriteFile(f, text, (DWORD)strlen(text), &written, NULL);
        CloseHandle(f);
    }

    /* observable 2: session-2 beacon (config-driven) -> phase7-session2 register */
    if (beacon_cmd[0] != '\0') {
        STARTUPINFOA si;
        PROCESS_INFORMATION pi;
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        ZeroMemory(&pi, sizeof(pi));
        char cmdline[600];
        wsprintfA(cmdline, "%s", beacon_cmd);
        if (CreateProcessA(NULL, cmdline, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                           NULL, NULL, &si, &pi)) {
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
    }
    return S_OK;
}

/* rundll32 entrypoint: forwards to the same benign behavior */
__declspec(dllexport) HRESULT DllRegisterServer(void)
{
    return LabEntry(NULL, NULL, NULL, 0);
}