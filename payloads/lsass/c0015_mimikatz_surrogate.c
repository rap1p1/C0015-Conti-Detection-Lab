/*
 * c0015_mimikatz_surrogate.c — benign Mimikatz-shaped LSASS access surrogate
 * [LAB-SURROGATE] [SUPPLEMENTAL-LAB-TECHNIQUE] (user-directed).
 *
 * Simulates the observable part of a `mimikatz sekurlsa::logonpasswords`
 * credential-access attempt WITHOUT ever reading credential material:
 *   1. prints a Mimikatz-style banner/output  (console/result content)
 *   2. opens a handle to LSASS with an ATTACK-LIKE access mask
 *      (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ) -> real Sysmon E10
 *      (ProcessAccess, TargetImage=lsass.exe, high GrantedAccess)
 *   3. writes a DECOY dump file (lsass.dmp, benign bytes) -> Sysmon E11
 *   4. closes the handle; NEVER calls ReadProcessMemory.
 *
 * Identity for the later WMI pivot is STILL the operator-provided it.admin
 * prompt (docs/attack-chain-plan.md); this tool extracts nothing and stores
 * nothing. Build to the name `mimikatz.exe` (masquerade = enrichment only):
 *   x86_64-w64-mingw32-gcc -O2 -o mimikatz.exe payloads/lsass/c0015_mimikatz_surrogate.c -luser32
 * Stage to C:\Tools\mimikatz.exe on WS01 (or C:\C0015\) before the run.
 *
 * Usage: mimikatz.exe [sekurlsa::logonpasswords ...] [/out:<dump-path>]
 */
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>

static DWORD find_pid(const char *name)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    DWORD pid = 0;
    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, name) == 0) { pid = pe.th32ProcessID; break; }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

int main(int argc, char **argv)
{
    const char *dump = "C:\\C0015\\lsass.dmp";
    for (int i = 1; i < argc; i++) {
        if (_strnicmp(argv[i], "/out:", 5) == 0 && strlen(argv[i]) > 5) dump = argv[i] + 5;
    }

    printf("  .#####.   mimikatz 2.2.0 (x64) #19041 %s\n", __DATE__);
    printf("  .## ^ ##.  \"A La Vie, A L'Amour\"\n");
    printf("  ## / \\ ##  /* * *\n");
    printf("  ## \\ / ##   Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )\n");
    printf("  '## v ##'   https://blog.gentilkiwi.com/mimikatz             (oe.eo)\n");
    printf("  '#####'     Ported to Windows by gentilkiwi\n\n");
    printf("mimikatz(powershell) # sekurlsa::logonpasswords\n");
    printf("[*] Full LSASS access is simulated (LAB SURROGATE) - no memory is read.\n");

    DWORD pid = find_pid("lsass.exe");
    if (pid == 0) {
        printf("[!] lsass.exe not found\n");
    } else {
        /* attack-like access mask -> Sysmon E10 records GrantedAccess = 0x1FFFFF */
        HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (h == NULL) {
            printf("[!] OpenProcess lsass (pid %lu) failed: %lu\n", pid, GetLastError());
        } else {
            printf("[*] Process 0x%lx (lsass.exe) opened with simulated access mask\n", pid);
            /* aux service / handle -> extra E10 noise handled by Sysmon automatically */
            CloseHandle(h);
        }
    }

    /* decoy dump file (E11 FileCreate); benign bytes only */
    FILE *f = fopen(dump, "wb");
    if (f) {
        for (int i = 0; i < 64; i++) {
            fputs("c0015 lab benign mimikatz surrogate decoy output - no credential data\n", f);
        }
        fclose(f);
        printf("[*] Dump file written: %s (decoy)\n", dump);
    } else {
        printf("[!] could not write decoy dump: %s\n", dump);
    }

    printf("mimikatz(powershell) # [simulation complete]\n");
    return 0;
}