/*
 * Build (MSVC):  cl /EHsc "Parent PID Spoofing.cpp"
 * Build (MinGW): g++ -o Parent-PID-Spoofing.exe "Parent PID Spoofing.cpp" -mconsole
 */

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600  /* Vista+ for PROC_THREAD_ATTRIBUTE_PARENT_PROCESS */
#endif

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef PROCESS_CREATE_PROCESS
#define PROCESS_CREATE_PROCESS 0x0080
#endif

// Custom system error printing function; prints the given text followed by the last error code and its system message
static void PrintError(const char* text) {
    DWORD err = GetLastError();    // Retrieve the last-error code for the calling thread
    LPSTR buf = nullptr;           // Buffer that will receive the formatted message (allocated by FormatMessageA)

    FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |  // dwFlags: Allocate a buffer for the message
        FORMAT_MESSAGE_FROM_SYSTEM |      // dwFlags: Get the message from the system message table
        FORMAT_MESSAGE_IGNORE_INSERTS,    // dwFlags: Do not expand insert sequences in the message
        nullptr,                          // lpSource: NULL for system messages
        err,                              // dwMessageId: The error code to look up
        0,                                // dwLanguageId: 0 for default language
        (LPSTR)&buf,                      // lpBuffer: Pointer to variable that receives the allocated buffer pointer
        0,                                // nSize: 0 when using FORMAT_MESSAGE_ALLOCATE_BUFFER
        nullptr);                         // Arguments: NULL for no insert values

    if (buf) {   // Strip trailing CR/LF from the message
        char* p = buf;
        while (*p && *p != '\r' && *p != '\n') ++p;
        *p = '\0';
    }
    printf("%s (0x%lX: %s)\n", text, err, buf ? buf : "<unknown>");
    if (buf) LocalFree(buf);   // Free the buffer allocated by FormatMessageA
}

// Enable SeDebugPrivilege in the current process so we can open other processes for PPID spoofing
static BOOL EnableDebugPrivilege(void) {
    HANDLE hToken = nullptr;     // Handle to the current process's access token
    TOKEN_PRIVILEGES tp = {};    // Structure that describes the privilege to enable
    LUID luid = {};              // Locally unique identifier for the privilege

    if (!OpenProcessToken(
        GetCurrentProcess(),                    // ProcessHandle: Handle to the process whose token is opened
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,  // DesiredAccess: Need to adjust privileges and query the token
        &hToken)) {                             // TokenHandle: Pointer that receives the token handle
        PrintError("OpenProcessToken (current) failed");
        return FALSE;
    }

    if (!LookupPrivilegeValueW(
        nullptr,              // lpSystemName: NULL for local system
        L"SeDebugPrivilege",  // lpName: Name of the privilege to look up
        &luid)) {             // lpLuid: Pointer that receives the LUID for the privilege
        PrintError("LookupPrivilegeValue(SeDebugPrivilege) failed");
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;                                // Number of privileges in the array
    tp.Privileges[0].Luid = luid;                         // LUID of the privilege to enable
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;   // Enable the privilege

    BOOL ok = AdjustTokenPrivileges(
        hToken,      // TokenHandle: Handle to the token to modify
        FALSE,       // DisableAllPrivileges: FALSE so only the specified privilege is changed
        &tp,         // NewState: Pointer to TOKEN_PRIVILEGES with the new state
        sizeof(tp),  // BufferLength: Size of the NewState buffer
        nullptr,     // PreviousState: NULL when not needed
        nullptr);    // ReturnLength: NULL when not needed
    CloseHandle(hToken);
    if (!ok) {
        PrintError("AdjustTokenPrivileges(SeDebugPrivilege) failed");
        return FALSE;
    }
    return TRUE;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <PID>\n", argc ? argv[0] : "Parent-PID-Spoofing.exe");
        printf("  Spawns cmd.exe with the given process as its parent (PPID spoofing).\n");
        return 1;
    }

    unsigned long pid = strtoul(argv[1], nullptr, 10);   // Parse the chosen parent PID from the command line
    if (pid == 0 || pid == 0xFFFFFFFFUL) {
        printf("Invalid PID: %s\n", argv[1]);
        return 1;
    }

    if (!EnableDebugPrivilege())
        return 1;

    // Open the process that will be the (spoofed) parent; handle must have PROCESS_CREATE_PROCESS access right
    HANDLE hParent = OpenProcess(
        PROCESS_CREATE_PROCESS,  // dwDesiredAccess: Required to use this handle as parent in UpdateProcThreadAttribute
        FALSE,                   // bInheritHandle: Do not inherit the handle
        (DWORD)pid);             // dwProcessId: PID of the process to open
    if (!hParent) {
        PrintError("OpenProcess(parent) failed");
        return 1;
    }

    SIZE_T attrSize = 0;   // Variable that receives the size required for the attribute list
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attrSize);   // Get required size (lpAttributeList NULL)
    LPPROC_THREAD_ATTRIBUTE_LIST attr = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(
        GetProcessHeap(),  // hHeap: Heap of the current process
        0,                 // dwFlags: 0
        attrSize);         // dwBytes: Size returned above
    if (!attr) {
        PrintError("HeapAlloc(attribute list) failed");
        CloseHandle(hParent);
        return 1;
    }
    if (!InitializeProcThreadAttributeList(
        attr,          // lpAttributeList: Buffer to initialize
        1,             // dwAttributeCount: Number of attributes we will add (one: parent process)
        0,             // dwFlags: Reserved, must be 0
        &attrSize)) {  // lpSize: Size of the buffer
        PrintError("InitializeProcThreadAttributeList failed");
        HeapFree(GetProcessHeap(), 0, attr);
        CloseHandle(hParent);
        return 1;
    }
    if (!UpdateProcThreadAttribute(
        attr,                                  // lpAttributeList: The attribute list to update
        0,                                     // dwFlags: Reserved, must be 0
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,  // Attribute: Set the parent process of the new process
        &hParent,                              // lpValue: Pointer to the handle of the spoofed parent process
        sizeof(HANDLE),                        // cbSize: Size of the handle
        nullptr,                               // lpPreviousValue: NULL when not needed
        nullptr)) {                            // lpReturnSize: NULL when not needed
        PrintError("UpdateProcThreadAttribute(PARENT_PROCESS) failed");
        DeleteProcThreadAttributeList(attr);
        HeapFree(GetProcessHeap(), 0, attr);
        CloseHandle(hParent);
        return 1;
    }

    STARTUPINFOEXW si = {};                       // Extended startup info so we can pass the attribute list (parent PPID)
    si.StartupInfo.cb = sizeof(STARTUPINFOEXW);   // Size of the structure
    si.lpAttributeList = attr;                    // List that includes PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
    PROCESS_INFORMATION pi = {};                  // Receives the new process and thread handles and IDs
    wchar_t cmdLine[] = L"cmd.exe";               // Command line for the child process (writable buffer for CreateProcessW)

    if (!CreateProcessW(
            nullptr,                          // lpApplicationName: NULL; use lpCommandLine
            cmdLine,                          // lpCommandLine: Command line to execute (cmd.exe)
            nullptr,                          // lpProcessAttributes: Default security
            nullptr,                          // lpThreadAttributes: Default security
            FALSE,                            // bInheritHandles: Do not inherit handles
            EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE,   // dwCreationFlags: Use STARTUPINFOEX and new console
            nullptr,                          // lpEnvironment: Use parent's environment
            nullptr,                          // lpCurrentDirectory: Use parent's current directory
            (LPSTARTUPINFOW)&si,              // lpStartupInfo: Extended startup info with spoofed parent
            &pi)) {                           // lpProcessInformation: Receives new process/thread info
        PrintError("CreateProcess failed");
        DeleteProcThreadAttributeList(attr);
        HeapFree(GetProcessHeap(), 0, attr);
        CloseHandle(hParent);
        return 1;
    }

    printf("Spawned cmd.exe with PID %lu; spoofed parent PID = %lu\n", pi.dwProcessId, pid);
    DeleteProcThreadAttributeList(attr);   // Free the attribute list before freeing the buffer
    HeapFree(GetProcessHeap(), 0, attr);
    CloseHandle(hParent);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}

