#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

// Custom system error printing function; prints the given text followed by the last error code and its system message
static void PrintError(const char* text) {
    DWORD err = GetLastError();    // Retrieve the last-error code for the calling thread
    LPSTR buf = nullptr;           // Buffer that will receive the formatted message (allocated by FormatMessageA)

    FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |  // dwFlags: Allocate a buffer for the message
        FORMAT_MESSAGE_FROM_SYSTEM |               // dwFlags: Get the message from the system message table
        FORMAT_MESSAGE_IGNORE_INSERTS,             // dwFlags: Do not expand insert sequences in the message
        nullptr,                         // lpSource: NULL for system messages
        err,                          // dwMessageId: The error code to look up
        0,                           // dwLanguageId: 0 for default language
        (LPSTR)&buf,                     // lpBuffer: Pointer to variable that receives the allocated buffer pointer
        0,                                  // nSize: 0 when using FORMAT_MESSAGE_ALLOCATE_BUFFER
        nullptr);                       // Arguments: NULL for no insert values

    if (buf) {   // Strip trailing CR/LF from the message
        char* p = buf;
        while (*p && *p != '\r' && *p != '\n') ++p;
        *p = '\0';
    }
    printf("%s (0x%lX: %s)\n", text, err, buf ? buf : "<unknown>");
    if (buf) LocalFree(buf);   // Free the buffer allocated by FormatMessageA
}

// Enable SeDebugPrivilege in the current process so we can open other processes for token access
static BOOL EnableDebugPrivilege(void) {
    HANDLE hToken = nullptr;     // Handle to the current process's access token
    TOKEN_PRIVILEGES tp = {};    // Structure that describes the privilege to enable
    LUID luid = {};              // Locally unique identifier for the privilege

    if (!OpenProcessToken(
        GetCurrentProcess(),                    // ProcessHandle: Handle to the process whose token is opened
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,  // DesiredAccess: Need to adjust privileges and query the token
        &hToken)) {                               // TokenHandle: Pointer that receives the token handle
        PrintError("OpenProcessToken (current) failed");
        return FALSE;
    }

    if (!LookupPrivilegeValueW(
        nullptr,           // lpSystemName: NULL for local system
        L"SeDebugPrivilege",     // lpName: Name of the privilege to look up
        &luid)) {                // lpLuid: Pointer that receives the LUID for the privilege
        PrintError("LookupPrivilegeValue(SeDebugPrivilege) failed");
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;                                // Number of privileges in the array
    tp.Privileges[0].Luid = luid;                         // LUID of the privilege to enable
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;   // Enable the privilege

    BOOL ok = AdjustTokenPrivileges(
        hToken,               // TokenHandle: Handle to the token to modify
        FALSE,       // DisableAllPrivileges: FALSE so only the specified privilege is changed
        &tp,                     // NewState: Pointer to TOKEN_PRIVILEGES with the new state
        sizeof(tp),          // BufferLength: Size of the NewState buffer
        nullptr,            // PreviousState: NULL when not needed
        nullptr);            // ReturnLength: NULL when not needed
    CloseHandle(hToken);
    if (!ok) {
        PrintError("AdjustTokenPrivileges(SeDebugPrivilege) failed");
        return FALSE;
    }
    return TRUE;
}

// Returns TRUE if the current process has an elevated token (e.g. running as Administrator)
static BOOL IsProcessElevated(void) {
    HANDLE hToken = nullptr;     // Handle to the current process's token
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        return FALSE;
    TOKEN_ELEVATION elev = {};   // Structure that receives the elevation status
    DWORD size = 0;              // Variable that receives the size of the elevation structure
    BOOL ok = GetTokenInformation(
        hToken,                   // TokenHandle: Handle to the access token
        TokenElevation, // TokenInformationClass: Request elevation information
        &elev,               // TokenInformation: Buffer that receives TOKEN_ELEVATION
        sizeof(elev),  // TokenInformationLength: Size of the buffer
        &size);                  // ReturnLength: Receives the size of the returned data
    CloseHandle(hToken);
    return ok && elev.TokenIsElevated;
}

// Re-launch this executable with "Run as administrator" (UAC). If outPath is non-null, elevated process writes results there and caller waits and prints that file to this CLI
static BOOL RelaunchElevated(int argc, char* argv[], const char* outPath) {
    char selfPath[MAX_PATH];     // Buffer to receive the full path of this executable
    if (!GetModuleFileNameA(
        nullptr,               // hModule: NULL to get the path of the executable file of the current process
        selfPath,           // lpFilename: Buffer that receives the path
        sizeof(selfPath)))       // nSize: Size of the buffer in characters
        return FALSE;

    char params[MAX_PATH * 2] = "";   // Buffer for command-line parameters (PID and optional output path)
    const char* lpParams = (argc >= 2) ? argv[1] : "";
    if (argc >= 2 && outPath && outPath[0]) {
        (void)snprintf(params, sizeof(params), "%s \"%s\"", argv[1], outPath);   // Build "PID \"outPath\"" for elevated process
        lpParams = params;
    }

    SHELLEXECUTEINFOA sei = {};            // Structure that specifies how to run the executable
    sei.cbSize = sizeof(sei);              // Set the size of the structure
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;   // fMask: Return process handle so we can wait for the elevated process
    sei.lpVerb = "runas";                  // lpVerb: "runas" to request elevation (UAC)
    sei.lpFile = selfPath;                 // lpFile: Path to the executable to run
    sei.lpParameters = lpParams;           // lpParameters: Command-line arguments (PID and optional result file path)
    sei.nShow = SW_NORMAL;                 // nShow: Show the new process window normally

    if (!ShellExecuteExA(&sei))
        return FALSE;

    // If we passed an output path, wait for the elevated process to finish and print its result file to this CLI
    if (sei.hProcess && outPath && outPath[0]) {
        WaitForSingleObject(sei.hProcess, 60000);   // dwMilliseconds: Wait up to 60 seconds for the elevated process to exit
        CloseHandle(sei.hProcess);
        char buf[4096];          // Buffer to read result file lines
        FILE* f = fopen(outPath, "r");
        if (f) {
            while (fgets(buf, sizeof(buf), f))
                printf("%s", buf);
            fclose(f);
            DeleteFileA(outPath);   // Remove the temporary result file
        }
    }
    return TRUE;
}

// When set by main, result lines are written here so the non-elevated parent can print them in the original CLI
static FILE* g_resultFile = nullptr;

// Print formatted output to stdout and to g_resultFile (if set); used so elevated process output is visible in the parent CLI
static void Report(const char* fmt, ...) {
    va_list ap, aq;         // ap: argument list for vprintf; aq: copy for vfprintf (va_list is consumed by use)
    va_start(ap, fmt);   // Initialize ap to retrieve arguments after fmt
    va_copy(aq, ap);  // Copy ap so we can use the same arguments twice (vprintf consumes ap)
    vprintf(fmt, ap);
    va_end(ap);
    if (g_resultFile) {
        vfprintf(g_resultFile, fmt, aq);
        fflush(g_resultFile);   // Ensure output is written so parent can read the file
    }
    va_end(aq);
}

int main(int argc, char* argv[]) {
    DWORD pid = 0;   // Process ID of the target process whose token we will impersonate

    // Parse the PID from the command line (argv[1])
    if (argc >= 2) {
        char* end = nullptr;                    // Pointer to the first invalid character after the number
        unsigned long p = strtoul(argv[1], &end, 10);   // Convert string to unsigned long in base 10
        pid = (p != 0 && p <= 0xFFFFFFFFu) ? (DWORD)p : 0;   // Valid PID must be non-zero and fit in DWORD
    }
    if (pid == 0) {
        printf("Usage: %s <PID>\n", argc ? argv[0] : "Token-Impersonation-and-Create-Process-with-Token.exe");
        printf("  Spawns cmd.exe with the security token of the given process.\n");
        return 1;
    }

    // When elevated process was launched with an output path (argc >= 3), write results there for the parent to print
    if (argc >= 3 && argv[2][0]) {
        g_resultFile = fopen(argv[2], "w");   // Open the result file so Report() can write output for the parent CLI
    }

    // When launched via UAC (runas), we often have no console; allocate one so output is visible in the elevated window
    BOOL needPause = FALSE;       // If TRUE, pause at exit so the user can read the console (e.g. when we allocated it)
    if (!GetConsoleWindow()) {    // GetConsoleWindow: Returns NULL if this process has no console
        if (AllocConsole()) {     // Create a new console for this process
            (void)freopen("CONOUT$", "w", stdout);   // Reopen stdout so it writes to the new console
            (void)freopen("CONOUT$", "w", stderr);   // Reopen stderr so it writes to the new console
            needPause = TRUE;     // Pause at end so the console window does not close immediately
        }
    }

    if (!EnableDebugPrivilege()) {
        Report("Warning: Could not enable SeDebugPrivilege; opening some processes may fail.\n");
    }

    // Open the target process so we can access its token (required for OpenProcessToken)
    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION,
        FALSE,
        pid);

    if (!hProcess) {
        DWORD err = GetLastError();
        if (err == 5 && !IsProcessElevated()) {   // ERROR_ACCESS_DENIED and we are not elevated
            printf("Access denied. Requesting elevation (UAC)...\n");
            char outPath[MAX_PATH];   // Buffer for the temporary result file path
            if (GetTempPathA(MAX_PATH, outPath)) {
                char* p = outPath + strlen(outPath);   // Point to the end of the temp directory path
                (void)snprintf(p, (size_t)(MAX_PATH - (p - outPath)), "TokenImp_%lu.txt", GetCurrentProcessId());   // Append unique filename
                if (RelaunchElevated(argc, argv, outPath))
                    return 0;   // Elevated process ran; parent already printed its output from the result file
            } else {
                if (RelaunchElevated(argc, argv, nullptr))
                    return 0;
            }
        }
        Report("PID %lu is not available or not running.\n", pid);
        PrintError("OpenProcess failed - is the PID valid and process running?");
        if (err == 5)
            Report("If the target is elevated or protected, approve the UAC prompt or run this program as Administrator.\n");
        if (g_resultFile) { fclose(g_resultFile); g_resultFile = nullptr; }
        return 2;
    }

    Report("PID %lu is running and accessible.\n", pid);

    // Open the target process's access token so we can duplicate it
    HANDLE hToken = nullptr;   // Handle to the target process's token
    if (!OpenProcessToken(
        hProcess,                         // ProcessHandle: Handle to the process whose token to open
        TOKEN_DUPLICATE | TOKEN_QUERY,    // DesiredAccess: Need to duplicate the token and query it
        &hToken)) {                         // TokenHandle: Pointer that receives the token handle
        PrintError("OpenProcessToken failed");
        CloseHandle(hProcess);
        if (g_resultFile) { fclose(g_resultFile); g_resultFile = nullptr; }
        return 3;
    }
    CloseHandle(hProcess);

    // Duplicate the token so we can spawn a process (cmd.exe) using the impersonated token
    HANDLE hDupToken = nullptr;   // Handle to the duplicated (impersonated) token
    if (!DuplicateTokenEx(
        hToken,                    // ExistingTokenHandle: Token to duplicate
        TOKEN_ALL_ACCESS,         // DesiredAccess: Request full access to the new token
        nullptr,                // TokenAttributes: NULL for default security
        SecurityImpersonation, // ImpersonationLevel: Impersonation level of the new token
        TokenPrimary,                   // TokenType: Primary token so it can be used to create a process
        &hDupToken)) {                 // NewTokenHandle: Pointer that receives the new token handle
        PrintError("DuplicateTokenEx failed");
        CloseHandle(hToken);
        if (g_resultFile) { fclose(g_resultFile); g_resultFile = nullptr; }
        return 4;
    }
    CloseHandle(hToken);   // No longer need the original token

    // Print the impersonated token handle and identifiers (TokenId, AuthenticationId) to the CLI
    Report("Impersonated token handle: %p\n", (void*)hDupToken);
    TOKEN_STATISTICS ts = {};   // Structure that receives token statistics (TokenId, AuthId, etc.)
    DWORD tsLen = 0;            // Variable that receives the size of the returned data
    if (GetTokenInformation(
        hDupToken,                   // TokenHandle: Handle to the access token
        TokenStatistics,   // TokenInformationClass: Request token statistics
        &ts,                    // TokenInformation: Buffer that receives TOKEN_STATISTICS
        sizeof(ts),       // TokenInformationLength: Size of the buffer
        &tsLen)) {                  // ReturnLength: Receives the size of the returned data
        Report("Impersonated token TokenId:      %08lX-%08lX\n", ts.TokenId.HighPart, ts.TokenId.LowPart);
        Report("Impersonated token AuthId (LUID): %08lX-%08lX\n", ts.AuthenticationId.HighPart, ts.AuthenticationId.LowPart);
    }

    // Spawn cmd.exe using the duplicated (impersonated) token so it runs in the target process's security context
    WCHAR cmdLine[] = L"cmd.exe";             // Command line for the new process
    STARTUPINFOW si = { sizeof(si) };     // Structure that specifies how the new process window should appear
    PROCESS_INFORMATION pi = {};              // Structure that receives process and thread handles and IDs

    // Attempt to create a process using the duplicated user token with profile loading
    BOOL created = CreateProcessWithTokenW(
        hDupToken,                     // hToken: Handle to the primary token (the duplicated token)
        LOGON_WITH_PROFILE,      // dwLogonFlags: Load the user's profile so the process has full environment
        nullptr,            // lpApplicationName: NULL; application is specified in lpCommandLine
        cmdLine,                // lpCommandLine: Command line to execute (cmd.exe)
        CREATE_NEW_CONSOLE,   // dwCreationFlags: New process gets its own console window
        nullptr,                // lpEnvironment: NULL to use the token's environment
        nullptr,           // lpCurrentDirectory: NULL to use the system directory
        &si,                    // lpStartupInfo: Pointer to STARTUPINFOW structure
        &pi);            // lpProcessInformation: Pointer that receives process and thread info

    if (!created) {
        Report("CreateProcessWithTokenW failed, trying CreateProcessAsUserW...\n");
        // If CreateProcessWithTokenW fails, try CreateProcessAsUserW (legacy method)
        created = CreateProcessAsUserW(
            hDupToken,                   // hToken: Handle to the primary token
            nullptr,          // lpApplicationName: NULL
            cmdLine,              // lpCommandLine: Command line (cmd.exe)
            nullptr,        // lpProcessAttributes: NULL for default
            nullptr,         // lpThreadAttributes: NULL for default
            FALSE,              // bInheritHandles: New process does not inherit handles
            CREATE_NEW_CONSOLE, // dwCreationFlags: New console for the process
            nullptr,              // lpEnvironment: NULL
            nullptr,         // lpCurrentDirectory: NULL
            &si,                  // lpStartupInfo: Pointer to STARTUPINFOW
            &pi);          // lpProcessInformation: Pointer that receives process and thread info
    }

    CloseHandle(hDupToken);   // Token is no longer needed after process creation

    if (!created) {
        PrintError("CreateProcessWithTokenW and CreateProcessAsUserW failed");
        if (g_resultFile) { fclose(g_resultFile); g_resultFile = nullptr; }
        return 5;
    }

    Report("Spawned cmd.exe with impersonated token from PID %lu. Spawned process PID: %lu.\n", pid, pi.dwProcessId);
    CloseHandle(pi.hThread);   // Free the thread handle; we do not need to wait on the new process
    CloseHandle(pi.hProcess);  // Free the process handle
    if (g_resultFile) { fclose(g_resultFile); g_resultFile = nullptr; }
    // If we allocated a console (e.g. when launched elevated via UAC), pause so the user can read the output
    if (needPause) {
        printf("Press Enter to exit.\n");
        (void)getchar();   // Wait for user input so the console window does not close immediately
    }
    return 0;
}
