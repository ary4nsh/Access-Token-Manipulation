/*
 * Build (MSVC):  cl /EHsc "Make and Impersonate Token.cpp"
 * Build (MinGW): g++ -o Make-and-Impersonate-Token.exe "Make and Impersonate Token.cpp" -lwtsapi32 -lnetapi32 -ladvapi32 -mconsole
 *               (main() is used as entry point so the linker uses the console CRT.)
 */

#define _CRT_SECURE_NO_WARNINGS
#define UNICODE
#define _UNICODE

#include <windows.h>
#include <lm.h>
#include <wtsapi32.h>
#include <cstdio>
#include <iostream>
#include <vector>
#include <string>
#include <set>
#include <algorithm>

#ifdef _MSC_VER
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "advapi32.lib")
#endif

// Custom system error printing function; prints the given text followed by the last error code and its system message
static void PrintError(const char* text) {
    DWORD err = GetLastError();    // Retrieve the last-error code for the calling thread
    LPSTR buf = nullptr;           // Buffer that will receive the formatted message (allocated by FormatMessageA)

    FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | // dwFlags: Allocate a buffer for the message
        FORMAT_MESSAGE_FROM_SYSTEM |              // dwFlags: Get the message from the system message table
        FORMAT_MESSAGE_IGNORE_INSERTS,            // dwFlags: Do not expand insert sequences in the message
        nullptr,                        // lpSource: NULL for system messages
        err,                         // dwMessageId: The error code to look up
        0,                          // dwLanguageId: 0 for default language
        (LPSTR)&buf,                    // lpBuffer: Pointer to variable that receives the allocated buffer pointer
        0,                                 // nSize: 0 when using FORMAT_MESSAGE_ALLOCATE_BUFFER
        nullptr);                      // Arguments: NULL for no insert values

    if (buf) {   // Strip trailing CR/LF from the message
        char* p = buf;
        while (*p && *p != '\r' && *p != '\n') ++p;
        *p = '\0';
    }
    printf("%s (0x%lX: %s)\n", text, err, buf ? buf : "<unknown>");
    if (buf) LocalFree(buf);   // Free the buffer allocated by FormatMessageA
}

// Get list of usernames that currently have a logon session on this machine
static std::set<std::wstring> GetLoggedInUserNames() {
    std::set<std::wstring> names;            // Set of logged-in usernames (lowercase)
    PWTS_SESSION_INFO pSessions = nullptr;   // Buffer that receives the session list (allocated by WTSEnumerateSessions)
    DWORD sessionCount = 0;                  // Variable that receives the number of sessions returned

    if (!WTSEnumerateSessions(
        WTS_CURRENT_SERVER_HANDLE,   // hServer: Handle of the terminal server (local machine)
        0,                          // Reserved: must be 0
        1,                           // Version: 1
        &pSessions,            // ppSessionInfo: Pointer that receives the session array
        &sessionCount)) {             // pCount: Pointer that receives the number of sessions
        return names;
    }

    for (DWORD i = 0; i < sessionCount; ++i) {
        if (pSessions[i].State != WTSActive && pSessions[i].State != WTSDisconnected)
            continue;

        LPWSTR pUserName = nullptr;   // Buffer that receives the user name (allocated by WTSQuerySessionInformation)
        DWORD bytesReturned = 0;      // Variable that receives the size of the returned data
        if (WTSQuerySessionInformation(
                WTS_CURRENT_SERVER_HANDLE,   // hServer: Handle of the terminal server
                pSessions[i].SessionId,    // SessionId: Session to query
                WTSUserName,            // WTSInfoClass: Request the user name
                &pUserName,                 // ppBuffer: Pointer that receives the buffer (allocated by API)
                &bytesReturned)       // pBytesReturned: Receives the size of the buffer
                && pUserName && pUserName[0]) {
            std::wstring u(pUserName);
            std::transform(u.begin(), u.end(), u.begin(), ::towlower);
            names.insert(u);
        }
        if (pUserName)
            WTSFreeMemory(pUserName);   // Free the buffer allocated by WTSQuerySessionInformation
    }

    if (pSessions)
        WTSFreeMemory(pSessions);   // Free the buffer allocated by WTSEnumerateSessions
    return names;
}

// Enumerate local user accounts and return those not in the logged-in set
static std::vector<std::wstring> GetUsersNotLoggedIn() {
    std::vector<std::wstring> result;            // List of local usernames that are not currently logged in
    LPUSER_INFO_0 pBuf = nullptr;                // Buffer that receives the user array (allocated by NetUserEnum)
    LPUSER_INFO_0 pTmp = nullptr;                // Pointer to walk the user array
    DWORD dwLevel = 0;                           // Information level (0 = USER_INFO_0, name only)
    DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;   // Preferred maximum length of returned data
    DWORD dwEntriesRead = 0;                     // Variable that receives the number of entries read
    DWORD dwTotalEntries = 0;                    // Variable that receives the total number of entries available
    DWORD dwResumeHandle = 0;                    // Resume handle for enumerating multiple buffers (0 to start)
    NET_API_STATUS nStatus;                      // Return value of NetUserEnum

    std::set<std::wstring> loggedIn = GetLoggedInUserNames();

    nStatus = NetUserEnum(
        nullptr,               // servername: NULL for local machine
        dwLevel,                    // level: 0 for USER_INFO_0
        FILTER_NORMAL_ACCOUNT,     // filter: Normal user accounts only (exclude built-in/guest)
        (LPBYTE*)&pBuf,            // bufptr: Pointer that receives the buffer (allocated by API)
        dwPrefMaxLen,          // prefmaxlen: Preferred max length
        &dwEntriesRead,       // entriesread: Receives the number of entries read
        &dwTotalEntries,     // totalentries: Receives the total number of entries
        &dwResumeHandle);   // resume_handle: Resume handle for continuation

    // If enumeration succeeded (or returned a partial buffer), walk the user list and keep only those not logged in
    if (nStatus == NERR_Success || nStatus == ERROR_MORE_DATA) {
        pTmp = pBuf;   // Point to the start of the user array
        for (DWORD i = 0; i < dwEntriesRead; ++i) {
            if (pTmp->usri0_name) {
                std::wstring name(pTmp->usri0_name);   // Copy the account name
                std::wstring nameLower = name;
                std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::towlower);   // Lowercase for comparison
                if (loggedIn.find(nameLower) == loggedIn.end())   // Not in the set of currently logged-in users
                    result.push_back(name);   // Add to the list of users available for impersonation
            }
            pTmp++;   // Advance to the next USER_INFO_0 entry
        }
    }

    if (pBuf)
        NetApiBufferFree(pBuf);   // Free the buffer allocated by NetUserEnum
    return result;
}

// Read a password from the console with echo disabled so the input is not visible
static std::wstring ReadPassword(const wchar_t* prompt) {
    std::wcout << prompt << std::flush;
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);   // Handle to the standard input device (console)
    DWORD mode = 0;   // Variable that receives the current console input mode
    GetConsoleMode(hStdin, &mode);   // Get current mode so we can restore it later
    SetConsoleMode(hStdin, mode & ~ENABLE_ECHO_INPUT);   // Disable echo so typed characters are not displayed

    std::wstring pass;
    wchar_t ch;
    while (std::wcin.get(ch) && ch != L'\n')
        pass += ch;
    std::wcout << L"\n";
    SetConsoleMode(hStdin, mode);   // Restore the original console mode (re-enable echo)
    return pass;
}

// Print the list of usernames (not logged in) as a numbered menu to the console
static void PrintUsers(const std::vector<std::wstring>& users) {
    if (users.empty()) {
        std::wcout << L"No users found that are currently not logged in.\n";
        return;
    }
    std::wcout << L"\nUsers not currently logged in:\n";
    std::wcout << L"----------------------------\n";
    for (size_t i = 0; i < users.size(); ++i)
        std::wcout << L"  " << (i + 1) << L". " << users[i] << L"\n";
    std::wcout << L"----------------------------\n";
}

static int Run(int argc, wchar_t* argv[]) {
    (void)argc;
    (void)argv;

    std::wcout << L"Enumerating local users not currently logged in...\n";

    std::vector<std::wstring> users = GetUsersNotLoggedIn();   // Local accounts that are not currently logged in
    PrintUsers(users);
    if (users.empty())
        return 0;

    std::wcout << L"\nEnter the number of the user to impersonate (0 to exit): ";
    int choice = 0;   // User's menu selection (1-based index, or 0 to exit)
    std::wcin >> choice;
    if (std::wcin.fail() || choice < 1 || choice > (int)users.size()) {
        if (choice != 0)
            std::wcerr << L"Invalid choice.\n";
        return 0;
    }

    std::wstring selectedUser = users[choice - 1];     // Username chosen by the user (1-based index)
    std::wcin.ignore(10000, L'\n');   // Consume the newline left in the buffer after reading the numeric choice
    std::wstring password = ReadPassword(L"Enter password for the selected user: ");

    HANDLE hToken = nullptr;   // Handle that will receive the logon token
    BOOL ok = LogonUserW(
        selectedUser.c_str(),          // lpszUsername: Name of the user account to log on
        L".",                            // lpszDomain: "." for local machine
        password.c_str(),              // lpszPassword: Password for the account
        LOGON32_LOGON_NETWORK,          // dwLogonType: Network logon (validates credentials without interactive logon)
        LOGON32_PROVIDER_DEFAULT,   // dwLogonProvider: Default provider
        &hToken);                           // phToken: Pointer that receives the handle to the token

    if (!ok) {
        PrintError("LogonUser failed");
        return 1;
    }

    ok = SetThreadToken(
        nullptr,    // ThreadHandle: NULL to set the token for the calling thread
        hToken);     // Token: Handle to the token to assign to the thread
    if (!ok) {
        PrintError("SetThreadToken failed");
        CloseHandle(hToken);
        return 1;
    }

    std::wcout << L"Success. Thread token set for user: " << selectedUser << L"\n";
    std::wcout << L"The current thread is now impersonating this user.\n";
    std::wcout << L"Press Enter to exit (token will be closed).\n";
    std::wcin.ignore(10000, L'\n');
    std::wcin.get();

    SetThreadToken(nullptr, nullptr);   // Remove the impersonation token from the current thread
    CloseHandle(hToken);   // Close the token handle returned by LogonUser
    return 0;
}

// Console entry point (avoids MinGW looking for WinMain when using wmain); gets wide argv and calls Run
int main() {
    int argc = 0;   // Variable that receives the number of command-line arguments
    LPWSTR cmdLine = GetCommandLineW();   // Retrieve the command line of the current process as a wide string
    wchar_t** argv = CommandLineToArgvW(cmdLine, &argc);   // Parse the command line into an argv-style array (allocated by API)
    int ret = Run(argc, argv);
    if (argv)
        LocalFree(argv);   // Free the buffer allocated by CommandLineToArgvW
    return ret;
}
