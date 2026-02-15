# Token Impersonation/Theft

A simple example that spawns `cmd.exe` with the security token of another process (by PID) by impersonating it. The program opens the target process, duplicates its token, and creates a new process with that token so the command prompt runs in the target’s security context. Note that this code does not bypass the UAC mechanism in Windows.

## How it works (step-by-step)

1. Parse the target process PID from the command line.
2. If the program was re-launched elevated (e.g. after UAC), open a result file so the non-elevated parent can read and print output in the original CLI.
3. If the process has no console (e.g. when started via UAC), allocate a console so output is visible.
4. Enable `SeDebugPrivilege` so we can open other processes and access their tokens.
5. Open the target process (`OpenProcess`). If access is denied and the current process is not elevated, re-launch the program with “Run as administrator” (UAC); the elevated instance writes results to a temp file and the parent waits and prints that file in the original CLI.
6. Open the target process’s access token (`OpenProcessToken`) and duplicate it as a primary token (`DuplicateTokenEx`) so it can be used to create a new process.
7. Print the impersonated token handle and identifiers (TokenId, AuthenticationId) to the CLI.
8. Spawn `cmd.exe` with the duplicated token (`CreateProcessWithTokenW`, or `CreateProcessAsUserW` as fallback) so it runs in the target process’s security context.
9. Report the spawned process PID, clean up handles, and optionally pause if a console was allocated.

## Usage

Run the executable with the PID of the target process. You can run it without Administrator rights; if the target is elevated and access is denied, the program will request elevation (UAC) and print the result in the same CLI after you approve.

```
C:\> Token-Impersonation.exe <PID>
```

Example:

```
C:\> Token-Impersonation.exe 7248
```

The program will:

- (If needed) request elevation via UAC and re-run with the same PID,
- open the target process and duplicate its token,
- print whether the PID was running, the impersonated token handle and TokenId/AuthId, and the spawned cmd.exe PID,
- spawn `cmd.exe` with that token (a new console window),
- and exit. The new `cmd.exe` runs in the security context of the target process.

To impersonate elevated or protected processes, approve the UAC prompt when asked, or run the command prompt as Administrator from the start.

![Token Impersonation + Create Process with Token](https://github.com/ary4nsh/Access-Token-Manipulation/blob/main/Token%20Impersonation%20%2B%20Create%20Process%20with%20Token/%7B76493691-73A9-49E4-81D1-30218FF5F654%7D.png)
