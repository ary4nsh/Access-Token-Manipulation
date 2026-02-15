# Parent PID Spoofing

A simple example that spawns `cmd.exe` with a spoofed parent process ID (PPID). The program takes a PID from the user, opens that process, and creates a new process (`cmd.exe`) whose parent is set to the chosen PID via `UpdateProcThreadAttribute` (`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`) and `CreateProcess` with `STARTUPINFOEX`. The new command prompt thus appears in the process tree as a child of the chosen process. Note that this code does not bypass the UAC mechanism in Windows.

## How it works (step-by-step)

1. Parse the chosen parent process PID from the command line.
2. Enable `SeDebugPrivilege` so we can open the target process.
3. Open the target process with `OpenProcess` using the `PROCESS_CREATE_PROCESS` access right (required for setting it as the parent).
4. Query the size needed for a process thread attribute list by calling `InitializeProcThreadAttributeList` with a NULL list.
5. Allocate the attribute list buffer with `HeapAlloc` and initialize it with `InitializeProcThreadAttributeList`.
6. Call `UpdateProcThreadAttribute` with `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` to set the spoofed parent process handle in the attribute list.
7. Fill a `STARTUPINFOEXW` structure with the attribute list and call `CreateProcessW` with the `EXTENDED_STARTUPINFO_PRESENT` and `CREATE_NEW_CONSOLE` flags so the new process is created with the chosen PID as its parent.
8. Report the spawned process PID and spoofed parent PID to the CLI, then clean up the attribute list and all handles.

## Usage

Run the executable with the PID of the process that should appear as the parent of the new `cmd.exe`. You typically need Administrator rights so that `SeDebugPrivilege` can be enabled and the target process can be opened.

```
C:\> Parent-PID-Spoofing.exe <PID>
```

Example:

```
C:\> Parent-PID-Spoofing.exe 5360
```

The program will:

- enable `SeDebugPrivilege` and open the target process,
- build a process attribute list with the chosen process as the parent,
- spawn `cmd.exe` in a new console with that parent (PPID spoofing),
- print the new cmd.exe PID and the spoofed parent PID, then exit. The new `cmd.exe` will show the chosen process as its parent in tools like Process Explorer or `tasklist`.

To spoof the parent of elevated or protected processes, run the command prompt as Administrator from the start.

/{0D34557C-599C-46C3-90DC-C803B0776110}.png

