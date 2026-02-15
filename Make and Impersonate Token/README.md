# Make and Impersonate Token

A simple example that enumerates local Windows user accounts that are not currently logged in, lets you choose one, creates a logon session for that user with `LogonUser`, asks for the user account's password, and assigns the token to the current thread with `SetThreadToken` so the program runs in that user’s security context. Administrator privileges may be required for `LogonUser` depending on the target account.

## How it works (step-by-step)

1. Enumerate local user accounts with `NetUserEnum` (normal accounts only).
2. Enumerate current logon sessions with `WTSEnumerateSessions` and `WTSQuerySessionInformation` to get the list of usernames that are currently logged in (active or disconnected sessions).
3. Build the list of users that exist locally but are not in the logged-in set and print them as a numbered menu in the console.
4. Read the user’s choice (number) from the command line; option 0 exits.
5. Prompt for the selected account’s password (input is hidden).
6. Call `LogonUser` (network logon, local machine) to create a logon session using the account's password and obtain a token for the chosen user.
7. Call `SetThreadToken` to assign that token to the current thread, so subsequent code runs in the chosen user’s security context.
8. Report success, wait for Enter, then clear the thread token and close the token handle before exit.

## Usage

Run the executable with no arguments. It will list local users that are not currently logged in and ask you to pick one by number, then prompt for that user’s password.

```
C:\> Make-and-Impersonate-Token.exe
```

The program will:

- Enumerate local users and show only those not currently logged in,
- Print a numbered list and ask you to enter the number of the user to impersonate (0 to exit),
- Prompt for the selected user’s password (typed input is hidden),
- Create a logon session with `LogonUser` using the target account's password and set the current thread’s token with `SetThreadToken`,
- Print a success message; the current thread is then impersonating the chosen user until you press Enter and the program exits.

To log on as accounts that require elevation or special rights, run the command prompt as Administrator before starting the program.
