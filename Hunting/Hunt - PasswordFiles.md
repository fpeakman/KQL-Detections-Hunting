# Password Files

|Idea / Hypothesis|Tactic|Notes|
|---|---|---|
|Users may store passwords/keys/secrets in an insecure way|[T1555 Credentials from Password Stores](https://attack.mitre.org/techniques/T1555/)| Will only detect file creation, modification or deletion events. Does not search for actual files|

## Why

- Users who have multiple passwords for multiple systems will often come up with their own method of storing passwords, in the absence of a corporate password manager or other official guidance.
- Users are often unaware of how to securely store passwords

### KQL

```KQL
let InterestingFileNames = dynamic([
    "password.txt",
    "passwords.txt",
    "creds.txt",
    "credentials.txt",
    "login.txt",
    "pass.txt",
    "pwd.txt",
    "secret.txt",
    "secrets.txt",
    "key.txt",
    "keys.txt",
    "passwords.xlsx",
    "credentials.xlsx",
    "password.doc",
    "passwords.doc",
    "credential.doc",
    "credentials.doc",
    "passwrd.txt",
    "passwd.txt",
    "userpass.txt"
]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName in~ (InterestingFileNames)
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessAccountName, ActionType
| order by Timestamp desc
