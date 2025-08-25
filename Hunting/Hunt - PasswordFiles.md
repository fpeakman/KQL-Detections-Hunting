# Password Files

## Description
This query looks for file events where the filename suggests insecure storage of credentials/keys/secrets

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
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, AccountName, ActionType
| order by Timestamp desc