# Password Files

|Idea / Hypothesis|Tactic|Notes|
|---|---|---|
|Users may store passwords/keys/secrets in an insecure way|[T1555 Credentials from Password Stores](https://attack.mitre.org/techniques/T1555/)| Will only detect file creation, modification or deletion events. Does not search for actual files|

## Why

- Users who have multiple passwords for multiple systems will often come up with their own method of storing passwords, in the absence of a corporate password manager or other official guidance.
- Users are often unaware of how to securely store passwords

### KQL

```KQL
let InterestingKeywords = dynamic(["pass", "cred", "login", "pwd", "secret", "key"]);
let pattern = strcat("(?i)(", strcat_array(InterestingKeywords, "|"), ")");
DeviceProcessEvents
| where Timestamp > ago(30d)
| where CommandLine matches regex pattern
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, AccountName, CommandLine
| order by Timestamp desc
