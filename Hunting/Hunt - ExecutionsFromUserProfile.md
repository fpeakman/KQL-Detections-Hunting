# Hunt for Executions from User Profile

|Idea / Hypothesis|Tactic|Notes|
|---|---|---|
|Executions from %userprofile% can indicate malware or incorrectly installed applications|[T1204.002 User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)||

## Why

- Users have write permissions to their user profile tree
- Malware will often be run from %AppData%  or %UserProfile%\Downloads
- Legitimate software such as browsers, will often install itself within the same locations when the user does not have local admin permission to install under %programfiles%
- Ideally, users should be prevented from executing files from their user profile tree using tools such as AppLocker

### KQL

```KQL
DeviceProcessEvents
| where FolderPath has_any ("AppData","Downloads") // has_any is case insensitive
// This query is very much a basic starting point