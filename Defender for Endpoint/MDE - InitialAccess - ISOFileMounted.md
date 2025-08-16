# ISO File Mounted

## Description
This query detects an iso shortcut creation event, which occurs when Windows mounts an ISO file.

### Mitre ATT&CK

[T1204.003 User Execution: Malicious Image]https://attack.mitre.org/techniques/T1204/003/)

```KQL
DeviceFileEvents
| where FileName endswith ".iso.lnk" or FileName endswith ".img.lnk"