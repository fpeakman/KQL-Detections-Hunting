# ISO File Mounted

## Description
This query detects an iso shortcut creation event, which occurs when Windows mounts an ISO file.

```KQL
DeviceFileEvents
| where FileName endswith ".iso.lnk" or FileName endswith ".img.lnk"