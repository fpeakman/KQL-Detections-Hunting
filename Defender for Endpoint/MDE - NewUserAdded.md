# User added via Command Line

## Description
This query detects users added via the command line using net.

```KQL
DeviceProcessEvents
| where FileName in ("net.exe", "net1.exe")
| where ProcessCommandLine has_all ("add","user")