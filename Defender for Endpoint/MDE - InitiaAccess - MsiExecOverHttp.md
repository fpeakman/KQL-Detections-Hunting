# MSIExec connecting to http

## Description
This query detects msiexec connecting over http/s for a remote msi file

### Mitre ATT&CK

[T1218.007 ESystem Binary Proxy Execution: Msiexec](https://attack.mitre.org/techniques/T1218/007/)

### KQL

```KQL
DeviceProcessEvents
| where ProcessCommandLine contains "msiexec" 
| where ProcessCommandLine contains "http"
| where ProcessCommandLine !contains @"c:\windows\ccmcache\" // Common fale positive