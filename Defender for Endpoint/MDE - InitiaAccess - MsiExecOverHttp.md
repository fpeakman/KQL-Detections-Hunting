# MSIExec connecting to http

## Description
This query detects msiexec connecting over http/s for a remote msi file

```KQL
DeviceProcessEvents
| where ProcessCommandLine contains "msiexec" 
| where ProcessCommandLine contains "http"
| where ProcessCommandLine !contains @"c:\windows\ccmcache\" // Common fale positive