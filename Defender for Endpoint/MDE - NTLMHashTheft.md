# Outgoing SMB traffic to internet

## Description
This query detects potential SMB traffic to a public IP. This could indicate NTLM hash theft

```KQL
DeviceNetworkEvents
| where ActionType == @"ConnectionSuccess"
| where (RemotePort==445 or RemotePort == 135)
| where RemoteIPType == @"Public" 
| where |(RemoteUrl has_any ("ExcludeDomainsHere")