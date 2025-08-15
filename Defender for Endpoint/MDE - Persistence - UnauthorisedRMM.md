# Unauthorised Remote Management and Monitoring Tools

## Description
This query detects unauthorised RMM tools, using LOLRMM list published by magicsword. Ripped from https://lolrmm.io/

```KQL
let ApprovedRMM = dynamic(["exampledomain.com"]); // Your approved RMM domain(s)
let RMMList = externaldata(URI: string, RMMTool: string)
    [h'https://raw.githubusercontent.com/magicsword-io/LOLRMM/main/website/public/api/rmm_domains.csv'];
let RMMUrl = RMMList | project URI;
DeviceNetworkEvents
| where ActionType == @"ConnectionSuccess"
| where RemoteUrl has_any(RMMUrl)
| where not (RemoteUrl has_any(ApprovedRMM))