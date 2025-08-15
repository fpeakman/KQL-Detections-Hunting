# Connection to Known Censys C2

## Description
This query detects outbound connections to IP's known to be bad by Censys https://censys.com/ within the last 30 days. IP's collected from https://github.com/drb-ra/C2IntelFeeds

```KQL
let C2IntelFeeds = externaldata(IP: string, ioc:string)[@"https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s-30day.csv"] with (format="csv", ignoreFirstRecord=True);
let IPList = C2IntelFeeds
| project IP;
DeviceNetworkEvents
| where RemoteIP in (IPList)
| join C2IntelFeeds on $left.RemoteIP == $right.IP