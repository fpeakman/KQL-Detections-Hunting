# Connection to Known Censys C2

## Description
This query detects connections to/from IP's known to be compromised by Proofpoint. https://rules.emergingthreats.net/

```KQL
let CompromisedList = externaldata(DestIP: string)[@"https://rules.emergingthreats.net/blockrules/compromised-ips.txt"] with (format="txt", ignoreFirstRecord=False);
DeviceNetworkEvents
| where RemoteIP in (MaliciousIP)