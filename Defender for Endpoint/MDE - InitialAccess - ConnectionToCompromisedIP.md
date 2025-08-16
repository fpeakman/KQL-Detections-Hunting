# Connection to Known Censys C2

## Description
This query detects connections to/from IP's known to be compromised by Proofpoint. https://rules.emergingthreats.net/

### Mitre ATT&CK

[TA0001 Initial Access](https://attack.mitre.org/tactics/TA0001/)

### KQL

```KQL
let CompromisedList = externaldata(DestIP: string)[@"https://rules.emergingthreats.net/blockrules/compromised-ips.txt"] with (format="txt", ignoreFirstRecord=False);
DeviceNetworkEvents
| where RemoteIP in (CompromisedList)