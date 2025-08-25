# Connection to Commonly Abused TLD

## Description
This query detects connections to or from ports that have been identified as suspicious. See [here](https://raw.githubusercontent.com/mthcht/awesome-lists/main/Lists/suspicious_ports_list.csv) for more details

### Mitre ATT&CK

[TA0008 Lateral Movement](https://attack.mitre.org/tactics/TA0008/)

### KQL

```KQL
let suspicious_ports = externaldata(dest_port: int)
[@"https://raw.githubusercontent.com/mthcht/awesome-lists/main/Lists/suspicious_ports_list.csv"]
with (format="csv", ignoreFirstRecord=true);
// Query DeviceNetworkEvents for matches on LocalPort or RemotePort
DeviceNetworkEvents
| where LocalPort in (suspicious_ports | project dest_port) or RemotePort in (suspicious_ports | project dest_port)
