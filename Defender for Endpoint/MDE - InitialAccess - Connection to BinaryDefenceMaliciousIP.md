# Connection to Commonly Abused TLD

## Description
This query detects connections to IPs that have been identified as malicious by Binary Defence. This includes IPs linked to malware, phishing and various other cyber threats.

### Mitre ATT&CK

[TA0001 Initial Access](https://attack.mitre.org/tactics/TA0001/)

### KQL

```KQL
let banlist = externaldata(IP: string) [@"https://binarydefense.com/banlist.txt"] with (format="txt") | where IP !startswith "#";
DeviceNetworkEvents
| where RemoteIP in (banlist | project IP)