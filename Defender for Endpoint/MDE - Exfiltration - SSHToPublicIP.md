# SSH to Public IP

## Description
This query detects SSH connections made outbound to Public IPs. This method can be used to exfiltrate data or to download malicious tools to the local machine.

### Mitre ATT&CK

[T1024.002 Exfiltration Over Alternative Protocol: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol](https://attack.mitre.org/techniques/T1048/002/)

```KQL
DeviceNetworkEvents
| where ActionType == ""SshConnectionInspected""
| where RemoteIPType == "Public"
| extend json = todynamic(AdditionalFields)
| project Timestamp, DeviceId, DeviceName, RemoteIP, RemotePort, RemoteUrl, LocalIP, Server=tostring(json.server), Client = tostring(json.client), ReportId, AdditionalFields