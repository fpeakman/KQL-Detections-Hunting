# Inbound RDP Connection Attempt from a Device using a Default Hostname

## Description
This query detects inbound RDP connection attempts from a device which uses a default hostname. This can indicate that an adversary has either infiltrated a local network or has achieved remote VPN access.

### Mitre ATT&CK

[T1021 Remote Services](https://attack.mitre.org/techniques/T1021/)

```KQL
DeviceNetworkEvents
| where InitiatingProcessRemoteSessionDeviceName startswith "desktop" or InitiatingProcessRemoteSessionDeviceName startswith "laptop"