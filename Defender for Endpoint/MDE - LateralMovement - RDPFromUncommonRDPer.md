# Inbound RDP Connection Attempt from a Device which does not normally RDP anywhere

## Description
This query detects inbound RDP connection attempts from a device which does not normally RDP anywhere

### Mitre ATT&CK

[T1021 Remote Services](https://attack.mitre.org/techniques/T1021/)

### KQL

```KQL
let TimeRange = 1d
let HasRDPdPreviously = 
DeviceNetworkEvents
| where Timestamp >= ago(TimeRange)
| where LocalPort == 3389 and Protocol == "Tcp"
| distinct ProcessRemoteSessionDeviceName
DeviceNetworkEvents
//| where Timestamp < ago(TimeRange) // Uncomment this if not using as a detection
| where LocalPort == 3389 and Protocol == "Tcp"
| where ProcessRemoteSessionDeviceName !in (HasRDPdPreviously)