# A device has failed to RDP to three or more devices in the last day

## Description
This query detects when a device has failed to RDP on to three or more devices in a day

### Mitre ATT&CK

[T1110 Brute Force](https://attack.mitre.org/techniques/T1110/)

### KQL

```KQL
DeviceLogonEvents
| where Timestamp > ago(1d)
| where ActionType == "LogonFailed"
| where LogonType == "RemoteInteractive"
| summarize TargetCount = dcount(DeviceName), Targets = make_set(DeviceName) by RemoteIP
| where TargetCount >= 3