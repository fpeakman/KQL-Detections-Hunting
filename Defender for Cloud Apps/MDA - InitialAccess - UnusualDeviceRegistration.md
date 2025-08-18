# Device Registration where devicename does not match expected convention

## Description
This query detects a new or updated device where the devicename does not match the expected convention

### Mitre ATT&CK

[T1098.005 Account Manipulation: Revice Registration](https://attack.mitre.org/techniques/T1098/005/)

### KQL

```KQL
CloudAppEvents
| where ActionType in ("Register device", "Add device", "Update device")
| extend TargetResources = RawEventDataParsed.targetResources
| extend DeviceName = tostring(TargetResources[0].displayName)
| where isnotempty(DeviceName)
| where not (DeviceName // Create your naming convention logic here