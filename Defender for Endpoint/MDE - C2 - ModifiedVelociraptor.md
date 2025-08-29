# Misuse of Velociraptor

## Description
This query detects evidence of Velociraptor being used

### Mitre ATT&CK

[T1219 Remote Access Tools](https://attack.mitre.org/techniques/T1219/)

### KQL

```KQL
DeviceRegistryEvents
| where ActionType in ("RegistryKeyCreated", "RegistryValueSet")
| where RegistryKey == @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Application\Velociraptor"