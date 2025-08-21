# Certutil used to decode

## Description
This query detects certutil being used to decode base64 encoded text

### Mitre ATT&CK

[T1140 - Deobfuscate/Decode Files or Information](T1140)

### KQL

```KQL
DeviceProcessEvents
| where FileName =~ "certutil.exe" or ProcessVersionInfoInternalFileName =~ "certutil.exe" or ProcessVersionInfoOriginalFileName =~ "certutil.exe" or ProcessVersionInfoFileDescription =~ "certutil.exe"
| where ProcessCommandLine has "-decode"