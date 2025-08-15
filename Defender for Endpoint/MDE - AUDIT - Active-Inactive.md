# Devices which are active in AD but inactive in MDE

## Description
This query detects devices which are active in AD but inactive in MDE. Ripped from https://github.com/alexverboon/Hunting-Queries-Detection-Rules/blob/main/Defender%20For%20Endpoint/MDE-Inactive-ADActive.md

```KQL
DeviceInfo
| where Timestamp > ago(30d)
| summarize arg_max(Timestamp,*) by DeviceName
| where OnboardingStatus == 'Onboarded' or OnboardingStatus == 'Can be onboarded'
| extend LastActiveDate = Timestamp
| where LastActiveDate < ago(7d)
| project Timestamp, LastActiveDate, DeviceName, OSPlatform, IsAzureADJoined
| join kind=leftouter  (IdentityLogonEvents
| where Timestamp > ago(7d)
| where isnotempty( AccountName)
| summarize arg_max(Timestamp,*) by DeviceName
| extend LastLogonDate = Timestamp)
on $left. DeviceName == $right. DeviceName
| where isnotempty( DeviceName1)