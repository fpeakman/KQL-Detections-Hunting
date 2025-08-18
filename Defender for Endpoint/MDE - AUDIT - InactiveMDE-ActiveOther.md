# Devices which are active in AD but inactive in MDE

## Description
This query detects devices which are active in AD/EID/Other services but inactive in MDE. Modified from https://github.com/alexverboon/Hunting-Queries-Detection-Rules/blob/main/Defender%20For%20Endpoint/MDE-Inactive-ADActive.md

### KQL

```KQL
let DetectionTimeThreshold = ago(2h) //You will need to tailor this for your organisation
DeviceInfo
| summarize arg_max(Timestamp,*) by DeviceName
| where OnboardingStatus == 'Onboarded' or OnboardingStatus == 'Can be onboarded'
| extend LastActiveDate = Timestamp
| where LastActiveDate < DetectionTimeThreshold
| project Timestamp, LastActiveDate, DeviceName, OSPlatform, IsAzureADJoined
| join kind=leftouter  (IdentityLogonEvents
| where Timestamp > DetectionTimeThreshold
| where isnotempty( AccountName)
| summarize arg_max(Timestamp,*) by DeviceName
| extend LastLogonDate = Timestamp)
on $left. DeviceName == $right. DeviceName
| where isnotempty( DeviceName1)