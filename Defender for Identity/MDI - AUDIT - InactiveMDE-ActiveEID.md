# Devices which are active in Entra ID but inactive in MDE

## Description
This query detects devices which are active in Entra ID but inactive in MDE.

### KQL

```KQL
let DetectionTimeThreshold = ago(2h) //You will need to tailor this for your organisation
DeviceInfo
| summarize arg_max(Timestamp,*) by DeviceName
| where OnboardingStatus == 'Onboarded' or OnboardingStatus == 'Can be onboarded'
| extend LastActiveDate = Timestamp
| where LastActiveDate < DetectionTimeThreshold
| project Timestamp, LastActiveDate, DeviceName, OSPlatform, IsAzureADJoined
| join kind=leftouter  (AADSignInEventsBeta
| where Timestamp > DetectionTimeThreshold
| where isnotempty( AccountUpn)
| summarize arg_max(Timestamp,*) by DeviceName
| extend LastSignInDate = Timestamp)
on $left. DeviceName == $right. DeviceName
| where isnotempty( DeviceName1)