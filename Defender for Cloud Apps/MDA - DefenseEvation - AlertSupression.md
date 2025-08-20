# New alert suppression rule created

## Description
This query detects new alert suppression rules

### Mitre ATT&CK

[TA0107 Inhibit Response Function](https://attack.mitre.org/tactics/TA0107/)

### KQL

```KQL
CloudAppEvents
| where ActionType == "Write AlertsSuppressionRules"