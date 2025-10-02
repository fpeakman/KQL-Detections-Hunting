# High Risk account sign in event with non-zero risk level

## Description
This query detects sign in events with a non-zero RiskLevelAggregated, for accounts which have a "High" "BlastRadius" rating. BlastRadius is based on the position of the user in the org tree and the user's Entra roles and permissions.

### Mitre ATT&CK

[T1078.004 Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)

### KQL

```KQL
AADSignInEventsBeta
| where RiskLevelAggregated != 0 // This may need to be tuned depending on your org. Other possible values are 10(Low), 50(Medium) and 100(High).
| join kind=inner IdentityInfo on $left.AccountObjectId == $right.AccountObjectId
| where BlastRadius == "High" // Other possible values are Low and Medium.
