# Successful sign in from a country not seen in the last 30 days

## Description
This query detects a successful sign in from a country not seen in the last 30 days.

### Mitre ATT&CK

[T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078/)

### KQL

```KQL
let KnownCountries = AADSignInEventsBeta
| where ErrorCode == 0
| where isnotempty(Country)
| distinct Country;
AADSignInEventsBeta
| where ErrorCode == 0
| where isnotempty(Country)
| where Country !in (KnownCountries)