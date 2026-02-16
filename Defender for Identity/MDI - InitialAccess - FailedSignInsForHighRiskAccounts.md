# Failed sign-in attempts for high-risk users

## Description
This query detects multiple failed sign-in attempts for high-risk user accounts

### Mitre ATT&CK

[TA0006 Credential Access](https://attack.mitre.org/tactics/TA0006/)

### KQL

```KQL
let TrustedIPs = dynamic(["Your IPs","here"]);
EntraIdSignInEvents
| where ErrorCode != 0
| where IPAddress !in (TrustedIPs)
| join kind=inner IdentityInfo on $left.AccountObjectId == $right.AccountObjectId
| where BlastRadius == "High"
| summarize FailedAttempts = count() by AccountUpn, IPAddress, Country, bin(Timestamp, 1h) // Group attempts by hour to cut down on noise
| where FailedAttempts > 2  // Adjust threshold as needed
