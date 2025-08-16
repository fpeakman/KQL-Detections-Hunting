# Potential mailbomb attack

## Description
This query detects a potential mail bomb attack where a user receives a suspiciously high volume of emails from unique senders. This is a chatracteristic of a mail bomb attack where a threat actor can subsequently pose as tech support and ask for access in order to "help" the victim.

### MIRE ATT&CK
[T1167 Email Bombing](https://attack.mitre.org/techniques/T1667/)

### KQL

```KQL
EmailEvents
| summarize UniqueSenders = dcount(SenderFromAddress) by bin(Timestamp, 1h), RecipientEmailAddress
| where UniqueSenders >= 20