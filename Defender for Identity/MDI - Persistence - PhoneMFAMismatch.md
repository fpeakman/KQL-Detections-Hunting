# User updated with new phone number for MFA which does not match number in Entra ID

## Description
This query detects mismatches between the phone provider in the EntraID user profile and the phone number used to authenticate via MFA

### MITRE ATT&CK

[T1556.006 Modify Authentication Process: Multi-Factor Authentication](https://attack.mitre.org/techniques/T1556/006/)

### KQL

```KQL
CloudAppEvents
| where ActionType == "Update user." and RawEventData contains "StrongAuthentication"
| extend target = RawEventData.ObjectId
| mvexpand ModifiedProperties = parse_json(RawEventData.ModifiedProperties)
| where ModifiedProperties matches regex @"\+\d{1,3}\s*\d{9,}"
| mvexpand ModifiedProperties = parse_json(ModifiedProperties)
| where ModifiedProperties contains "NewValue" and ModifiedProperties matches regex @"\+\d{1,3}\s*\d{9,}"
| extend PhoneNumber = extract(@"\+\d{1,3}\s*\d{9,}", 0, tostring(ModifiedProperties))

// Joining IdentityInfo table to get phone numbers provided on the user profile
| join kind=inner (IdentityInfo) on $left.AccountDisplayName == $right.AccountDisplayName

// Filtering to show only different phone numbers
| where Phone != PhoneNumber