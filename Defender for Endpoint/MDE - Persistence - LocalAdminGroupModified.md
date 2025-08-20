# Local Administrator Group Modified

## Description
This query detects any modifications to the local Administrators group 

### Mitre ATT&CK

[T1098 Account Manipulation](https://attack.mitre.org/techniques/T1098/)

### KQL

```KQL
DeviceEvents
| where ActionType == "UserAccountAddedToLocalGroup"
| extend GroupName = tostring(parse_json(AdditionalFields).GroupName)
| where GroupName == "Administrators"
//| where not(AccountName in ("expected_user1", "expected_user2")) //Modify to include users which are added regularly by e.g. GPO
