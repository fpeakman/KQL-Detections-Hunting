# Modification of privileged on-premise groups

## Description
This query detects the modification of highly privileged on-premise groups

### Mitre ATT&CK

[T1098.007 Account Manipulation](https://attack.mitre.org/techniques/T1098/)

```KQL
let PrivilegedOnPremGroups = datatable(GroupName: string) [
    "Account Operators", "Administrators", "Backup Operators", "Domain Admins", "Domain Controllers",
    "Enterprise Admins", "Enterprise Read-only Domain Controllers", "Group Policy Creator Owners",
    "Incoming Forest Trust Builders", "Microsoft Exchange Servers", "Network Configuration Operators",
    "Print Operators", "Read-only Domain Controllers", "Replicator", "Schema Admins", "Server Operators",
	"AnyOtherGroupsThatAreAppropriateForYourEnvironment"
];
IdentityDirectoryEvents
| where ActionType == "Group Membership changed"
| extend AdditionalFieldsParsed = parse_json(AdditionalFields)
| extend FromGroup = tostring(AdditionalFieldsParsed["FROM.GROUP"])
| extend ToGroup = tostring(AdditionalFieldsParsed["TO.GROUP"])
| extend TargetObject = iff(isnull(AdditionalFieldsParsed["TARGET_OBJECT.USER"]), AdditionalFieldsParsed["TARGET_OBJECT.GROUP"], AdditionalFieldsParsed["TARGET_OBJECT.USER"])
| extend TargetObject = iff(isnull(TargetObject), AdditionalFieldsParsed["TARGET_OBJECT.DEVICE"], TargetObject)
| extend Action = iff(isnotempty(ToGroup), "Add", "Remove")
| extend GroupModified = iff(isnotempty(ToGroup), ToGroup, FromGroup)
| where GroupModified in (PrivilegedOnPremGroups)