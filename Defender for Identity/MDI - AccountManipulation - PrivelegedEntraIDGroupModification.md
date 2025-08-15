# Modification of privileged Entra ID groups

## Description
This query detects the modification of highly privileged Entra ID groups


```KQL
let PrivilegedEntraGroups = dynamic(["Global Administrators", "Privileged Role Administrators", "Company Administrators", "Security Administrators",
	"AnyOtherGroupsThatAreAppropriateForYourEnvironment"
]);
CloudAppEvents
| where ActionType in~ ("Add member to group", "Remove member to group", "Add member to role", "Remove member from role")
| extend GroupOrRole = tostring(RawEventData.Target.DisplayName)
| where GroupOrRole in~ (PrivilegedEntraGroups)
| extend Action = iff(ActionType contains "Add", "Add", "Remove")