# Title

|Idea / Hypothesis|Tactic|Notes|
|---|---|---|
|CISA Known Exploited Vulnerabilities should be prioritised for remediation|Tactic|CISA KEV is normally updated 3+ times a week. KQL copied from [KQLQuery.com](https://kqlquery.com/posts/externaldata/)|

## Why

- Attackers like to use known and reliable vulnerabilities to keep costs low (i.e. no need for 0days) and reduce dwell time (no trickey exploits or exploit chains)
- CISA collects information on vulnerabilities exploited during security incidents and uses this to public their Known Exploited Vulnerability list
- Vulnerabilities from this list should be prioritised for remediation.

### KQL

```KQL
let KnowExploitesVulnsCISA = externaldata(cveID: string, vendorProject: string, product: string, vulnerabilityName: string, dateAdded: datetime, shortDescription: string, requiredAction: string, dueDate: datetime, 
notes: string)[@"https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"] with (format="csv", ignoreFirstRecord=True);
DeviceTvmSoftwareVulnerabilities
| join kind=inner KnowExploitesVulnsCISA on $left.CveId == $right.cveID
| summarize TotalDevices = dcount(DeviceId) by CveId
| sort by TotalDevices
| render columnchart with(title="Active CVEIds CISA KEV")