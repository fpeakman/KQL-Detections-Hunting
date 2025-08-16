# DLL Hijacking

## Description
This query detects suspicious DLL loading events by matching them against a curated list of known vulnerable dlls from Hijacklibs.net. Query modified from https://www.anvilogic.com/detection-voyagers/top-10-kql-queries-every-detection-engineer-should-know

### Mitre ATT&CK
[T1574.001 Hijack Execution Flow: DLL](https://attack.mitre.org/techniques/T1574/001/)



```KQL
let dll_hijacking_source = externaldata
(
    Name:string,
    Author:string,
    Created:string,
    Vendor:string,
    CVE:string,
    ExpectedLocations:string,
    VulnerableExecutablePath:string,
    VulnerableExecutableType:string,
    VulnerableExecutableAutoElevated:string,
    VulnerableExecutablePrivilegeEscalation:string,
    VulnerableExecutableCondition:string,
    VulnerableExecutableSHA256:string,
    VulnerableExecutableEnvironmentVariable:string,
    Resources:string,
    Acknowledgements:string,
    URL:string
)
[@"https://hijacklibs.net/api/hijacklibs.csv"] 
with (format="csv", ignoreFirstRecord=True);

DeviceImageLoadEvents
| join kind=inner (dll_hijacking_source) on $left.SHA256 == $right.VulnerableExecutableSHA256
| where isnotempty(VulnerableExecutableSHA256)