# System Binary Unusual Network Event

## Description
This query detects network events for system binaries which do not normally connect to the network

### Mitre ATT&CK

[T1218 System Binary Proxy Execution](https://attack.mitre.org/techniques/T1218/)


### KQL

```KQL
let InterestingSystemBinaries = dynamic(["msiexec.exe", "regsvr32.exe", "certreq.exe", "findstr.exe", "mmc.exe", "wmic.exe", "rundll32.exe", "certutil.exe", "curl.exe", "bitsadmin.exe", "cmstp.exe", "esentutl.exe"]);
let ExcludedSubnets = dynamic(["10.0.0.0/8", "192.168.0.0/16"]); // Set your internal subnets here. Required as "RemoteIPType" is not always reliable.
let ExcludedDomains = dynamic(["update.microsoft.com", "login.windows.net"]); // Example legitimate domains. You may need to include your internal domains, depending on your environment.
DeviceNetworkEvents
| where InitiatingProcessFileName in~ (InterestingSystemBinaries)
| where RemoteIPType == "Public" or RemoteUrl matches regex @"^(http|https)://" 
| where not (ipv4_is_in_any_range(RemoteIP, ExcludedSubnets))
| where not (RemoteUrl has_any (ExcludedDomains))