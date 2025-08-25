# Connection to Commonly Abused TLD

## Description
This query detects connections to TLDs that the [Cyber Crime Information Center ](http://cybercrimeinfocenter.org/) has identified as having elevated risk of hosting phishing content.

### Mitre ATT&CK

[TA0001 Initial Access](https://attack.mitre.org/tactics/TA0001/)

### KQL

```KQL
let badTLDs = externaldata(TLD:string)
[@"https://raw.githubusercontent.com/mthcht/awesome-lists/main/Lists/TLDs/latest_bad_tlds_phishing_cybercrimeinfocenter_list.csv"]
with (format="csv");
DeviceNetworkEvents
| where isnotempty(RemoteUrl)
| extend ParsedUrl = parse_url(RemoteUrl)
| extend Host = tolower(tostring(ParsedUrl["Host"]))
| where isnotempty(Host)
| extend UrlTLD = split(Host, '.')[-1]
| where UrlTLD in~ (badTLDs) // Case-insensitive match