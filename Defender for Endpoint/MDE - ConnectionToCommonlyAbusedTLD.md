# Connection to Commonly Abused TLD

## Description
This query detects connections to TLDs and ccTLDs that are commonly abused. Built up from the Spamhaus 2024 annual report https://www.spamhaus.org/resource-hub/domain-reputation/domain-reputation-update-oct-2024-mar-2025/

```KQL
let AbusedTLDs = datatable(extension: string) [
    '.top', '.cc', '.vip', '.xyz', '.cn', '.shop', '.co', '.ru', '.loan', '.xin', '.gdn', '.info', '.bid', '.pro', '.sbs', '.one', '.icu', '.me', '.tv'
];
DeviceNetworkEvents
| extend ParsedUrl = parse_url(RemoteUrl)
| extend Domain = tostring(ParsedUrl["Host"])
| extend IndexArray = split(Domain, '.')
| extend TLD = iff(array_length(IndexArray) >= 2 and strlen(IndexArray[-2]) <= 3, 
                   strcat('.', IndexArray[-2], '.', IndexArray[-1]), 
                   strcat('.', IndexArray[-1]))
| where isnotempty(Domain)
| where TLD in~ AbusedTLDs