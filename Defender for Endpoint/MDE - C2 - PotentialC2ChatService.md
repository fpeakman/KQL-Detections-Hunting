# Connection to Chat Services which have been abuse for C2 

## Description
This query detects connections to chat services which have been abused for C2.

### Mitre ATT&CK

[T1071.001 Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)

```KQL
let ChatC2Domains = dynamic(["telegram.org", "discord.com", "discordapp.com", "slack.com", "whatsapp.com"]); //You must tune this for your environment
DeviceNetworkEvents
| extend ParsedUrl = parse_url(RemoteUrl)
| extend Host = tolower(tostring(ParsedUrl["Host"]))
| where isnotempty(Host) and (
    Host endswith "telegram.org" or
    Host endswith "discord.com" or
    Host endswith "discordapp.com" or
    Host endswith "slack.com" or
    Host endswith "whatsapp.com"
)