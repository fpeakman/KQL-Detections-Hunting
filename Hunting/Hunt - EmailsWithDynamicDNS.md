# Hunt for spikes in emails containing links to Dynamic DNS providers

|Idea / Hypothesis|Tactic|Notes|
|---|---|---|
|Dynamic DNS providers can be abused to allow anyone to register subdomains|[T1566 Phishing](https://attack.mitre.org/techniques/T1566/)|[Threat Intelligence Report from Silent Push](https://www.silentpush.com/blog/dynamic-dns-providers/)|

## Why

- Dynamic DNS providers are frequently exploited through temporary hosting
- Spikes in emails containing Dynamic DNS provider links can indicate a wider attack
- Continually low / null volumes of these links, provide evidence that blocking these providers is low risk

### KQL

```KQL
let DynamicDNS = dynamic(["changeip.com","clouddns.net","dnsexit.com","duckdns.org","duiadns.net","dyn.com","dynu.com","now-dns.com","ydns.io","noip.com"]) // From the Silent Push liek of "Major DDNS providers"
EmailUrlInfo
| where Timestamp > ago(7d) // Due to subqeury we probably want to limit the number of events initially
| mv-apply domain = DynamicDNS to typeof(string) on (
    where UrlDomain endswith domain
    | limit 1
  ) // Uses subquery to step through each DynamicDNS entry, to allow use of endswith operator
| summarize DDNS = count() by bin(Timestamp,1h)