# Title

|Idea / Hypothesis|Tactic|Notes|
|---|---|---|
|Idea / Hypothesis|Tactic|Notes|

## Why

- Port 443 is commonly used for legitimate HTTPS traffic, making it an attractive channel for attackers to hide data exfil activities within encrypted traffic.
- By using a well-known port like 443, adversaries can blend malicious traffic with normal traffic, reducing the likelihood of detection by traditional security controls.
- Spikes in traffic over port 443 can signal an exfil attempt, as attackers may try to move data through encrypted channels that are less scrutinized.

### KQL

```KQL
code