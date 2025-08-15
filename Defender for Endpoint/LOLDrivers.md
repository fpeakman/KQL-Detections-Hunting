# Vulnerable LOL driver loaded

## Description
This query detects vulnerable drivers being loaded on an endpoint. Uses the FOSS repository maintained by the team at https://www.loldrivers.io/ and published by MagicSword team https://portal.magicsword.io/

```KQL
let loldrivers = (externaldata (SHA256:string) [@'https://raw.githubusercontent.com/magicsword-io/LOLDrivers/main/detections/hashes/samples.sha256'] with (format='txt'));
loldrivers
| join DeviceEvents on SHA256
| where ActionType == "DriverLoad"