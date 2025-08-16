# Device Code Flow has been used to authenticate a session

## Description
This query detects a successful attempt to authenticate a session using the device code flow. The attacker attempts to use DeviceCode as an authentication method access a resource and receives a response of "To sign in, use a web browser to open the page https://microsoft.com/devicelogin and enter the code XXXXXXXX to authenticate." They then contact the target to convince them to complete this action. Then the attacker gain refresh and access tokens for the resouce as the target. https://www.inversecos.com/2022/12/how-to-detect-malicious-oauth-device.html

### Mitre ATT&CK

[T1566 Phishing](https://attack.mitre.org/techniques/T1566/)

### KQL

```KQL
AADSignInEventsBeta
| where ErrorCode == 0
| where EndpointCall == "Cmsi:Cmsi"
| where isempty(AadDeviceId)