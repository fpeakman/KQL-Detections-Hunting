# Encoded Powershell Download Command

## Description
This query detects BASE64 encoded powershell download commands.

### Mitre ATT&CK
[T1027.013 Obfuscated Files or Information: Encrypted/Encoded File](https://attack.mitre.org/techniques/T1027/013/)

```KQL
let EncodedList = dynamic(['-encodedcommand', '-enc', '-en', '-e']);
let DownloadVariables = dynamic(['WebClient', 'DownloadFile', 'DownloadData', 'DownloadString', 'WebRequest', 'Shellcode', 'http', 'https']); //Array used with has_any which is case insensitive
DeviceProcessEvents
| where ProcessCommandLine contains "powershell" or InitiatingProcessCommandLine contains "powershell"
| where ProcessCommandLine has_any (EncodedList) or InitiatingProcessCommandLine has_any (EncodedList)
| extend base64String = extract(@'\s+([A-Za-z0-9+/]{20}\S+$)', 1, ProcessCommandLine)
| extend DecodedCommandLine = base64_decode_tostring(base64String)
| extend DecodedCommandLineReplaceEmptyPlaces = replace_string(DecodedCommandLine, '\u0000', '')
| where isnotempty(base64String) and isnotempty(DecodedCommandLineReplaceEmptyPlaces)
| where DecodedCommandLineReplaceEmptyPlaces has_any (DownloadVariables)