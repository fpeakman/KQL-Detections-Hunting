# Potential Click Fix Attack

## Description
This query detects potential "Click Fix" attacks where a target is manipulated in to running a malicious command. Adapted from https://detect.fyi/hunting-clickfix-initial-access-techniques-8c1b38d5ef9b. Will not detect BASE64 encyphered PS commands.

### Mitre ATT&CK

[T1204.004 User Execution: Malicious Copy and Paste](https://attack.mitre.org/techniques/T1204/004/)

```KQL
let ps_keywords = dynamic(["start-process", "hidden", "command", "bypass", "new-object", "http", "invoke", "iex", "-exec", "verification", "classname", "cimmethod", "methodname", "win32_process", "system.diagnostics.process", "system.management.automation", "Reflection.Assembly", "FromBase64String", "import-module", "add-type", "webclient"]);
let script_keywords = dynamic (["http", "javascript:", "verification", "eval", ".js", ".vbs", ".hta", ".bat"]);
let registry_activity=(DeviceRegistryEvents
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName =~ "explorer.exe"
| where ActionType == "RegistryValueSet"
| where isnotempty( RegistryValueData)
| where RegistryKey endswith @"\CurrentVersion\Explorer\RunMRU"
| extend regkey_length = strlen(RegistryValueData)
| where regkey_length >= 50 //filter short strings that are unlikely to contain full commands
| where RegistryValueData has_any ("powershell", "pwsh", "cmd", "mshta", "curl") and (RegistryValueData has_any (ps_keywords) or RegistryValueData has_any (script_keywords)) //LOLBin spawned will always be in the RunMRU, so it does not need to be included as a keyword
| project registry_change=Timestamp,DeviceName, InitiatingProcessAccountName, RegistryKey, RegistryValueData, regkey_length
 );
DeviceNetworkEvents
| where Timestamp > ago(window)
| where InitiatingProcessParentFileName in~ ("explorer.exe", "services.exe")
| where InitiatingProcessFileName has_any ("powershell", "pwsh", "cmd", "mshta", "msiexec")
| where isnotempty(RemoteUrl) or isnotempty(RemoteIP)
| join kind=inner (registry_activity) on DeviceName
| where Timestamp between (registry_change .. -10s ) or Timestamp between (registry_change .. +10s )
| project process_execution=Timestamp, registry_change, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort, RemoteIPType, ActionType,RegistryKey, RegistryValueData, regkey_length