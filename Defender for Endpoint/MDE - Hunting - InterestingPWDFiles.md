# Interesting possible password files

## Description
This query identifies file activities to file extensions which could potentially contain credentials.

### Mitre ATT&CK

N/A

### KQL

```KQL
let InterestingPWDExtentions = datatable (extension: string) [
'.kdbx','.unattend','.config','.config','.ini','.ps1','.bat','.cmd','.vba','.sql' ]
DeviceFileEvents
| extend indexArray = split(FileName, '.')
| extend extension = strcat(".",indexArray[array_length(indexArray)-1])
| join InterestingPWDExtentions on $left.extension == $right.extension