# Globally rare, executable file created in Public Folder.

## Description
This query detects executable files with low GlobalPrevalence being created in Public Folder.

```KQL
let ExecutableFileExtensions = dynamic(['bat', 'cmd', 'com', 'cpl', 'ex', 'exe', 'jse', 'msc','ps1', 'reg', 'vb', 'vbe', 'ws', 'wsf', 'hta', '.dll']);
DeviceFileEvents
| where FolderPath contains @'C:\Users\Public'
| extend FileExtension = tostring(extract(@'.*\.(.*)', 1, FileName))
| where FileExtension in~ (ExecutableFileExtensions)
| invoke FileProfile('SHA256', 10000)
| where GlobalPrevalence <= 250