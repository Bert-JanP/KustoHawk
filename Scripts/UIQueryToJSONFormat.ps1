$Query = "let Device = '{DeviceId}';
let TimeFrame = {TimeFrame};
let ImageLoads = DeviceImageLoadEvents
| where DeviceId =~ Device
| where Timestamp > ago(TimeFrame)
| where ActionType == 'ImageLoaded'
| where FileName =~ 'samlib.dll'
| where isnotempty(InitiatingProcessSHA256)
| invoke FileProfile(InitiatingProcessSHA256, 1000)
| where GlobalPrevalence <= 50 or isempty(GlobalPrevalence)
| project Timestamp, DeviceId, DeviceName, ActionType, FileName, InitiatingProcessFileName, InitiatingProcessSHA256, InitiatingProcessAccountSid, ReportId;
let NamedPipes = DeviceEvents
| where DeviceId =~ Device
| where Timestamp > ago(TimeFrame)
| where ActionType == 'NamedPipeEvent'
| where isnotempty(InitiatingProcessSHA256)
| join kind=inner (ImageLoads | distinct InitiatingProcessSHA256) on InitiatingProcessSHA256
| where parse_json(AdditionalFields).PipeName == @'\Device\NamedPipe\wkssvc'
| project Timestamp, DeviceId, DeviceName, ActionType, FileName, InitiatingProcessFileName, InitiatingProcessSHA256, InitiatingProcessAccountSid, PipeName = parse_json(AdditionalFields).PipeName, ReportId;
let Connection = DeviceNetworkEvents
| where DeviceId =~ Device
| where Timestamp > ago(TimeFrame)
| where ActionType == 'ConnectionSuccess'
| where isnotempty(InitiatingProcessSHA256)
| join kind=inner (ImageLoads | distinct InitiatingProcessSHA256) on InitiatingProcessSHA256
| project Timestamp, DeviceId, DeviceName, ActionType, RemoteIP, RemoteUrl, InitiatingProcessFileName, InitiatingProcessSHA256, InitiatingProcessAccountSid, ReportId;
union NamedPipes, ImageLoads, Connection
| sort by Timestamp asc, DeviceId, InitiatingProcessSHA256
| scan with_match_id=Id declare (Step:string, Delta:timespan) with (
    step InitialConnection: ActionType == 'ConnectionSuccess' => Step = 's1';
    step NamedPipe: ActionType == 'NamedPipeEvent' and DeviceId == InitialConnection.DeviceId and InitiatingProcessSHA256 == InitialConnection.InitiatingProcessSHA256 and Timestamp between (Timestamp .. datetime_add('second', 1, InitialConnection.Timestamp)) and InitiatingProcessAccountSid == InitialConnection.InitiatingProcessAccountSid => Step = 's2', Delta = Timestamp - InitialConnection.Timestamp;
    step ImageLoad: ActionType == 'ImageLoaded' and DeviceId == NamedPipe.DeviceId and InitiatingProcessSHA256 == NamedPipe.InitiatingProcessSHA256 and Timestamp between (Timestamp .. datetime_add('second', 1, NamedPipe.Timestamp)) and InitiatingProcessAccountSid == NamedPipe.InitiatingProcessAccountSid  => Step = 's3', Delta = Timestamp - NamedPipe.Timestamp;
)
| where Step == 's3'"
$Output = $Query -replace '\r','\r' -replace '\n','\n'
Write-Output $Output