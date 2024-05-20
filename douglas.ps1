param(
[Parameter(Mandatory=$False)]
[Switch]$a
)

$banner = @"

    ____                    __                 ____  __ __ ___ 
   / __ \____  __  ______ _/ /___ ______      / __ \/ // /|__ \
  / / / / __ \/ / / / __ `/ / __ `/ ___/_____/ / / / // /___/ /
 / /_/ / /_/ / /_/ / /_/ / / /_/ (__  )_____/ /_/ /__  __/ __/ 
/_____/\____/\__,_/\__, /_/\__,_/____/      \____/  /_/ /____/ 
                  /____/                                       ⠀⠀⠀

          +----DEFENSE BY OFFENSE BLUE TEAM----+     
               
                      "ву ємяє кувѕ"
   
      +------𝐈𝐧𝐜𝐢𝐝𝐞𝐧𝐭 𝐑𝐞𝐬𝐩𝐨𝐧𝐬𝐞 & 𝐓𝐡𝐫𝐞𝐚𝐭 𝐇𝐮𝐧𝐭𝐢𝐧𝐠------+ 



"@

    Write-Host $banner -ForegroundColor Red
    $ErrorActionPreference= 'silentlycontinue'

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    Write-Host '𝘿𝙤𝙪𝙜𝙡𝙖𝙨-042 you must run it with Administrator privileges'
    Exit 1
}

$ip = ((ipconfig | findstr [0-9].\.)[0]).Split()[-1]
$blue = (gi env:\Computername).Value
Write-Host "Collecting data for $blue ($ip) | $(Get-Date -Format dd/MM/yyyy-H:mm:ss)"

$data = {
"==== 一般信息 ===="
#Get-ComputerInfo | Format-List -Property CsDNSHostName, CsDomain, OsName, OsVersion, OsBuildNumber, OsArchitecture, OsUptime, OsLocalDateTime, TimeZone, OsSerialNumber, OsMuiLanguages, OsHotFixes, WindowsRegisteredOrganization, WindowsRegisteredOwner, WindowsSystemRoot, OsPagingFiles, CsManufacturer, CsModel, CsName, CsProcessors, CsNetworkAdapters, BiosBIOSVersion, BiosSeralNumber, BiosFirmwareType, CsDomainRole, OsStatus, OsSuites, LogonServer, DeviceGuardSmartStatus, DeviceGuardRequiredSecurityProperties, DeviceGuardAvailableSecurityProperties, DeviceGuardSecurityServicesConfigured, DeviceGuardSecurityServicesRunning, DeviceGuardCodeIntegrityPolicyEnforcementStatus, DeviceGuardUserModeCodeIntegrityPolicyEnforcementStatus
systeminfo
"------------------------------------------------------------------------------------------------------------------------------------
"

"--- 组策略设置 ---"
gpresult.exe -z
"----------------------------------------
"

"--- 加密信息 ---"
manage-bde.exe -status
"----------------------------------------
"
"==== 账户和组信息 ===="
"--- 所有用户（包括隐藏账户） ---"
Get-WmiObject -Class Win32_UserAccount
"----------------------------------------
"
"--- 本地用户 ---"
Get-LocalUser
"----------------------------------------
"
"--- 启用的本地用户 ---"
Get-LocalUser | ? Enabled -eq "True"
"----------------------------------------
"
"--- 本地组 ---"
Get-LocalGroup
"----------------------------------------
"
"--- 本地组管理员 ---"
Get-LocalGroup Administrators
"----------------------------------------
"
"--- 账户设置 ---"
net accounts
"----------------------------------------
"


"==== 操作系统版本和修补程序 ===="
"--- 修补程序 ---"
Get-HotFix
"----------------------------------------
"
"--- 操作系统 ---"
Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, Servicepackmajorversion, BuildNumber, CSName, LastBootUpTime
Get-ItemProperty "HKLM:\SOFTWARE\MICROSOFT\windows NT\CurrentVersion" | Select-Object ReleaseId
"----------------------------------------
"


"==== 硬件查询 ===="
"--- BIOS信息 ---"
gcim -ClassName Win32_BIOS | fl Manufacturer, Name, SerialNumber, Version;
"-----------------------------------------------------------------------------
"
"--- 处理器信息 ---"
gcim -ClassName Win32_Processor | fl caption, Name, SocketDesignation;
"-----------------------------------------------------------------------------
"
"--- 制造商、系统系列、型号、系统类型信息 ---"
gcim -ClassName Win32_ComputerSystem | fl Manufacturer, Systemfamily, Model, SystemType
"----------------------------------------
"
"--- 逻辑磁盘驱动器信息 ---"
gcim  -ClassName Win32_LogicalDisk
gcim  -ClassName Win32_LogicalDisk |Select -Property DeviceID, DriveType, @{L='FreeSpaceGB';E={"{0:N2}" -f ($_.FreeSpace /1GB)}}, @{L="Capacity";E={"{0:N2}" -f ($_.Size/1GB)}} | fl
"----------------------------------------
"

"==== 防火墙信息 ===="
"--- Windows防火墙配置 ---"
netsh advfirewall show currentprofile
"----------------------------------------
"
"--- 防火墙配置文件 ---"
Get-NetFirewallProfile
"----------------------------------------
"
"--- 防火墙设置 ---"
Get-NetFirewallSetting
"----------------------------------------
"
"--- 未启用的防火墙 ---"
Get-NetFirewallRule | Where-Object { $_.Enabled -ne $true }
"----------------------------------------
"
"==== 网络信息 ===="
"--- 活动网络接口 ---"
Get-NetAdapter | ? status -eq "up" |  Get-NetIPAddress | Select IPAddress,InterfaceIndex, InterfaceAlias, AddressFamily,PrefixOrigin |Sort InterfaceAlias | Format-Table -Wrap
"----------------------------------------
"
"--- 活动的TCP连接远程IP ---"
(Get-NetTCPConnection).remoteaddress | Sort-Object -Unique
"----------------------------------------
"
"--- 列出UDP端点 ---"
Get-NetUDPEndpoint | select local*,creationtime, remote* | ft -autosize
"----------------------------------------
"
"--- 网络IPv6地址 ---"
Get-NetIPAddress -AddressFamily IPv6  | ft Interfacealias, IPv6Address
"----------------------------------------
"
"--- 显示互联网上的TCP连接 ---"
Get-NetTCPConnection -AppliedSetting Internet | select-object -property remoteaddress, remoteport, creationtime | Sort-Object -Property creationtime | format-table -autosize
"----------------------------------------
"

"==== 检查主机文件 ===="
"--- DNS缓存 ---"
Get-DnsClientCache
"----------------------------------------
"
"---- DNS缓存成功 ----"
Get-DnsClientCache -Status 'Success' | Select Name, Data
"----------------------------------------
"


"--- 主机文件及属性 ---"
gc "C:\Windows\System32\Drivers\etc\hosts"
gci "C:\Windows\System32\Drivers\etc\hosts" | fl *Time* 
"----------------------------------------
"

"==== 共享文件夹 ===="
net use
"----------------------------------------
"

"==== 进程信息 ===="
"--- 进程连接 ---"
$nets = netstat -bano|select-string 'TCP|UDP'; 
foreach ($n in $nets)    
{
$p = $n -replace ' +',' ';
$nar = $p.Split(' ');
$pname = $(Get-Process -id $nar[-1]).Path;
$n -replace "$($nar[-1])","$($ppath) $($pname)";
}
"----------------------------------------
"
"--- 正在运行的进程 ---"
tasklist /v /fo table /fi "STATUS ne Unknown"
"----------------------------------------
"
"--- 进程AppData ---"
get-process | ?{$_.Path -like '*appdata*'}
"----------------------------------------
"
"--- 进程AppData详细信息 ---"
get-process | select name, path, starttime, ID | ?{$_.Path -like '*appdata*'} | fl
"----------------------------------------
"
"--- 进程列表 ---"
Get-Process -IncludeUserName | Format-Table -Property Name, Id, Path, UserName, Company, Handles, StartTime, HasExited -Wrap
"----------------------------------------
"
"--- 前7个CPU使用率 ---"
Get-Process | Sort-Object CPU -Descending | Select-Object -First 7 | Format-Table Name, CPU, WorkingSet -AutoSize
"----------------------------------------
"
"--- 前7个内存使用率 ---"
Get-Process | Sort-Object WorkingSet -Descending | Select-Object -First 7 | Format-Table Name, WorkingSet -AutoSize
"----------------------------------------
"
"--- 进程命令行 ---"
Get-WmiObject Win32_Process | Select-Object Name,  ProcessId, CommandLine | Sort Name | Format-Table -Wrap
"----------------------------------------
"


"==== 持久性 ===="
"--- 启动命令 ---"
Get-CimInstance -Class Win32_StartupCommand | Format-Table -Property Name, Command, User, Location -Wrap
"----------------------------------------
"
"--- 计划任务 ---"
(Get-ScheduledTask).Where({$_.State -ne "Disabled"}) | Sort TaskPath | Format-Table -Wrap
"----------------------------------------
"
"--- 计划任务（WIFI） ---"
Get-ScheduledTask -Taskname "wifi*" | fl *
"----------------------------------------
"


"======== 服务查询 ======="
"--- 基本服务信息 ---"
Get-Service | Select-Object Name, DisplayName, Status, StartType
"----------------------------------------
"
"--- 详细的服务信息 ---"
Get-WmiObject win32_service | Select-Object Name, PathName, StartName, StartMode, State, ProcessId | Sort PathName| Format-Table -Wrap
#Get-CimInstance -Class Win32_Service -Filter "Caption LIKE '%'" | Select-Object Name, PathName, ProcessId, StartMode, State | Format-Table
"----------------------------------------
"
"--- 自动服务信息 ---"
Get-Service | Select-Object Name,DisplayName, Status,StartType | where StartType -eq "Automatic"
"----------------------------------------
"
"--- 正在运行的服务信息 ---"
Get-Service | Select-Object Name,DisplayName, Status,StartType | where Status -eq "Running"
"----------------------------------------
"
"--- 事件日志服务 ---"
get-service -name "eventlog" | fl *
"----------------------------------------
"


"======== 软件安装 ======="
Get-CimInstance -ClassName win32_product | Select-Object Name,Version, Vendor, InstallDate, InstallSource, PackageName, LocalPackage |  Format-Table -Wrap
"----------------------------------------
"


"==== 用户活动 ===="
"--- 最近使用的USB设备 ---"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\* | Select FriendlyName
"----------------------------------------
"
"--- 最近修改的文件 ---"
$RecentFiles = Get-ChildItem -Path $env:USERPROFILE -Recurse -File
$RecentFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 50 FullName, LastWriteTime
"----------------------------------------
"

"--- PowerShell历史记录 ---"
Get-History
"----------------------------------------
"
"--- Kerberos会话 ---"
klist sessions
"----------------------------------------
"


"==== SMB QUERIES ===="
"--- SMB会话 ---"
Get-SmbSession
"----------------------------------------
"
"--- SMB查询 ---"
Get-SmbShare; Get-SmbShare | Select-Object Dialect, ServerName, ShareName | Sort-Object Dialect
"----------------------------------------
"
"--- SMB连接 ---"
Get-SmbConnection
"----------------------------------------
"


"==== 远程查询 ===="
"--- RDP会话 ---"
qwinsta /counter
"----------------------------------------
"
"--- RDP状态启用-禁用 ---"
if ((Get-ItemProperty "hklm:\System\CurrentControlSet\Control\Terminal Server").fDenyTSConnections -eq 0){write-host "RDP Enabled" } else { echo "RDP Disabled" }
"----------------------------------------
"
"--- PowerShell会话 ---"
Get-PSSession
"----------------------------------------
"
"--- PowerShell会话配置 ---"
Get-PSSessionConfiguration | fl Name, PSVersion, Permission
"----------------------------------------
"


"==== 注册表分析 ===="
"--- 列出Windows注册表项 ---"
(Gci -Path Registry::).name
"----------------------------------------
"
"--- 列出HKCU注册表项 ---"
Get-ChildItem -Path HKCU:\ | Select-Object -ExpandProperty Name
"----------------------------------------
"
"--- Run注册表项中的HKCU属性 ---"
Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\"
"----------------------------------------
"
"--- Run注册表项中的HKLM属性 ---"
Get-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\" | Get-ItemProperty


"==== 日志查询 ===="
"--- 事件日志列表 ---"
Get-Eventlog -List 
"----------------------------------------
"
"--- 最近20条应用程序日志 ---"
Get-Eventlog Application -Newest 20
"----------------------------------------
"
"--- 最近20条系统日志 ---"
Get-Eventlog system -Newest 20
"----------------------------------------
"
"--- 最近20条安全日志 ---"
Get-Eventlog security -Newest 20
"----------------------------------------
"



if ($a -eq $true)
{
"==== 高级调查 ===="
"--- 总进程实例 ---"
Get-Process | Group-Object ProcessName | Select Count, Name | Sort Count -Descending
"----------------------------------------
"

"--- 预取文件 ---"
gci C:\Windows\Prefetch\ | Sort Name | Format-Table Name,CreationTime,LastWriteTime,LastAccessTime
"----------------------------------------
"

"--- DLL列表 ---"
gps | Format-List ProcessName, @{l="Modules";e={$_.Modules|Out-String}}
"----------------------------------------
"

"--- WMI ---"
Get-WmiObject -Class __FilterToConsumerBinding -Namespace root\subscription | FT Consumer,Filter,__SERVER -wrap
"----------------------------------------
"

"--- WMI筛选器 ---"
Get-WmiObject -Class __EventFilter -Namespace root\subscription | FT Name, Query, PSComputerName -wrap
"----------------------------------------
"

"--- WMI消费者 ---"
Get-WmiObject -Class __EventConsumer -Namespace root\subscription | FT Name,ScriptingEngine,ScriptText -wrap
"-------------------------------------------------------------------
"

"--- Windows Defender 排除项 ---"
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions'
"--------------------------------------------------------------------
"
"--- 最近 3 天修改的 .exe 文件列表 ---"
$limit = (Get-Date).AddDays(-3); Get-ChildItem -Path C:\ -Recurse -Include *.exe | Where-Object { $_.LastWriteTime -ge $limit } | ForEach-Object { Write-Host "$($_.Extension) $($_.Name) $($_.LastWriteTime)" }
"--------------------------------------------------------------------
"


"--- 命名管道列表 ---"
Get-ChildItem -Path '\\.\pipe\' |  Sort Length | Format-Table FullName, Length, IsReadOnly, Exists, CreationTime, LastAccessTime
"-------------------------------------------------------------------
"

}

}

& $data | Out-File -FilePath $pwd\REPORT_$blue.txt
Write-Host "Data saved in $pwd\REPORT_$blue.txt" -ForegroundColor Green
