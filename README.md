# Douglas-042 - Threat Hunting 
# Incident Response - PowerShell Hunting
[![EmreKybs](https://img.shields.io/badge/MadeBy-Emrekybs-blue)
<img src="https://github.com/emrekybs/Douglas-042/blob/main/Douglas.png">
   
DOUGLAS-042 stands as an ingenious embodiment of a PowerShell script meticulously designed to expedite the triage process and facilitate the meticulous collection of crucial evidence derived from both forensic artifacts and the ephemeral landscape of volatile data. Its fundamental mission revolves around providing indispensable aid in the arduous task of pinpointing potential security breaches within Windows ecosystems. With an overarching focus on expediency, DOUGLAS-042 orchestrates the efficient prioritization and methodical aggregation of data, ensuring that no vital piece of information eludes scrutiny when investigating a possible compromise. As a testament to its organized approach, the amalgamated data finds its sanctuary within the confines of a meticulously named text file, bearing the nomenclature of the host system's very own hostname. This practice of meticulous data archival emerges not just as a systematic convention, but as a cornerstone that paves the way for seamless transitions into subsequent stages of the Forensic journey.

### 支持查询的内容
1、常规信息；
2、帐户和组信息；
3、网络状态；
4、进程信息；
5、OS Build和HOTFIXE；
6、硬件信息；
7、持久化；
8、加密信息；
9、防火墙信息；
10、服务信息；
11、历史日志；
12、SMB查询；
13、远程处理查询；
14、注册表分析；
15、日志查询；
16、软件安装；
17、用户活动；

### 高级查询
1、查询Prefetch文件信息；
2、DLL列表；
3、WMI筛选器；
4、命名管道；


### Content Queries
* General information
* Accountand group information
* Network
* Process Information
* OS Build and HOTFIXE 
* Persistence
* HARDWARE Information
* Encryption information
* FIREWALL INFORMATION
* Services
* History
* SMB Queries
* Remoting queries
* REGISTRY Analysis
* LOG queries
* Instllation of Software
* User activity
### Advanced Queries
* Prefetch file information
* DLL List
* WMI filters and consumers
* Named pipes

# Usage
Using administrative privileges, just run the script from a PowerShell console, then the results will be saved in the directory as a txt file.

    $ PS >./douglas.ps1
    
# Advance usage
    $ PS >./douglas.ps1 -a

<img src="https://github.com/emrekybs/Douglas-042/blob/main/png.jpg">
