2026/04/05 - 08:44


The Blue Team Playbook (Security Onion)
Open your Hunt tab. Use these specific KQL queries to find the tracks left by the Red Team commands above.

# To see exactly what data you have available in your Security Onion environment
event.dataset: *
OQL Query> * | groupby event.module event.dataset
event.module: This identifies the source engine. You’ll likely see zeek (network metadata), suricata (alerts), endpoint (Elastic Agent), or osquery.
event.dataset: This tells you the flavor of that data. For Zeek, you’ll see conn, dns, http, ssl. For endpoints, you might see process, filesystem, or network.

OQL Query> * | groupby observer.name observer.ip observer.type
observer.name / ip: This reveals the identity of the firewalls, switches, or servers forwarding logs to Security Onion.
observer.type: Tells you if it's a firewall, ids, or host.


Stage 1: Initial Access 

1.2 Sliver Beacon
# Hunting the Sliver Beacon Execution
You ran soupdate.exe and then spawned an interactive session. This creates a parent-child process relationship that is very suspicious.
OQL Query> process.name: "soupdate.exe" OR process.parent.name: "soupdate.exe"
• Why this works: When you typed whoami in Sliver, the beacon spawned a child process to execute that command. This query catches the beacon itself and any commands it runs.
# Hunting the Network C2 (The "Heartbeat")
Your beacon is talking to 192.168.31.130 on port 9001. In a real scenario, you wouldn't know the port, so you hunt for the behavior of the traffic.
OQL Query: destination.ip: "192.168.31.130" AND destination.port: (9001 OR 8088 OR 4443)
• Deep Dive: To see if it's a beacon, look at the network.community_id in SO. If you see the same ID appearing every few seconds (depending on your jitter), that's your C2 heartbeat.

The "Foreign Executable" Hunt (File Ingress)
Legitimate software is usually downloaded via browsers or managed by IT. It is very rare for a user to download an .exe file into C:\Users\Public\.
OQL Query:  event.dataset: "zeek.files" AND file.extension: "exe" AND NOT file.path: "*Program Files*"
• What it finds: Any executable appearing in "weird" places like \Public\, \Temp\, or \Downloads\.

The "Suspect Parent" Hunt (Execution)
This is the "Silver Bullet" for Blue Teams. Standard Windows processes (like cmd.exe or powershell.exe) should be started by explorer.exe (the user) or a system service. They should never be started by a random file sitting in C:\Users\Public\.
OQL Query: process.parent.path: "*\Users\Public\*" OR process.name: ("cmd.exe" OR "powershell.exe" OR "whoami.exe")
◇ What it finds: Any shell or discovery tool born from an untrusted location. This would immediately flag soupdate.exe spawning your reverse shell.

4. The "In-Memory" PowerShell Hunt (Downloaders)
You used a New-Object Net.WebClient command. That is a classic "Living off the Land" (LotL) technique.
OQL Query: process.name: *
OQL Query: process.name: "powershell.exe" OR process.args: ("*Net.WebClient*" OR "*DownloadString*" OR "*IEX*")
OQL Query: process.name : "powershell.exe" and (process.args : "*DownloadFile*")
OQL Query: process.name: "certutil.exe" AND process.args: ("*urlcache*" OR "*split*")
OQL Query: process.name: "bitsadmin.exe" AND process.args: ("*transfer*" OR "*download*")
OQL Query: process.name: ("curl.exe" OR "wget.exe") AND process.args: ("*http*" OR "*-o*" OR "*-O*")
OQL Query: process.name: ("cscript.exe" OR "wscript.exe") AND process.args: ("*http*" OR "*.vbs*" OR "*.js*")
OQL Query: process.name: "mshta.exe" AND process.args: ("*http*" OR "*.hta*")
◇ What it finds: PowerShell being used as a web-downloader rather than a management tool.

5. Non-Standard Port Hunting
Most web traffic goes over 80 or 444. Your Sliver listeners used 9001, 8088, and 4443.
OQL Query: event.dataset: "zeek.conn" AND NOT destination.port: (80, 443, 53, 135, 445)
OQL Query: network.protocol: "dns" OR network.protocol: "http"
OQL Query: network
◇ What it finds: Any "weird" port talk. In a small lab, this will immediately highlight your Kali machine.






Stage2. Persistence
OQL Query: *CurrentVersion\\Run*






Stage 3: Privilege Escalation
Goal: Detect UAC bypass or "RunAs" attempts.
◇ KQL: process.name : "consent.exe" OR process.args : "-Verb runAs"
◇ What to look for: Multiple consent.exe starts in a short window means someone is spamming UAC prompts.
The rasphone.pbk file is the "Phonebook" for Windows Remote Access. It lives at:
System-Wide (All Users): C:\ProgramData\Microsoft\Network\Connections\Pbk\rasphone.pbk
User-Specific: C:\Users\<username>\AppData\Roaming\Microsoft\Network\Connections\Pbk\rasphone.pbk
Process Injection /Task Hijacking: Your Sliver beacon (soupdate.exe) may have instructed Windows to load a malicious COM object. Windows then starts dllhost.exe process to run that object and read rasphone.pbk.


3.2 GodPotato for PrivEsc + Donut for Process Injection
1. Identity Preparation (Rubeus)
• Log Source: Windows Security Event 4624 (Logon)
• Detection Query: winlog.event_data.LogonType: 9
event.module:system AND event.code:4624
event.code: "4624" AND winlog.event_data.LogonType: "9"
event.code: "4624" AND winlog.event_data.LogonProcessName: "seclogo" AND winlog.event_data.TargetOutboundUserName: *
• The "Smell" (Interesting Data): * Look for High-Entropy Strings: Random gibberish in the Network Account Name (e.g., FYOLXO8G) and Network Account Domain (e.g., 3MQEY1CD).
◇ These are generated by Rubeus to create a unique, isolated logon session.
◇ Logon Type 9 = “NewCredentials” (a.k.a. RunAs / S4U / Pass‑the‑Hash style impersonation)
◇ Pivot on the LUID: In your Event ID 4624, find the Logon ID (e.g., 0x20449F). Use this ID to filter all other logs. You will see every action that "Jan" took while using that specific, suspicious session. winlog.event_data.SubjectLogonId: 0x20449F = This is the LUID of the original user who ran the command.

2. Process Staging (Rubeus)
◇ Log Source: Sysmon Event 1 / Security 4688 (Process Creation)
◇ Detection Query: process.name: "notepad.exe" AND winlog.event_data.LogonType: 9
◇ The "Smell" (Interesting Data): * Suspicious Parent: You will see svchost.exe spawning notepad.exe.
▪ This happens because Rubeus uses the Secondary Logon Service (seclogo) to create the "sacrificial" process.
The seclogo (Secondary Logon) process is what facilitates "Run as different user." Seeing svchost.exe (which hosts seclogo) as the source of a Logon Type 9 for jan.tinbergen confirms that a tool requested a new process context.
This is a "cloning" operation. It happens when a user who is already logged in starts a new process and tells Windows: "Locally, I want to stay as Jan, but if this specific process tries to talk to the network, use these other credentials instead."

3. C2 Call Home (Sliver)
◇ Log Source: Sysmon Event 3 (Network Connection) / Zeek (Network Metadata)
◇ Detection Query: process.name: "notepad.exe" AND NOT destination.ip: "127.0.0.1"
◇ The "Smell" (Interesting Data): * Beaconing Behavior: Frequent, small, outbound encrypted packets (mTLS) originating from notepad.exe.
▪ Standard text editors do not typically communicate with external IP addresses on the internet.

• Watch for "Living off the Land" abuse: Create a visualization in Kibana for "Network Connections by Non-Browser Processes." If notepad.exe, calc.exe, or cmd.exe appear with outbound external traffic, it should trigger a high-priority alert.
• The "Jan" Baseline: Since you know jan.tinbergen was the account used, filter for her activity over the last 24 hours. Look for the transition from her normal Logon Type 2 (Interactive) to the red team's Logon Type 9.






Stage 4: Credential Access
Goal: Catch someone touching the password database (LSASS).
dbgcore.dll provides the MiniDumpWriteDump function.

4.1 & 4.2  Kerberoasting & AS-REP Roasting (Rubeus)
Rubeus is requesting Service Tickets (TGS) or Authentication Responses (AS-REP) for specific accounts.
• SO Query: event.code: (4769 OR 4768) AND winlog.event_data.TicketEncryptionType: "0x17"
• The Logic: Most modern Windows environments use AES (0x12). Kerberoasting often requests RC4 (0x17) because it is much faster to crack offline.
• IOC to Watch: A single user (Jan) requesting many Service Tickets (4769) in a short window, especially if the Service Name is not a standard computer account (e.g., HTTP/bvt-web).
Kerberoasting
winlog.event_data.PreAuthType: 0 → No Pre-Authentication = Do not require Kerberos preauthentication. → AS-REP Roasting
winlog.event_data.TicketEncryptionType: 0x17 = RC4-HMAC encryption → weak encryption for offline cracking
winlog.event_data.TicketOptions: 0x40800010 → These flag define how the ticket can be used
• 0x40000000 = Forwardable
• 0x00800000 = Renewable
• 0x00000010 = Renewable-ok
• The Finding: This specific combination is a signature of Rubeus. While legitimate Windows clients use similar flags, the way Rubeus requests the ticket often results in this specific hex pattern in the logs.
Service Name = krbtgt → The user is asking the DC for a Master Ticket (TGT).
AS-REPRoasting
winlog.event_data.ServiceName: jan.tinbergen → Service is under User Account name. Service name should be a computer name (ending $)
winlog.event_data.TicketEncryptionType: 0x17 = RC4-HMAC encryption → weak encryption for offline cracking
Account Name: DESKTOP-9N19EBO$ while Service Name: jan.tinbergen → Account Mismatch

4.3 DCSync (Mimikatz)
DCSync is the "Crown Jewel" of detection. It mimics a Domain Controller to ask for account secrets.
Event ID 4662 = Captures the use of Extended Rights on AD objects.
◇ SO Query: event.code: 4662 AND winlog.event_data.Properties: (*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2* OR *1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*)
◇ The Logic: These GUIDs represent "Replicating Directory Changes." Only real Domain Controllers should ever perform this action.
◇ IOC to Watch: Look for a non-DC computer (Jan's workstation) performing "Replication" against the DC.
The "Replication" GUIDs
• Value: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 (DS-Replication-Get-Changes)
• Value: 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 (DS-Replication-Get-Changes-All)
• Reasoning: These are the specific technical "permissions" required to pull hashes from the NTDS.dit database. Under normal circumstances, only Domain Controllers (accounts ending in $) should ever request these. Seeing jan.tinbergen or your workstation IP requesting these is a "Defcon 1" alert.
winlog.event_data.AccessMask : 0x100 → Access Mask 0x100.  This indicates that the user is not just "reading" a property (like a phone number), but exercising a high-level extended right (Control Access) over the domain root object.
winlog.event_data.ObjectName : DC=bvt,DC=local → The Object Name, DCSync targets the root of the domain. Standard users might look up objects in an OU, but they almost never perform "Control Access" operations on the entire domain root. 

4.4 Golden Ticket (Rubeus)
A Golden Ticket is a forged TGT. It’s hard to detect because it looks like a valid login, but there are "telltale" signs in the metadata.
◇ SO Query: event.code: 4624 AND winlog.event_data.LogonType: 3 AND winlog.event_data.TargetUserName: "Administrator" AND winlog.event_data.AuthenticationPackageName: "Kerberos"
◇ The Logic: Look for the Ticket Lifetime. A default Golden Ticket often has a 10-year lifetime, whereas Windows defaults to 10 hours.
◇ IOC to Watch: Event 4624 where the user is Administrator but the Logon ID is not linked to a previous 4672 (Special Logon) or 4768 (TGT Request). It’s a "Session from nowhere."



4. LSASS / NTDS.dit / SAM Dumping
This is the physical theft of the credential databases.
LSASS
◇ SO Query (Process Access): process.command_line: *procdump* OR process.command_line: *lsass.dmp*
process.args: ["-ma", "lsass.exe"] → -ma stands for "Full Dump." = For LSASS, this ensures that all cached credentials, NTLM hashes, and Kerberos tickets are written to the .dmp file.
process.executable: C:\Users\Public\procdump64.exe → Procdump executable
lsass.dmp → Dump File
user.name: SYSTEM → To dump LSASS memory, you need the highest possible privileges on the local machine.
NTDS.dit
◇ SO Query (NTDS Capture): process.command_line: *ntdsutil* AND process.command_line: (*ifm* OR *create*)
◇ The Logic: ntdsutil is a legitimate tool, but using it to "create full" snapshots in C:\Windows\Temp is 99% malicious.
◇ IOC to Watch:
process.command_line Values: ac i ntds, ifm, create full → These are the specific sub-commands for ntdsutil to trigger an Install From Media backup.
C:\Windows\Temp\Dump → Attackers need a place to store the hundreds of megabytes of data they are about to steal.
Hostname win-39at6p60vj5 →  Confirms the attack reached the Domain Controller.
Exit Code 0 → Success The database was successfully dumped to the Temp folder.
Code Signature unsigned →  (Parent)The Sliver beacon has no valid signature, raising the alert score.

▪ SAM/LSA Registry Export: reg.exe save hklm\sam or reg.exe save hklm\system.
SO Query: event.code: 4663 AND winlog.event_data.ObjectName: (*SAM* OR *SECURITY*)    → Object Access: Someone is physically touching the SAM registry hive.
SO Query: event.code: 5145 AND winlog.event_data.RelativeTargetName: "winreg"    →  IPC$ Share Access, To dump the SAM, NXC must connect to the winreg named pipe over SMB. This query looks for the "Network Share Object" access.
SO Query: event.code: 7045 AND winlog.event_data.ServiceName: "RemoteRegistry"    → Remote Registry Service Start, NetExec will automatically try to start this service if it’s disabled. Seeing this service start on a DC, triggered by a remote user like Jan, is highly suspicious.
SO Query: event.code: 4624 AND winlog.logon.type: "Network"
IOC to watch:
user.name: ANONYMOUS LOGON → anonymous access to a Domain Controller should be zero.
winlog.event_data.LmPackageName: NTLM V1 → NTLM V1 is deprecated and highly vulnerable to relay attacks. Attackers use NTLM V1 because many exploitation libraries (like older versions of Impacket or certain Kali tools) default to it for speed and compatibility. This stands out in logs
winlog.event_data.WorkstationName: -  → Empty Workstation Name. Kali tools often leave this blank. A "Blank Workstation" + "Anonymous Logon" + "NTLM V1" is the classic "Attacker in the Room" profile.


+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Summary Table for Notes
| Attack                | Event ID                  | Interesting IOC / Reasoning                                                                                                                    |
| Kerberoast 		| 4769 			| TicketEncryptionType: 0x17. Indicates a downgrade to weak RC4 for easier cracking. |
| DCSync 		| 4662 			| Access to Replicating Directory Changes GUIDs from a non-DC IP address. |
| Golden Ticket 	| 4624 			| Domain: BVT but no corresponding 4768 (TGT request) on the DC logs for that session. |
| NTDS Dump 		| 1 (Sysmon) 		| ntdsutil.exe used with ifm (Install From Media) arguments. |
| SAM Dump 		| 4624 / 3 		| Inbound SMB connection to DC from Jan, followed by S-1-5-21...-500 (Admin) access. |


Final SOC Tip:
For the SAM Dump (via nxc / NetExec), look for Event ID 4624 with Logon Type 3 (Network) followed immediately by Event ID 4663 (Object Access) on the registry hives SAM and SECURITY. Standard users should never trigger an audit for reading these sensitive keys.






Stage 5: Defense Evasion
Goal: Find hidden PowerShell commands.
◇ KQL: process.command_line : ("*enc*" or "*EncodedCommand*")
◇ Pro-Tip: In the Hunt window, click the "Group By" button and select process.command_line to see the Base64 strings.

Stage 5: Persistence
Goal:
KQL> registry.path : "*\CurrentVersion\Run*"






Stage 6: Lateral Movement
Goal: See one computer talking to many others on sensitive ports.
◇ KQL: destination.port : (445 or 135 or 5985) and network.direction : "internal"
◇ Hunt Method: Group by source.ip and count destination.ip. If one "Student" IP is talking to 50 other IPs on port 445, they are scanning your network.

6.3 PTH
SO Query: event.code: 4624 AND winlog.event_data.LogonType: 3
SO Query: event.code: 4624 AND winlog.event_data.LogonType: 3 AND winlog.event_data.TargetUserName: "Administrator" AND winlog.event_data.AuthenticationPackageName: "NTLM"
IOC to watch:
1. The "Ghost" Source (Workstation Name)
• Field: Workstation Name: -  → IOC: The workstation name is empty (indicated by the hyphen).
• Reasoning: When a real Windows machine connects to another, it almost always provides its NetBIOS name (e.g., JAN-LAPTOP). Linux-based tools like Impacket often leave this field blank or use a default that doesn't match the environment.

2. The "Elevated" Network Login
◇ Field: Logon Type: 3 and Elevated Token: Yes → IOC: A Network login (Type 3) that is immediately granted an Elevated Token.
◇ Reasoning: Most remote network logons for standard users are not "Elevated." However, psexec specifically targets the ADMIN$ share, which requires administrative privileges. Seeing the built-in Administrator (RID 500) logging in from an external IP (192.168.31.130) and getting full elevation is a major red flag.

3. The NTLM vs. Kerberos Tell
◇ Field: Authentication Package: NTLM and Logon Process: NtLmSsp → IOC: The use of NTLM for a Domain Administrator account.
◇ Reasoning: In a modern domain like BVT.LOCAL, Windows prefers Kerberos for almost everything. psexec.py -hashes ... forces the use of NTLM because it is passing the NT hash directly.

Decoding the "psexec" Signature
Since psexec installs a service, they should look for Event ID 7045 (Service Control Manager (SCM) generated for new service installed).
• SO Query: event.code: 7045
The details in this Event ID 7045 are the textbook indicators of Impacket’s psexec module:
• Service Name (zcCE): Impacket generates a random 4-character string for the service name to avoid signature-based detection of constant names like "PSEXESVC".
• Service File Name (%systemroot%\pihogMSy.exe): Note the random name (8 characters) here as well. psexec uploads this binary to the ADMIN$ share (which is C:\Windows\) before registering it as a service.
• Service Account (LocalSystem): This is the ultimate goal. Even though you logged in as Administrator, the service runs as SYSTEM, giving you full control over the OS kernel and memory.
• User Identifier (...-500): The winlog.user.identifier ends in 500, confirming the built-in Administrator account was the one that commanded the Service Control Manager to create this entry.










Stage 7: Exfiltration
Goal: Find data leaving the network via unusual tools.
◇ KQL: process.name : "bitsadmin.exe" OR (network.bytes > 10000000 and NOT network.direction : "internal")
