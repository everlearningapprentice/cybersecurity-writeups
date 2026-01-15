# Sherlock Investigation Report (Threat Intelligence)

## I. Executive Summary

* **Scenario Name:** \[SalineBreeze-1]
* **Case ID:** \[littlestarlight/2025-11-01]
* **Adversary Group:** \[`Salt Typhoon`/`Earth Estries`/`FamousSparrow`,`GhostEmperor`,`UNC2286`]
* **Targeted System:** **\[Network Infrastructure]** of telecommunication, government, and technology sectors
* **Motive:** Geopolitical Gain. Salt Typhoon is a People's Republic of China (PRC) state-backed actor that has been active since at least 2019.

---

## II. MITRE ATT&CK Techniques Used

### `T1098.004` --- Account Manipulation: SSH Authorized Keys
The threat actor added SSH `authorized_keys` under root or other users at Linux level

### `T1110.002` --- Brute Force: Password Cracking
The threat actor cracked passwords for accounts with weak encryption obtained from the configuration files of compromised network devices.

### `T1136` --- Create Account
The threat actor created Linux-level users through modification of \[`/etc/shadow/`, `/etc/passwd`].

### `T1602.002` --- Data from Configuration Repository: Network Device Configuration Dump
The threat actor attempted to acquire additional credentials by dumping network device configurations.

### `T1587.001` --- Develop Capabilities: Malware
The threat actor has used custom-built utility, dubbed JumbledPath.

### `T1048.003` --- Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol
The threat actor has exfiltrated device configurations from exploited network devices over FTP and TFTP.

### `T1190` --- Exploit Public-Facing Application
The threat actor has exploited \[`CVE-2018-0171`] in the Smart Install feature of Cisco IOS and Cisco IOS XE software for initial access.

### `T1590.004` --- Gather Victim Network Information: Network Topology
The threat actor has used the exfiltrated device configuration files to help discover upstream and downstream network segments.

### `T1562.004` --- Impair Defenses: Disable or Modify System Firewall
The threat actor has made changes to the Access Control List (ACL) and loopback interface address on compromised devices.

### `T1070.002` --- Indicator Removal: Clear Linux or Mac System Logs
The threat actor has cleared logs including \[`.bash_history`, `auth.log`, `lastlog`, `wtmp`, `btmp`].

### `T1040` --- Network Sniffing
The threat actor has used a variety of tools \[`Tcpdump`, `Tpacap`, `Embedded Packet Capture (EPC)`, `JumbledPath`] to capture packet data between network interfaces.

### `T1588.002` --- Obtain Capabilities: Tool
The threat actor has used publicly available tooling \[`Tcpdump`, `Tpacap`, `Embedded Packet Capture (EPC)`] to exploit vulnerabilities.

### `T1572` --- Protocol Tunneling
The threat actor has modified device configurations to create and use Generic Routing Encapsulation (GRE) tunnels.

### `T1021.004` --- Remote Services: SSH
The threat actor repeatedly modified the loopback address on compromised switches and used them as the source of SSH connections to additional devices within the target environment, allowing them to bypass access control lists (ACLs).

## III. Common Vulnerabilities and Exposures (CVEs) Exploited


### CVE-2021-26855

### CVE-2021-26857

### CVE-2021-26858

### CVE-2021-27065

### CVE-2022-3236

### CVE-2023-46805

### CVE-2023-48788

### CVE-2024-21887


## IV. Software

### `S1206` --- JumbledPath
* **Usage:** \[at least 2024]
* **Language:** \[`GO`]
* **Binary:** \[`ELF binary`]
* **Architecture:** \[`x86-64 architecture`]
* **Portability:** \[Potentially usable across **Linux operating systems and network devices** from multiple vendors]
* **Techniques**
It allowed them to execute a packet capture \[`T1040`] on a remote Cisco device through an actor-defined jump-host \[`T1104`,`T1665`]. It also attempted to clear logs and impair logging along the jump-path \[`T1562`, `T1070.002`] and return the resultant compressed, encrypted capture \[`T1560`] via another unique series of actor-defined connections or jumps \[`T1665`]. This allowed the threat actor to create a chain of connections and perform capture on a remote device. The use of this utility would help to obfuscate the original source and the ultimate destination, of the request and would also allow its operator to move through potentially otherwise non-publicly-reachable (or routable) devices or infrastructure.

### GhostSpider
* **Usage:** \[at least 2024]
* **Language:** \[``]
* **Binary:** \[``]
* **Architecture:** \[``]
* **Portability:** \[]
* **Techniques**
It is a multi-modal backdoor malware designed with several layers to load different modules based on specific purposes. This backdoor communicates with its C&C server using a custom protocol protected by Transport Layer Security (TLS), ensuring secure communication.
that allowed them to gain persistent access to compromised systems 

Among Salt Typhoon’s arsenal is the advanced "GhostSpider" backdoor malware, specifically engineered to infiltrate telecommunications networks [2]. This tool provides persistent access to compromised systems, enabling prolonged surveillance and data extraction.

### Snappybee
* **Usage:** \[at least 2024]
* **Language:** \[``]
* **Binary:** \[``]
* **Architecture:** \[``]
* **Portability:** \[]
* **Techniques**
It is a backdoor malware.

### Masol RAT
* **Usage:** \[at least 2024]
* **Language:** \[``]
* **Binary:** \[``]
* **Architecture:** \[``]
* **Portability:** \[]
* **Techniques**
It is a backdoor malware.

### Demodex
* **Usage:** \[at least 2024]
* **Language:** \[``]
* **Binary:** \[``]
* **Architecture:** \[``]
* **Portability:** \[]
* **Techniques**
It is a rootkit.

---

## V. References
* https://attack.mitre.org/groups/G1045/ \[**MITRE ATT&CK**]
* https://blog.talosintelligence.com/salt-typhoon-analysis/ \[**Cisco Talos**]
* https://www.picussecurity.com/resource/blog/salt-typhoon-telecommunications-threat \[**Picus Security**]
* https://www.trendmicro.com/en_us/research/24/k/earth-estries.html \[**Trend Micro**]