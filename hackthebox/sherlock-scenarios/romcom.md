# Sherlock Investigation Report

## I. Executive Summary

  * **Scenario Name:** \[RomCom]
  * **Case ID:** \[littlestarlight/2025-10-31]
  * **Final Conclusion:** A successful compromise was confirmed on the target system by an unidentified attacker. The attacker exploited **\[CVE-2025-8088]** to achieve **\[persistence]**.
  * **Key Evidence:** The definitive proof was found in the **\[$MFT]** (Master File Table) and **\[$J]** (USNJournal) showing covertly added files.

-----

## II. Chronological Timeline of Events

### Event 1: Malicious File Download (RAR)

  * **Timestamp (UTC):** \[2025-09-02 08:13:50]
  * **Source File / Artifact:** \[`$MFT`,`$J`]
  * **Event Description:** A malicious RAR archive was downloaded by the user from an external source.
  * **Analysis:** Initial delivery of the threat. The RAR archive \[`Pathology-Department-Research-Records.rar`] was found in `$MFT`, but two files were discovered with conflicting creation times. The correct time was extracted and confirmed from the USN Journal `$J`. THe correct path is determined to be `C:\Users\susan\Documents`.

### Event 2: Malicious Archive Payload Execution

  * **Timestamp (UTC):** \[2025-09-02 08:14:18]
  * **Source File / Artifact:** \[`$MFT`,`$J`]
  * **Event Description:** The user extracted the files from the downloaded RAR, and the malicious files were executed.
  * **Analysis:** Initial system compromise.
    * Of the other five records were found in the same path `C:\Users\susan\Documents` as the RAR file, only one record \[`Genotyping_Results_B57_Positive.pdf`] was created around the same time as the archive file. This is most likely to be the decoy document that the victim intended to extract.
    * The creation time was cross-referenced against the USN Journal `$J` to find other hidden `FileCreate` events across the entire volume, identifying the hidden payload \[`ApbxHelper.exe`] and the persistence mechanism \[`Display Settings.lnk`].
    * \[`ApbxHelper.exe`] was confirmed to be added to path `C:\Users\susan\AppData\Local`.

### Event 3: Persistence

  * **Timestamp (UTC):** \[2025-09-02 08:14:18]
  * **Source File / Artifact:** \[`$MFT`]
  * **Event Description:** A shortcut was added to the Startup Programs.
  * **Analysis:** **Persistence** was achieved by adding \[`Display Settings.lnk`] to the Startup folder `C:\Users\susan\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`, ensuring \[`ApbxHelper.exe`] is executed on future system logins. The creation of a shortcut linking to a tool marks this as \[`T1547.009`]

-----

## III. Detailed Artifact Analysis

### A. Malicious RAR File

  * **Artifact:** \[`Pathology-Department-Research-Records.rar`]
  * **Source File:** \[`$MFT`,`$J`]
  * **Relevant Snippet:**\
    \[`$MFT`]
    ```
    Parent Path	File Name	Extension	Created0x10	Created0x30	Last Modified0x10	Last Modified0x30	Last Record Change0x10	Last Record Change0x30	Last Access0x10	Last Access0x30
    .\Users\susan\AppData\Local\Temp\vmware-susan\VMwareDnD\9775f068	Pathology-Department-Research-Records.rar	.rar	2025-09-02 08:13:41	2025-09-02 08:13:50	2025-09-02 14:54:54	2025-09-02 08:13:50	2025-09-02 14:54:54	2025-09-02 08:13:50	2025-09-02 08:13:50	2025-09-02 08:13:50
    .\Users\susan\Documents	Pathology-Department-Research-Records.rar	.rar	2025-09-02 08:13:50		2025-09-02 14:54:54	2025-09-02 08:13:50	2025-09-02 08:14:04	2025-09-02 08:13:50	2025-09-02 08:14:18	2025-09-02 08:13:50
    ```

    \[`$J`]
    ```
    Update Timestamp	Name	Extension	Update Reasons
    2025-09-02 08:13:50	Pathology-Department-Research-Records.rar	.rar	FileCreate
    2025-09-02 08:13:50	Pathology-Department-Research-Records.rar	.rar	FileCreate
    ```

  * **Analysis:** The initial malicious archive used for ingress and user execution.
    * **Full Path:** \[`C:\Users\susan\Documents\Pathology-Department-Research-Records.rar`]
    * **Size:** \[`8,746,363 bytes`]
    * **Disk Coordinates:** The file is not fragmented. The entirety of the file's data is located in a single data run of \[`0x858`] clusters, beginning at \[`0x2ED3DC`].
    * **Timestamp Corroboration:** The **$J FileCreate** event at \[`2025-09-02 08:13:50`] confirms the time the file was written to the disk, marking the completion of the **Initial Access** download.

### B. The Decoy Document

  * **Artifact:** \[`Genotyping_Results_B57_Positive.pdf`]
  * **Source File:** \[`$MFT`,`$J`]
  * **Relevant Snippet:**\
    \[`$MFT`]
    ```
    Parent Path	File Name	Extension	Created0x10	Created0x30	Last Modified0x10	Last Modified0x30	Last Record Change0x10	Last Record Change0x30	Last Access0x10	Last Access0x30
    .\Users\susan\Documents	Genotyping_Results_B57_Positive.pdf	.pdf	2025-09-02 08:14:18		2025-09-02 08:14:18		2025-09-02 08:15:05	2025-09-02 08:14:18	2025-09-02 08:15:05	2025-09-02 08:14:18
    ```

    \[`$J`]
    ```
    Update Timestamp	Name	Extension	Update Reasons
    2025-09-02 08:14:18	Genotyping_Results_B57_Positive.pdf	.pdf	FileCreate
    ```

  * **Analysis:** The decoy document to prompt user file extraction. The document was opened on \[`2025-09-02 08:15:05`].
    * **Full Path:** \[`C:\Users\susan\Documents\Genotyping_Results_B57_Positive.pdf`]
    * **Size:** \[`91,441 bytes`]
    * **Disk Coordinates:** The file is not fragmented. The entirety of the file's data is located in a single data run of \[`0x17`] clusters, beginning at \[`0x3A8A96`].
    * **Timestamp Corroboration:** The **$MFT Created0x10** and **$J FileCreate** event at \[`2025-09-02 08:14:18`] confirms the time the file was written to the disk.

### C. The Payload

  * **Artifact:** \[`ApbxHelper.exe`]
  * **Source File:** \[`$MFT`,`$J`]
  * **Relevant Snippet:**\
    \[`$MFT`]
    ```
    Parent Path	File Name	Extension	Created0x10	Created0x30	Last Modified0x10	Last Modified0x30	Last Record Change0x10	Last Record Change0x30	Last Access0x10	Last Access0x30
    .\Users\susan\AppData\Local	ApbxHelper.exe	.exe	2025-09-02 08:14:18		2025-09-02 08:14:18	2025-09-02 08:14:18	2025-09-02 08:14:28	2025-09-02 08:14:18	2025-09-02 08:14:18	2025-09-02 08:14:18
    ```

    \[`$J`]
    ```
    Update Timestamp	Name	Extension	Update Reasons
    2025-09-02 08:14:18	ApbxHelper.exe	.exe	FileCreate
    ```

  * **Analysis:** The payload to be executed at every login.
    * **Full Path:** \[`C:\Users\susan\AppData\Local\ApbxHelper.exe`]
    * **Size:** \[`1,728,496 bytes`]
    * **Disk Coordinates:** The file is not fragmented. The entirety of the file's data is located in a single data run of \[`0x1A6`] clusters, beginning at \[`0x3DA011`].
    * **Timestamp Corroboration:** The **$MFT Created0x10** and **$J FileCreate** event at \[`2025-09-02 08:14:18`] confirms the time the file was written to the disk.

### D. The Persistence Mechanism

  * **Artifact:** \[`Display Settings.lnk`]
  * **Source File:** \[`$MFT`,`$J`]
  * **Relevant Snippet:**\
    \[`$MFT`]
    ```
    Parent Path	File Name	Extension	Created0x10	Created0x30	Last Modified0x10	Last Modified0x30	Last Record Change0x10	Last Record Change0x30	Last Access0x10	Last Access0x30
    .\Users\susan\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup	Display Settings.lnk	.lnk	2025-09-02 08:14:18		2025-09-02 08:14:18		2025-09-02 08:14:18		2025-09-02 08:32:10	2025-09-02 08:14:18
    ```

    \[`$J`]
    ```
    Update Timestamp	Name	Extension	Update Reasons
    2025-09-02 08:14:18	Display Settings.lnk	.lnk	FileCreate
    ```

  * **Analysis:** The shortcut placed in the Startup Folder to run the payload.
    * **Full Path:** \[`C:\Users\susan\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Display Settings.lnk`]
    * **Size:** \[`2,018 bytes`]
    * **Disk Coordinates:** The file is not fragmented. The entirety of the file's data is located in a single data run of \[`0x1`] clusters, beginning at \[`0x70C13`].
    * **Timestamp Corroboration:** The **$MFT Created0x10** and **$J FileCreate** event at \[`2025-09-02 08:14:18`] confirms the time the file was written to the disk.

-----

## IV. Answers to Challenge Questions

  * **Question 1: What is the CVE assigned to the WinRAR vulnerability exploited by the RomCom threat group in 2025?**

      * **Answer:** `CVE-2025-8088`
      * **Reference:** Web Search.

  * **Question 2: What is the nature of this vulnerability?**

      * **Answer:** `Path Traversal`
      * **Reference:** https://www.cve.org/CVERecord?id=CVE-2025-8088

  * **Question 3: What is the name of the archive file under Susan's documents folder that exploits the vulnerability upon opening the archive file?**

      * **Answer:** `Pathology-Department-Research-Records.rar`
      * **Reference:** See Event 1 and Section III.A.

  * **Question 4: When was the archive file created on the disk?**

      * **Answer:** `2025-09-02 08:13:50`
      * **Reference:** See Event 1 and Section III.A.

  * **Question 5: When was the archive file opened?**

      * **Answer:** `2025-09-02 08:14:04`
      * **Reference:** See Event 1 and Section III.A.

  * **Question 6: What is the name of the decoy document extracted from the archive file, meant to appear legitimate and distract the user?**

      * **Answer:** `Genotyping_Results_B57_Positive.pdf`
      * **Reference:** See Event 2 and Section III.B.

  * **Question 7: What is the name and path of the actual backdoor executable dropped by the archive file?**

      * **Answer:** `C:\Users\Susan\Appdata\Local\ApbxHelper.exe`
      * **Reference:** See Event 2 and Section III.C.

  * **Question 8: The exploit also drops a file to facilitate the persistence and execution of the backdoor. What is the path and name of this file?**

      * **Answer:** `C:\Users\Susan\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Display Settings.lnk`
      * **Reference:** See Event 3 and Section III.D.

  * **Question 9: What is the associated MITRE Technique ID discussed in the previous question?**

      * **Answer:** `T1547.009`
      * **Reference:** See Event 3.

  * **Question 10: When was the decoy document opened by the end user, thinking it to be a legitimate document?**

      * **Answer:** `2025-09-02 08:15:05`
      * **Reference:** See Section III.B.