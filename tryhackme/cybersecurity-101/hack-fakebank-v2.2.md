# 🏴 CTF / TryHackMe Write-up – [TryHackMe/Hack Fakebank v2.2]

## 🔎 Challenge Info

* **Platform:** TryHackMe
* **Category:** Misc
* **Difficulty:** Easy
* **Date Completed:** 2025-09-13

---

## 🎯 Objective

*Transfer $2000 from bank account 2276 to account number 8881.*

---

## 🧠 Thought Process

This was a tutorial stage. There were already instructions given to aid in hacking the bank. But, before proceeding with the task, I first wanted to take a look at the bank page `http://fakebank.thm/` and see what the contents were like. The page was extremely short and contained only a few items: the basic account details, balance, and a short transaction history.

Since the site is only `http`, it means I could potentially read the requests and responses that were being sent. However, there wasn't much the basic website could do. All links I clicked simply led back to the main account page.

Using the website's debugger, I looked for hidden scripts and found `script.js` which seemed to contain the task completion script and the flag. Though I already found the answer, in the spirit of the game, I continued with the completion of the task of transferring the money.

TryHackMe already provided a list of words that I could use to help find pages that exist in the site. Using this list, I ran the following command:

```bash
gobuster -u http://fakebank.thm -w wordlist.txt dir
```

The results were two directories:
* `/images` which returned with a code of `301`
* `/bank-transfer` which could be opened

After adding `/bank-transfer` onto the end of the link, I was brought to a page that had a form for transferring money. Using this form, according to the task, I found the flag in another way.

---

## 🛠️ Steps Taken

1. **Recon / Info Gathering**

   * Tool(s) used: `gobuster`
   * Findings: discovered hidden `/bank-transfer` directory

2. **Exploitation / Analysis**

   * Method: Insecure Direct Object Reference, Source Code Disclosure
   * Tool(s): Firefox

3. **Privilege Escalation / Decryption / Forensics Steps**

   * Added the hidden directory name directly onto the url
   * Modified the form in the admin page to send money to account 8881

4. **Flag / Final Result**

   * `BANK-HACKED`

---

## 📚 Key Learnings

* New tool learned: `gobuster`
* New concept:
    * directory brute forcing can uncover hidden admin pages
    * looking at hidden scripts can reveal important information (such as the flag)

---