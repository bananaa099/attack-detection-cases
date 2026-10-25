# Case 02 - New Admin Account

I wanted to see what it looks like in the logs when someone creates a new user and makes them an admin. This is a common sign of an attacker trying to stay in the system.

## What I did

In my Windows VM I ran:

```powershell
net user testadmin P@ssw0rd123 /add
net localgroup administrators testadmin /add
```

First command creates a user, second one adds it to the Administrators group.

## What I found in Splunk

Two Windows Security events showed up:

- **4720** - a new user account was created (testadmin)
- **4732** - the account was added to the Administrators group

Search I used:

```spl
index=* (EventCode=4720 OR EventCode=4732) | table _time, host, EventCode, Account_Name
```

The two events happened a few seconds apart, so you can see the whole thing: user created, then made admin.

## Why it matters

Attackers create their own admin account so they can get back in later. One new user is normal, but a new user that becomes an admin right away is worth a closer look. On a real alert I would check who ran it and if it was planned by IT.

MITRE: T1136 (Create Account), T1098 (Account Manipulation)

## Cleanup

```powershell
net user testadmin /delete
```

## Screenshots

- `images/01-splunk-alerts.png` - the events in a table
- `images/02-attack-commands.png` - the commands I ran
