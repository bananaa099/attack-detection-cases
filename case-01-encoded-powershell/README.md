# Case 01: Encoded PowerShell

I wanted to see if a PowerShell command hidden in Base64 would show up in Splunk. Short version: it did.

## What I did
Wrote a harmless command, encoded it, and ran it with `-enc` in my Windows VM:

```powershell
$cmd = 'Invoke-WebRequest -Uri "http://example.com" -UseBasicParsing | Out-Null'
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
powershell -NoProfile -enc $enc
```

The command only requests example.com. Nothing is downloaded or executed.

## What I found in Splunk
Sysmon logged it as EventID 1 (process creation):

- Process: `powershell.exe`
- Command line: `-NoProfile -enc <Base64>`
- Parent: another `powershell.exe`
- User: `DESKTOP-064M1HL\admin`
- Time: 21/10/2026 21:29:09 UTC

The search I used:
```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 "powershell" "-enc"
```

## Why it matters
Attackers use `-enc` because the real command is hidden from a quick look at the logs. Admin scripts rarely need `-NoProfile` together with `-enc`, so the combination is worth an alert.

## Alert
I saved the search as a real-time alert called "Encoded PowerShell execution" (trigger: results > 0, action: Add to Triggered Alerts).

## False positives
Some installers and admin scripts use `-enc`. Before closing an alert, I would check the decoded command and the parent process.

## Screenshots
- `01-attack-command.png`: the command I ran
- `02-splunk-table.png`: the event in Splunk
- `03-splunk-encoded-powershell-detected.png`: the key fields in a table