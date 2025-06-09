# iCal Render Bender

Phishing with iCal events

TL;Dr

When Outlook renders inbound events, it uses the ORGANIZER field to render the traffic. There is no validation, and multiple rendering ~~bugs~~ features create some great opportunities for social engineering.

Initially presented at [Bsides DSM 2025](Bsides DSM 2025)

[Accompanying slide deck](https://docs.google.com/presentation/d/1PTmQjviLZidnOCVBLchBL7p7V1Lq_mtfDEBoilKDOFc/edit?usp=sharing)

## Requirements

- Your own SMTP mail server/credentials
- Targets in an O365/Exchange environment

## How to use

### Passing in SMTP server/credentials

To use my examples, copy example_vars.sh to vars.sh and populate with your own values, or simply set your own environment variables.

```shell
export SMTP_SERVER=<smtp_server>:<smtp_port>
export SMTP_USER=<smtp_user>
export SMTP_PASSWORD=<smtp_password>
```

You can also specify your smtp server and credentials using the script directly:

```shell
python3 renderbender.py --user <smtp_user> --pass <smtp_pass> --url <smtp_server> ...
```

### Basic usage

You'll need to install the pyptz module (apt, pipenv etc). Once installed, you can call the python script:

```shell
python3 ./renderbender.py -h
usage: renderbender.py [-h] [--body ] --from  [--meeting-begin ] [--meeting-end ] [--meeting-summary ] [--password ] [--priority ] --spoof-from-name
                       --spoof-from  --subject  --target-cn  --target  --tz  [--url ] [--user ]

Sends phishing emails with 'on behalf of' with calender invites

options:
  -h, --help          show this help message and exit
  --body              Body of the email
  --debug             Enable debug, print message prior to sending
  --dryrun            Disable sending of message
  --from              Actual from address
  --meeting-begin     Begin time for Teams meeting
  --meeting-end       End time for Teams meeting
  --meeting-summary   The summary (title) for the meeting
  --password          SMTP Password
  --priority          Priority of the event (1-5)
  --spoof-from-name   CN for "from" user
  --spoof-from        On behalf of email
  --subject           Email subject
  --target-cn         Target CN (rcpt)
  --target            Target email (rcpt)
  --tz                Timezone for meeting
  --url               SMTP server:port
  --user              SMTP Username
```

Check out the included `send-example*.sh` scripts for examples.

### Generating timestamps for meeting-begin/meeting-end

Linux

```shell
# 1 day from now
date --date="+1 day" +%Y%m%dT%H%M%S

# 8 hours from now
date --date="+8 hour" +%Y%m%dT%H%M%S
```

PowerShell:

```powershell
# 1 day from now
(Get-Date).AddDays(1).ToString("yyyyMMddTHHmmss")

# 8 hours from now
(Get-Date).AddHours(8).ToString("yyyyMMddTHHmmss")
```
