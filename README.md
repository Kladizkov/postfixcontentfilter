# postfixcontentfilter
Content filter script for postfix

## Some Background

An organization use Postfix for email server. This organization need to implement a custom email policy. The restriction are like (1) some "privileged" email users should be able to send mails to outside the origanization domain, (2) some "unprivileged" email users should not be allowed to send mails to outside the organization domain. If "unprivileged" email users send mails to outside the organization, it is discarded and they are notified about the incident. The system admin is also notified about the incident and server log the complete email message for security audit purpose.

### Postfix Content Filter

Postfix has a feature for Advanced Content Filter. A custom script listens at localhost:10026, receives email from postfix, filter the content and inject it back into postfix listening at localhost:10025. If the script doesn't inject it back into postfix, the message gets discarded.

### Files

pfcf ( stands for postfix content filter ) has three files - pfcf.ini, pfcf.py and pfcf.service.

pfcf.ini - The config file.   
pfcf.py - The python script that does the content filter   
pfcf.service - The systemd service file for easy start, restart and stop job.   
