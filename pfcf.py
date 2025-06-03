import asyncio
from aiosmtpd.controller import Controller
from aiosmtpd.handlers import AsyncMessage
from email.message import EmailMessage
import smtplib
import logging
import traceback
import syslog
import systemd.daemon
import configparser
import datetime


class CustomSMTPHandler(AsyncMessage):
    def __init__(self, config):
        super().__init__()
        self.config = config
        self.load_config()

    def load_config(self):
        self.warnOnUnknownDomain = self.config.getboolean('default', 'WarnOnUnknownDomain', fallback=False)
        self.knownDomains = [d.strip().lower() for d in self.config.get('default', 'KnownSenderDomains', fallback='').split(',')]
        self.warningExemptRecipientDomains = [d.strip().lower() for d in self.config.get('default', 'WarningExemptRecipientDomains', fallback='').split(',')]
        self.warningExemptRecipientEmails = [e.strip().lower() for e in self.config.get('default', 'WarningExemptRecipientEmails', fallback='').split(',')]

        self.companyName = self.config.get('default', 'CompanyName')
        self.adminEmail = self.config.get('default', 'AdminEmail')
        self.primarySenderDomainToFilter = self.config.get('default', 'PrimarySenderDomainToFilter')
        self.addressesAllowedForOutbound = self.config.get('default', 'AddressesAllowedForOutbound').split(',')
        self.allowedOutboundDomains = self.config.get('default', 'AllowedOutboundDomains').split(',')
        self.bounceSender = self.config.get('default', 'BounceSender')
        logFile = self.config.get('default', 'LogFile')

        logging.basicConfig(
            level=logging.INFO,
            filename=logFile,
            filemode='a',
            format='%(asctime)s :: %(levelname)s :: %(message)s'
        )

    async def handle_message(self, message: EmailMessage):
        # --- LOOP RETRY LOGIC ---
        loop_count = int(message.get('X-PFCF-Loop-Count', '0'))

        if loop_count >= 2 or message.get('X-PFCF-Processed') == 'yes':
            syslog.syslog('pfcf: Message already fully processed or retried. Skipping.')
            logging.warning("Message marked as processed or exceeded loop retry. Skipping further actions.")
            return

        # Update loop count and headers
        loop_count += 1
        if message.get('X-PFCF-Loop-Count'):
            message.replace_header('X-PFCF-Loop-Count', str(loop_count))
        else:
            message.add_header('X-PFCF-Loop-Count', str(loop_count))

        if loop_count == 2:
            message.add_header('X-PFCF-Processed', 'yes')
            
        mailfrom = message['X-MailFrom'].replace("'", "").replace('"', '')
        xrcpttos = []
        xrcpttos.extend(message.get_all('X-RcptTo', []))
        xrcpttos = [addr.strip() for part in xrcpttos for addr in part.split(';')]
        xrcpttos = [addr.strip() for part in xrcpttos for addr in part.split(',')]
        # Remove duplicates from xrcpttos while preserving order
        seen = set()
        xrcpttos = [x for x in xrcpttos if not (x in seen or seen.add(x))]
        
        logging.info("Content Filter Started")
        logging.info("Message addressed from: %s", mailfrom)
        logging.info("Message addressed to (X-RcptTo): %s", ', '.join(xrcpttos)) if xrcpttos else logging.info("No X-RcptTo recipients")

                # --- UNKNOWN DOMAIN WARNING ---
        sender_domain = mailfrom.split('@')[-1].lower() if '@' in mailfrom else ''

        def is_recipient_exempt():
            for rcpt in xrcpttos:
                rcpt = rcpt.lower()
                rcpt_domain = rcpt.split('@')[-1]
                if rcpt in self.warningExemptRecipientEmails:
                    return True
                if rcpt_domain in self.warningExemptRecipientDomains:
                    return True
            return False

        if self.warnOnUnknownDomain and sender_domain not in self.knownDomains and not is_recipient_exempt():
            if message.is_multipart():
                for part in message.walk():
                    if part.get_content_type() == 'text/html':
                        html = part.get_payload(decode=True).decode(errors='replace')
                        warning_html = "<div style='color:red; font-weight:bold;'>CAUTION: This email is from an unknown source. Please exercise caution with attachments and links.</div><br/>" + html
                        part.set_payload(warning_html)
                        part.set_type('text/html')
                        logging.info("Warning text added")
            else:
                if message.get_content_type() == 'text/html':
                    html = message.get_payload(decode=True).decode(errors='replace')
                    warning_html = "<div style='color:red; font-weight:bold;'>CAUTION: This email is from an unknown source. Please exercise caution with attachments and links.</div><br/>" + html
                    message.set_payload(warning_html)
                    message.set_type('text/html')
                    logging.info("Warning text added")

        mailToFilter = 0
        mailRejected = 0
        xrcpttos_filtered = []

        try:
            if self.primarySenderDomainToFilter in mailfrom:
                if mailfrom in self.addressesAllowedForOutbound:
                    mailToFilter = 0
                    syslog.syslog('pfcf: Exempted sender found. Skipping filter.')
                    logging.info("Exempted sender found. Skipping filter.")
                else:
                    mailToFilter = 1
                    syslog.syslog('pfcf: Unprivileged sender. Filtering.')
                    logging.info("Unprivileged sender. Filtering.")
                    for rcptTo in xrcpttos:
                        if any(domain in rcptTo for domain in self.allowedOutboundDomains):
                            if rcptTo not in xrcpttos_filtered:
                                xrcpttos_filtered.append(rcptTo)
                    if len(xrcpttos) != len(xrcpttos_filtered):
                        mailRejected = 1
                        syslog.syslog('pfcf: All or some recipient rejected.')
                        logging.info("=== REJECTED MESSAGE START ===\n%s\n=== REJECTED MESSAGE END ===", message)
            else:
                mailToFilter = 0
                syslog.syslog('pfcf: No primary sender domain. Skipping filter.')
                logging.info("No primary sender domain. Skipping filter.")
        except Exception:
            syslog.syslog('pfcf: Critical Exception')
            logging.error('Critical Exception')
            logging.error(traceback.format_exc())

        try:
            send_to = xrcpttos_filtered if (mailToFilter == 1 and xrcpttos_filtered) else xrcpttos
            logging.info("Allowed recipients: %s", ', '.join(send_to))
            if send_to:
               with smtplib.SMTP('localhost', 10026) as server:
                server.send_message(message, from_addr=mailfrom, to_addrs=send_to)
                logging.info("Send successful")

            if mailRejected:
                x = datetime.datetime.now().strftime("%a, %d %b %Y %H:%M:%S +0530")
                bounce_msg = f"""\
From: Mailer <{self.bounceSender}>
To: {mailfrom}
MIME-Version: 1.0
Content-type: text/html
Subject: Email Rejected
Date: {x}

Your mail could not be sent to one or more recipients as it violates {self.companyName} email policies.
"""
                bounce_admin_msg = f"""\
From: Mailer <{self.bounceSender}>
To: {self.adminEmail}
MIME-Version: 1.0
Content-type: text/html
Subject: Email Rejected - Policy Violation
Date: {x}

Email from {mailfrom} could not be sent to one or more recipients as it violates {self.companyName} email policies. Check logs for more details.
"""
                for recipient, content in [(mailfrom, bounce_msg), (self.adminEmail, bounce_admin_msg)]:
                    with smtplib.SMTP('localhost', 10026) as server:
                        server.sendmail(self.bounceSender, recipient, content)
                logging.info("One or more messages rejected")

        except Exception as e:
            syslog.syslog(f'pfcf: SMTP send exception - {str(e)}')
            logging.error("SMTP send exception")
            logging.error(traceback.format_exc())


if __name__ == '__main__':
    systemd.daemon.notify('READY=1')
    syslog.syslog('pfcf: Started')
    syslog.syslog('pfcf: Reading configuration settings')

    config = configparser.ConfigParser()
    config.read('/etc/pfcf.ini')

    handler = CustomSMTPHandler(config)
    controller = Controller(handler, hostname='127.0.0.1', port=10025)
    controller.start()
    print("SMTP server running. Press Ctrl+C to stop.")
    try:
        asyncio.get_event_loop().run_forever()
    except KeyboardInterrupt:
        controller.stop()
        print("SMTP server stopped.")
