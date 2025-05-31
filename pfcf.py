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
