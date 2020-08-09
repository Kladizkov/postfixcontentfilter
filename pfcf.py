import smtpd
import asyncore
import datetime
import smtplib
import logging
import traceback
import syslog
import systemd.daemon
import configparser

class CustomSMTPServer(smtpd.SMTPServer):

	def process_message(self, peer, mailfrom, rcpttos, data):
		
		mailfrom.replace('\'', '')
		mailfrom.replace('\"', '')
		
		for recipient in rcpttos:
			recipient.replace('\'', '')
			recipient.replace('\"', '')
		
		logging.info('Content Filter Started')

		logging.info('Message addressed from: %s', mailfrom)
		logging.info('Message addressed to : %s', ', '.join(rcpttos))

		try:

			x = datetime.datetime.now()
			bounceMailContent = """From: Mailer <""" + bounceSender + """>
To: """ + mailfrom + """
MIME-Version: 1.0
Content-type: text/html
Subject: Email Rejected
Date: """ + x.strftime("%a, %-d %b %Y %H:%M:%S +0530") + """

Your mail could not be send to one or more of its recipient as it violates """ + companyName + """ email policies.

"""

			bounceMailContentForAdmin = """From: Mailer <""" + bounceSender + """>
To: """ + adminEmail + """
MIME-Version: 1.0
Content-type: text/html
Subject: Email Rejected - Policy Violation
Date: """ + x.strftime("%a, %-d %b %Y %H:%M:%S +0530") + """

EMail from """ + mailfrom + """ could not be send to one or more of its recipient as it violates """ + companyName + """ email policies. Check log for more details.

"""

			mailToFilter = 0
			mailRejected = 0
			rcpttos_filtered = []

			if primarySenderDomainToFilter in mailfrom:
				if mailfrom in addressesAllowedForOutbound:
					mailToFilter = 0
					syslog.syslog('pfcf: Exempted sender found in from address. Skipping filter.')
					logging.info("Exempted sender found in from address. Skipping filter.")
				else:
					mailToFilter = 1
					syslog.syslog('pfcf: Unprivileged sender found in from address. Starting filter.')
					logging.info("Unprivileged sender found in from address. Starting filter.")
					for rcptTo in rcpttos:
						for allowedOutboundDomain in allowedOutboundDomains:
							if allowedOutboundDomain in rcptTo:
								rcpttos_filtered.append(rcptTo)

					if ((len(rcpttos) != len(rcpttos_filtered))):
						mailRejected = 1
						syslog.syslog('pfcf: All or some of the recipient rejected.')	
						logging.info('=== REJECTED MESSAGE START ===')
						logging.info(data)
						logging.info('=== REJECTED MESSAGE END ===')
						logging.info("All or some of the recipient rejected.")
			else:
				mailToFilter = 0
				syslog.syslog('pfcf: No primary sender domain found in from address. Skipping filter.')
				logging.info("No primary sender domain found in from address. Skipping filter.")

		except:
			pass
			syslog.syslog('pfcf: Critical Exception')
			logging.error('Critical Exception')
			logging.error(traceback.format_exc())

		try:
			if (mailToFilter == 1):
				if(rcpttos_filtered):
					server = smtplib.SMTP('localhost', 10026)
					server.sendmail(mailfrom, rcpttos_filtered, data)
					server.quit()
					logging.info('Send successful')
			else:
				server = smtplib.SMTP('localhost', 10026)
				server.sendmail(mailfrom, rcpttos, data)
				server.quit()
				logging.info('Send successful')
			
			if mailRejected == 1:
				server = smtplib.SMTP('localhost', 10026)
				server.sendmail(bounceSender, mailfrom, bounceMailContent)
				server.quit()
				server = smtplib.SMTP('localhost', 10026)
				server.sendmail(bounceSender, adminEmail, bounceMailContentForAdmin)
				server.quit()
				logging.info('One or more message rejected')
            
		except smtplib.SMTPException:
			syslog.syslog('pfcf: Exception SMTPException')
			logging.error('Exception SMTPException')
			logging.error(traceback.format_exc())
			pass
		except smtplib.SMTPServerDisconnected:
			syslog.syslog('pfcf: Exception SMTPServerDisconnected')
			logging.error('Exception SMTPServerDisconnected')
			pass
		except smtplib.SMTPResponseException:
			syslog.syslog('pfcf: Exception SMTPResponseException')
			logging.error('Exception SMTPResponseException')
			pass		
		except smtplib.SMTPSenderRefused:
			syslog.syslog('pfcf: Exception SMTPSenderRefused')
			logging.error('Exception SMTPSenderRefused')
			pass		
		except smtplib.SMTPRecipientsRefused:
			syslog.syslog('pfcf: Exception SMTPRecipientsRefused')
			logging.error('Exception SMTPRecipientsRefused')
			pass		
		except smtplib.SMTPDataError:
			syslog.syslog('pfcf: Exception SMTPDataError')
			logging.error('Exception SMTPDataError')
			pass		
		except smtplib.SMTPConnectError:
			syslog.syslog('pfcf: Exception SMTPConnectError')
			logging.error('Exception SMTPConnectError')
			pass		
		except smtplib.SMTPHeloError:
			syslog.syslog('pfcf: Exception SMTPHeloError')
			logging.error('Exception SMTPHeloError')
			pass		
		except smtplib.SMTPAuthenticationError:
			syslog.syslog('pfcf: SMTPAuthenticationError')
			logging.error('Exception SMTPAuthenticationError')
			pass
		except:
			syslog.syslog('pfcf: Undefined exception')
			logging.error('Undefined exception')
			logging.error(traceback.format_exc())

		return
		
systemd.daemon.notify('READY=1')
syslog.syslog('pfcf: Started')
syslog.syslog('pfcf: Reading configuration settings')

config = configparser.ConfigParser()
config.read('/etc/pfcf.ini')
companyName = config.get('default', 'CompanyName')
adminEmail = config.get('default', 'AdminEmail')
primarySenderDomainToFilter = config.get('default', 'PrimarySenderDomainToFilter')
aafo = config.get('default', 'AddressesAllowedForOutbound')
aod = config.get('default', 'AllowedOutboundDomains')
addressesAllowedForOutbound = aafo.split(',')
allowedOutboundDomains = aod.split(',')
bounceSender = config.get('default', 'BounceSender')
logFile = config.get('default', 'LogFile')

logging.basicConfig(level=logging.INFO, filename=logFile, filemode='a', format='%(asctime)s :: %(levelname)s :: %(message)s')

server = CustomSMTPServer(('127.0.0.1', 10025), None)

asyncore.loop()
