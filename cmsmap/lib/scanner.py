#! /usr/bin/env python3
import sys
# Import Objects
from urllib.parse import urlparse

from .bruteforcer import BruteForcer
from .druscan import DruScan
from .genericchecks import GenericChecks
from .initialize import initializer
from .jooscan import JooScan
from .mooscan import MooScan
from .report import Report
from .requester import Requester
from .wpscan import WPScan


class Scanner:
    # Main class for scanning the website
    def __init__(self, is_random_user_agent: bool = False, is_color: bool = False):
        self.headers = initializer.headers
        self.url = None
        self.force = None
        self.file = None
        self.notExistingCode = 404
        self.notValidLen = []
        self.report = Report(color=is_color)
        self.requester = Requester(is_random_user_agent=is_random_user_agent)
        self.bruter = BruteForcer(is_random_user_agent=is_random_user_agent, is_color=is_color)
        self.genericchecker = GenericChecks(is_random_user_agent=is_random_user_agent, is_color=is_color)
        self.wpscan = WPScan(is_random_user_agent=is_random_user_agent, is_color=is_color)
        self.jooscan = JooScan(is_random_user_agent=is_random_user_agent, is_color=is_color)
        self.druscan = DruScan(is_random_user_agent=is_random_user_agent, is_color=is_color)
        self.mooscan = MooScan(is_random_user_agent=is_random_user_agent, is_color=is_color)

    # Execute some initial checks and then attempt to identify the type of CMS
    def RunScanner(self):
        self.wpscan.url = self.jooscan.url = self.druscan.url = self.mooscan.url = initializer.url
        self.genericchecker.CheckURL()
        self.genericchecker.NotExistingURL()
        self.wpscan.notExistingCode = self.jooscan.notExistingCode = self.druscan.notExistingCode = self.genericchecker.notExistingCode
        self.wpscan.notValidLen = self.jooscan.notValidLen = self.druscan.notValidLen = self.genericchecker.notValidLen
        self.genericchecker.HTTPSCheck()
        self.genericchecker.HeadersCheck()
        self.genericchecker.RobotsTXT()
        if self.force is None:
            self.FindCMSType()
        else:
            self.ForceCMSType()

    # Force the execution of the scan based on the user's input
    def ForceCMSType(self):
        if self.force == 'W':
            if initializer.BruteForcingAttack:
                self.bruter.force = 'W'
                self.bruter.Start()
            else:
                self.wpscan.WPrun()
        elif self.force == 'J':
            if initializer.BruteForcingAttack:
                self.bruter.force = 'J'
                self.bruter.Start()
            else:
                self.jooscan.Joorun()
        elif self.force == 'D':
            if initializer.BruteForcingAttack:
                self.bruter.force = 'D'
                self.bruter.Start()
            else:
                self.druscan.Drurun()
        elif self.force == 'M':
            self.mooscan.Moorun()
        else:
            msg = "Not Valid Option Provided: use (W)ordpress, (J)oomla, (D)rupal"
            self.report.error(msg)
            sys.exit(1)

    # Attempt to identify the type of CMS based on the configuration file
    def FindCMSType(self):
        msg = "Detecting type of CMS ..."
        self.report.verbose(msg)
        if self.force is None:
            self.requester.request(self.url + "/wp-config.php", data=None)
            if (self.requester.status_code == 403 or self.requester.status_code == 200) and len(self.requester.htmltext) not in self.notValidLen and self.force is None:
                self.force = 'W'
            else:
                msg = "WordPress Config File Not Found: " + self.url + "/wp-config.php"
                self.report.verbose(msg)
            # Joomla
            self.requester.request(self.url + "/configuration.php", data=None)
            if (self.requester.status_code == 403 or self.requester.status_code == 200) and len(self.requester.htmltext) not in self.notValidLen and self.force is None:
                self.force = 'J'
            else:
                msg = "Joomla Config File Not Found: " + self.url + "/configuration.php"
                self.report.verbose(msg)
            # Drupal
            self.requester.request(self.url + "/sites/default/settings.php", data=None)
            if (self.requester.status_code == 403 or self.requester.status_code == 200) and len(self.requester.htmltext) not in self.notValidLen and self.force is None:
                self.force = 'D'
            pUrl = urlparse(self.url)
            netloc = pUrl.netloc.lower()
            self.requester.request(self.url + "/sites/" + netloc + "/settings.php", data=None)
            if (self.requester.status_code == 403 or self.requester.status_code == 200) and len(self.requester.htmltext) not in self.notValidLen and self.force is None:
                self.force = 'D'
            else:
                msg = "Drupal Config File Not Found: " + self.url + "/sites/default/settings.php"
                self.report.verbose(msg)
            # Moodle
            self.requester.request(self.url + "/config.php", data=None)
            if (self.requester.status_code == 403 or self.requester.status_code == 200) and len(self.requester.htmltext) not in self.notValidLen and self.force is None:
                self.force = 'M'
            else:
                msg = "Moodle Config File Not Found: " + self.url + "/config.php"
                self.report.verbose(msg)
            # CMS Detection has failed
            if self.force is None:
                msg = "CMS detection failed :("
                self.report.error(msg)
                msg = "We can not detect CMS on your target or your target maybe use WAF (Web Application Firewall)"
                self.report.error(msg)
                # msg = "Try to rescan using custom options to force the scanner to scan chosen CMS"
                # self.report.error(msg)
                # msg = "Use -f to force CMSmap to scan (W)ordpress, (J)oomla or (D)rupal"
                # self.report.error(msg)
                sys.exit(0)
            else:
                self.ForceCMSType()
        else:
            msg = "CMSmap forced to scan: " + self.force
            self.report.verbose(msg)


scanner = Scanner()
