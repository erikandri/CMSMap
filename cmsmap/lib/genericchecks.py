#! /usr/bin/env python3
import queue
import re
import sys
import time
# Import Object
from urllib.parse import urlparse

from .initialize import initializer
from .report import Report
from .requester import Requester
# Import Class
from .threadscanner import ThreadScanner


# Perform web application generic checks
class GenericChecks:

    def __init__(self, is_random_user_agent: bool = False, is_color: bool = False):
        self.interFiles = None
        self.NotExistingPage = None
        self.relPath = None
        self.url = None
        self.headers = initializer.headers
        self.notExistingCode = 404
        self.thread_num = 5
        self.commExt = ['.txt', '.php', '/', '.html']
        self.notValidLen = []
        self.commFiles = [line.strip() for line in open(initializer.commFiles, encoding='utf-8')]
        self.requester = Requester(is_random_user_agent=is_random_user_agent)
        self.report = Report(color=is_color)

    # Validate the URL provided
    def CheckURL(self):
        pUrl = urlparse(self.url)
        initializer.netloc = pUrl.netloc.lower()
        initializer.scheme = pUrl.scheme.lower()
        path = pUrl.path.lower()
        if not initializer.scheme:
            self.url = "http://" + self.url
            self.report.status("No HTTP/HTTPS provided. Assuming HTTP...")
        if path.endswith("asp" or "aspx"):
            self.report.error("You are not scanning a PHP website")
            sys.exit(1)
        if path.endswith("txt" or "php"):
            self.url = re.findall(
                re.compile('(.+?)/[A-Za-z0-9]+\.txt|php'), self.url)[0]

    # Check if directory is listing
    def DirectoryListing(self, relPath):
        self.relPath = relPath
        msg = "Checking directory listing: " + self.relPath
        self.report.verbose(msg)
        self.requester.request(self.url + self.relPath, data=None)
        dirList = re.search("<title>Index of", self.requester.htmltext, re.IGNORECASE)
        if dirList:
            msg = self.url + self.relPath
            self.report.low(msg)

    # Check if website is over HTTPS
    def HTTPSCheck(self):
        msg = "Checking if the website is in HTTPS ..."
        self.report.verbose(msg)
        pUrl = urlparse(self.url)
        scheme = pUrl.scheme.lower()
        if scheme == 'http':
            # check HTTPS redirection
            self.requester.noredirect(self.url, data=None)
            if self.requester.status_code == 200:
                msg = "Website Not in HTTPS: " + self.url
                self.report.medium(msg)
            else:
                redirected = re.search("https", str(self.requester.htmltext), re.IGNORECASE)
                if self.requester.status_code != 302 and not redirected:
                    msg = "Website Not in HTTPS: " + self.url
                    self.report.medium(msg)

    # Check Security Headers
    def HeadersCheck(self):
        self.requester.request(self.url, data=None)
        msg = "Checking headers ..."
        self.report.verbose(msg)
        if self.requester.response.headers.get('Server'):
            msg = "Server: " + self.requester.response.headers.get('Server')
            self.report.info(msg)
        if self.requester.response.headers.get('X-Powered-By'):
            msg = "X-Powered-By: " + self.requester.response.headers.get('X-Powered-By')
            self.report.info(msg)
        if self.requester.response.headers.get('X-Generator'):
            msg = "X-Generator: " + self.requester.response.headers.get('X-Generator')
            self.report.low(msg)
        if self.requester.response.headers.get('x-xss-protection') == '0':
            msg = "X-XSS-Protection Disabled"
            self.report.high(msg)
        if not self.requester.response.headers.get('x-frame-options') or (
                self.requester.response.headers.get('x-frame-options').lower() != 'sameorigin' or 'deny'):
            msg = "X-Frame-Options: Not Enforced"
            self.report.low(msg)
        if not self.requester.response.headers.get('strict-transport-security'):
            msg = "Strict-Transport-Security: Not Enforced"
            self.report.info(msg)
        if not self.requester.response.headers.get('x-content-security-policy'):
            msg = "X-Content-Security-Policy: Not Enforced"
            self.report.info(msg)
        if not self.requester.response.headers.get('x-content-type-options'):
            msg = "X-Content-Type-Options: Not Enforced"
            self.report.info(msg)

    # Check if AutoComplete is set to Off on login pages
    def AutocompleteOff(self, relPath):
        msg = "Checking Autocomplete Off on the login page ..."
        self.report.verbose(msg)
        self.relPath = relPath
        self.requester.request(self.url + self.relPath, data=None)
        autoComp = re.search("autocomplete=\"off\"", self.requester.htmltext, re.IGNORECASE)
        if not autoComp:
            msg = "Autocomplete Off Not Found: " + self.url + self.relPath
            self.report.info(msg)

    # Check if robots.txt is available
    def RobotsTXT(self):
        msg = "Checking Robots.txt File ..."
        self.report.verbose(msg)
        self.requester.request(self.url + "/robots.txt", data=None)
        if self.requester.status_code == 200 and len(self.requester.htmltext) not in self.notValidLen:
            msg = "Robots.txt Found: " + self.url + "/robots.txt"
            self.report.low(msg)
        else:
            msg = "No Robots.txt Found"
            self.report.low(msg)

    # Extract error codes and page length from a not existing web page
    def NotExistingURL(self):
        msg = "Requesting Not Existing Pages ..."
        self.report.verbose(msg)
        self.NotExistingPage = self.url + "/N0WayThatYouAreHere" + time.strftime('%d%m%H%M%S')
        for commExt in self.commExt:
            self.requester.request(self.NotExistingPage + commExt, data=None)
            self.notValidLen.append(len(self.requester.htmltext))
            self.notExistingCode = self.requester.status_code
        self.notValidLen = sorted(set(self.notValidLen))

    # Find interesting directories or files via  dictionary attack
    def CommonFiles(self):
        msg = "Checking interesting directories/files ... "
        self.report.message(msg)
        self.interFiles = []
        # Create Code
        q = queue.Queue()
        # Spawn all threads into code
        for u in range(self.thread_num):
            t = ThreadScanner(self.url, "/", "", self.interFiles, self.notExistingCode, self.notValidLen, q)
            t.daemon = True
            t.start()

        for extIndex, ext in enumerate(self.commExt):
            # Add all plugins to the queue
            for commFilesIndex, file in enumerate(self.commFiles):
                q.put(file + ext)
            q.join()

        for file in self.interFiles:
            msg = self.url + "/" + file
            self.report.low(msg)
