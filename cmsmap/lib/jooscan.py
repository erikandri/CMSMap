#! /usr/bin/env python3
import queue
import re
import time

from .bruteforcer import BruteForcer
from .exploitdbsearch import searcher
from .genericchecks import GenericChecks
# Import Objects
from .initialize import initializer
from .report import Report
from .requester import Requester
# Import Class
from .threadscanner import ThreadScanner


class JooScan:
    # Scan Joomla site
    def __init__(self, is_random_user_agent: bool = False, is_color: bool = False):
        self.url = None
        self.usernames = []
        self.pluginPath = "?option="
        self.pluginsFound = []
        self.notValidLen = []
        self.notExistingCode = 404
        self.confFiles = [line.strip() for line in open(initializer.confFiles, encoding='utf-8')]
        self.excludeEDBPlugins = []
        self.excludeEDBPlugins = ['system', 'com_banners', 'com_contact', 'com_content', 'com_users']
        self.plugins = [line.strip() for line in open(initializer.joo_plugins, encoding='utf-8')]
        self.report = Report(color=is_color)
        self.requester = Requester(is_random_user_agent=is_random_user_agent)
        self.bruter = BruteForcer(is_random_user_agent=is_random_user_agent, is_color=is_color)
        self.genericchecker = GenericChecks(is_random_user_agent=is_random_user_agent, is_color=is_color)

    # Joomla checks
    def Joorun(self):
        msg = "CMS Detection: Joomla"
        self.report.info(msg)
        searcher.cmstype = "Joomla"
        searcher.pluginPath = self.pluginPath
        searcher.exclude = self.excludeEDBPlugins
        self.JooGetLocalFiles()
        self.JooVersion()
        self.JooTemplate()
        self.JooConfigFiles()
        self.JooFeed()
        self.bruter.usrlist = self.usernames
        self.bruter.pswlist = initializer.weakpsw
        if self.bruter.dictattack is not None:
            self.bruter.Joorun()
        self.genericchecker.AutocompleteOff('/administrator/index.php')
        self.JooDefaultFiles()
        if initializer.FullScan: self.genericchecker.CommonFiles()
        self.JooModulesIndex()
        self.JooComponents()
        if not initializer.FullScan: searcher.exclude = self.excludeEDBPlugins
        self.JooComponentsVersion()
        searcher.query = self.pluginsFound
        searcher.OfflinePlugins()
        self.JooDirsListing()

    # Grab the small plugins, versions and default files generated at run time
    def JooGetLocalFiles(self):
        self.plugins_small = [line.strip() for line in open(initializer.joo_plugins_small, encoding='utf-8')]
        self.versions = [line.strip() for line in open(initializer.joo_versions, encoding='utf-8')]
        self.defaultFiles = [line.strip() for line in open(initializer.joo_defaultFiles, encoding='utf-8')]
        self.defaultFolders = [line.strip() for line in open(initializer.joo_defaultFolders, encoding='utf-8')]

    # Find Joomla version and check it on exploit-db
    def JooVersion(self):
        msg = "Checking Joomla version ..."
        self.report.verbose(msg)
        self.requester.request(self.url + "/administrator/manifests/files" + '/joomla.xml', data=None)
        regex = '<version>(.+?)</version>'
        pattern = re.compile(regex)
        version = re.findall(pattern, self.requester.htmltext)
        if version:
            msg = "Joomla Version: " + version[0]
            self.report.info(msg)
            if version[0] in self.versions:
                for ver in self.versions:
                    searcher.query = ver
                    searcher.OfflineCore()
                    if ver == version[0]:
                        break

    # Find current Joomla templates and check them on exploit-db
    def JooTemplate(self):
        msg = "Checking Joomla template ..."
        self.report.verbose(msg)
        self.requester.request(self.url + '/index.php', data=None)
        WebTemplates = re.findall("/templates/(.+?)/", self.requester.htmltext, re.IGNORECASE)
        WebTemplates = sorted(set(WebTemplates))
        self.requester.request(self.url + '/administrator/index.php', data=None)
        AdminTemplates = re.findall("/administrator/templates/(.+?)/", self.requester.htmltext, re.IGNORECASE)
        AdminTemplates = sorted(set(AdminTemplates))
        if WebTemplates:
            for WebTemplate in WebTemplates:
                msg = "Joomla Website Template: " + WebTemplate
                self.report.info(msg)
                searcher.query = WebTemplate
                searcher.OfflineTheme()
        if AdminTemplates:
            for AdminTemplate in AdminTemplates:
                msg = "Joomla Administrator Template: " + AdminTemplate
                self.report.info(msg)
                searcher.query = AdminTemplate
                searcher.OfflineTheme()

    # Find old or temp Joomla config files left on the web root
    def JooConfigFiles(self):
        msg = "Checking Joomla old configuration files ..."
        self.report.verbose(msg)
        for file in self.confFiles:
            self.requester.request(self.url + "/configuration" + file, data=None)
            if self.requester.status_code == 200 and len(self.requester.htmltext) not in self.notValidLen:
                msg = "Configuration File Found: " + self.url + "/configuration" + file
                self.report.high(msg)

    # Find default Joomla files (large number, prompt the user if display them all)
    def JooDefaultFiles(self):
        self.defFilesFound = []
        msg = "Checking Joomla default files ..."
        self.report.verbose(msg)
        msg = "Joomla Default Files: "
        self.report.message(msg)
        msg = "Joomla is likely to have a large number of default files"
        self.report.message(msg)
        msg = "Would you like to list them all?"
        self.report.message(msg)
        if not initializer.default:
            if input("[y/N]: ").lower().startswith('y'):
                # Check for default files
                for r, file in enumerate(self.defaultFiles):
                    self.requester.request(self.url + file, data=None)
                    if self.requester.status_code == 200 and len(self.requester.htmltext) not in self.notValidLen:
                        self.defFilesFound.append(self.url + file)
                for file in self.defFilesFound:
                    msg = file
                    self.report.info(msg)

    # Find Joomla users via Feed (Feed is available only in old versions of Joomla)
    def JooFeed(self):
        self.requester.request(self.url + '/?format=feed', data=None)
        jooUsers = re.findall("<author>(.+?) \((.+?)\)</author>", self.requester.htmltext, re.IGNORECASE)
        if jooUsers:
            msg = "Enumerating Joomla Usernames via \"Feed\" ..."
            self.report.message(msg)
            jooUsers = sorted(set(jooUsers))
            for user in jooUsers:
                self.usernames.append(user[1])
                msg = user[1] + ": " + user[0]
                self.report.info(msg)

    # Find directory listing in default directories and components directories
    def JooDirsListing(self):
        msg = "Checking for Directory Listing Enabled ..."
        self.report.info(msg)
        self.report.WriteTextFile(msg)
        for folder in self.defaultFolders:
            self.genericchecker.DirectoryListing(folder)
        for plugin in self.pluginsFound:
            self.genericchecker.DirectoryListing('/components/' + plugin)

    # Find modules checking the source code of the main page
    def JooModulesIndex(self):
        msg = "Checking Joomla modules in the index page"
        self.report.verbose(msg)
        self.requester.request(self.url, data=None)
        self.pluginsFound = re.findall(
            re.compile('/modules/(.+?)/'), self.requester.htmltext)
        self.pluginsFound = sorted(set(self.pluginsFound))

    # Template to find plugins version
    # Convert JooPluginsFound in a dictionary
    def JooComponentsVersion(self):
        self.pluginsFoundVers = {}
        for pluginFound in self.pluginsFound:
            self.pluginsFoundVers[pluginFound] = None
        self.pluginsFound = self.pluginsFoundVers

    # Find components via dictionary attack
    def JooComponents(self):
        msg = "Searching Joomla Components ..."
        self.report.message(msg)
        if not initializer.FullScan: self.plugins = self.plugins_small
        # Create Code
        q = queue.Queue()
        # Spawn all threads into code
        for u in range(initializer.threads):
            t = ThreadScanner(self.url, self.pluginPath, "/", self.pluginsFound, self.notExistingCode, self.notValidLen,
                              q)
            t.daemon = True
            t.start()
        # Add all plugins to the queue
        for r, i in enumerate(self.plugins):
            q.put(i)
        while not q.empty():
            time.sleep(1)
        q.join()


jooscan = JooScan()
