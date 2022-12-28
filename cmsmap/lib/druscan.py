#! /usr/bin/env python3
import queue
import re

from .bruteforcer import BruteForcer
from .exploitdbsearch import ExploitDBSearch
from .genericchecks import GenericChecks
# Import Objects
from .initialize import initializer
from .report import Report
from .requester import Requester
# Import Class
from .threadscanner import ThreadScanner


class DruScan:
    # Scan Drupal site
    def __init__(self, is_random_user_agent: bool = False, is_color: bool = False):
        self.pluginsFoundVers = None
        self.postdata = None
        self.forgottenPsw = None
        self.quser = None
        self.blog = None
        self.alphanum = None
        self.views = None
        self.defFilesFound = None
        self.Drutheme = None
        self.defaultFolders = None
        self.defaultFiles = None
        self.versions = None
        self.plugins_small = None
        self.url = None
        self.notExistingCode = 404
        self.notValidLen = []
        self.pluginPath = "/modules/"
        self.confFiles = [line.strip() for line in open(initializer.confFiles, encoding='utf-8')]
        self.usernames = []
        self.pluginsFound = []
        self.plugins = [line.strip() for line in open(initializer.dru_plugins, encoding='utf-8')]
        self.bruter = BruteForcer(is_random_user_agent=is_random_user_agent, is_color=is_color)
        self.report = Report(color=is_color)
        self.genericchecker = GenericChecks(is_random_user_agent=is_random_user_agent, is_color=is_color)
        self.requester = Requester(is_random_user_agent=is_random_user_agent)
        self.searcher = ExploitDBSearch(is_color=is_color)

    # Drupal checks
    def Drurun(self):
        msg = "CMS Detection: Drupal"
        self.report.info(msg)
        self.searcher.cmstype = "Drupal"
        self.searcher.pluginPath = self.pluginPath
        self.DruGetLocalFiles()
        self.DruVersion()
        self.DruCurrentTheme()
        self.DruConfigFiles()
        self.DruViews()
        self.DruBlog()
        self.DruQUser()
        self.bruter.usrlist = self.usernames
        self.bruter.pswlist = initializer.weakpsw
        if self.bruter.dictattack is not None:
            self.bruter.Drurun()
        self.genericchecker.AutocompleteOff(self.quser)
        self.DruDefaultFiles()
        if initializer.FullScan:
            self.genericchecker.CommonFiles()
        self.DruForgottenPassword()
        self.DruModulesIndex()
        self.DruModules()
        self.DruModulesVersion()
        self.searcher.query = self.pluginsFound
        self.searcher.OfflinePlugins()
        self.DruDirsListing()

    # Grab the small plugins, versions and default files generated at run time
    def DruGetLocalFiles(self):
        self.plugins_small = [line.strip() for line in open(initializer.dru_plugins_small, encoding='utf-8')]
        self.versions = [line.strip() for line in open(initializer.dru_versions, encoding='utf-8')]
        self.defaultFiles = [line.strip() for line in open(initializer.dru_defaultFiles, encoding='utf-8')]
        self.defaultFolders = [line.strip() for line in open(initializer.dru_defaultFolders, encoding='utf-8')]

    # Find Drupal version and check it on exploit-db
    def DruVersion(self):
        msg = "Checking Drupal version ..."
        self.report.verbose(msg)
        self.requester.request(self.url + '/CHANGELOG.txt', data=None)
        regex = 'Drupal (\d+\.\d+),'
        pattern = re.compile(regex)
        version = re.findall(pattern, self.requester.htmltext)
        if version:
            msg = "Drupal Version: " + version[0]
            self.report.info(msg)
            if version[0] in self.versions:
                for ver in self.versions:
                    self.searcher.query = ver
                    self.searcher.OfflineCore()
                    if ver == version[0]:
                        break

    # Find current Drupal theme and check it on exploit-db
    def DruCurrentTheme(self):
        msg = "Checking Drupal theme"
        self.report.verbose(msg)
        self.requester.request(self.url, data=None)
        DruTheme = re.findall("/themes/(.+?)/", self.requester.htmltext, re.IGNORECASE)
        if DruTheme:
            self.Drutheme = DruTheme[0]
            msg = "Drupal Theme: " + self.Drutheme
            self.report.info(msg)
            self.searcher.query = self.Drutheme
            self.searcher.OfflineTheme()

    # Find old or temp Drupal conf files left on the web root
    def DruConfigFiles(self):
        msg = "Checking Drupal old config files"
        self.report.verbose(msg)
        for file in self.confFiles:
            self.requester.request(self.url + "/sites/default/settings" + file, data=None)
            if self.requester.status_code == 200 and len(self.requester.htmltext) not in self.notValidLen:
                msg = "Configuration File Found: " + self.url + "/sites/default/settings" + file
                self.report.high(msg)

    # Find default Drupal files (large number, prompt the user if display them all)
    def DruDefaultFiles(self):
        msg = "Checking Drupal default files"
        self.report.verbose(msg)
        self.defFilesFound = []
        msg = "Drupal Default Files: "
        self.report.message(msg)
        msg = "Drupal is likely to have a large number of default files"
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

    # Find Drupal users via the View Module
    def DruViews(self):
        self.views = "/?q=admin/views/ajax/autocomplete/user/"
        if not initializer.disableCleanURLs:
            self.views = self.views.replace("?q=", "")
        self.alphanum = list("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
        msg = "Enumerating Drupal Usernames via \"Views\" Module..."
        self.report.message(msg)
        self.requester.noredirect(self.url + "/?q=admin/views/ajax/autocomplete/user/NotExisingUser1234!", data=None)
        # If NotExisingUser1234 returns [], then enumerate users
        if self.requester.htmltext == '[]':
            msg = "\"Views\" Module vulnerable to user enumeration"
            self.report.medium(msg)
            for letter in self.alphanum:
                self.requester.noredirect(self.url + self.views + letter, data=None)
                regex = '"(.+?)"'
                pattern = re.compile(regex)
                self.usernames = self.usernames + re.findall(pattern, self.requester.htmltext)
            self.usernames = sorted(set(self.usernames))
            for user in self.usernames:
                msg = user
                self.report.info(msg)

    # Find Drupal users checking the first 50 authors blogs
    def DruBlog(self):
        self.blog = "/?q=blog/"
        if not initializer.disableCleanURLs:
            self.blog = self.blog.replace("?q=", "")
        self.requester.request(self.url + self.blog, data=None)
        if self.requester.status_code == 200:
            msg = "Enumerating Drupal Usernames via \"Blog\" Module..."
            self.report.message(msg)
            for blognum in range(1, 50):
                self.requester.request(self.url + self.blog + str(blognum), data=None)
                regex = "<title>(.+?)\'s"
                pattern = re.compile(regex)
                user = re.findall(pattern, self.requester.htmltext)
                self.usernames = self.usernames + user
                if user:
                    msg = user[0]
                    self.report.info(msg)
            self.usernames = sorted(set(self.usernames))

    def DruQUser(self):
        self.quser = "/?q=user/"
        if not initializer.disableCleanURLs:
            self.quser = self.quser.replace("?q=", "")
        msg = "Enumerating Drupal Usernames via \"" + self.quser + "\"..."
        self.report.message(msg)
        for usernum in range(1, 50):
            self.requester.request(self.url + self.quser + str(usernum), data=None)
            regex = "users\/(.+?)\?destination"
            pattern = re.compile(regex)
            user = re.findall(pattern, self.requester.htmltext)
            self.usernames = self.usernames + user
            if user:
                msg = user[0]
                self.report.info(msg)
        self.usernames = sorted(set(self.usernames))

    # Check if it is possible to enumerate users via Forgotten password functionality
    def DruForgottenPassword(self):
        self.forgottenPsw = "/?q=user/password"
        if not initializer.disableCleanURLs:
            self.forgottenPsw = self.forgottenPsw.replace("?q=", "")
        msg = "Checking Drupal forgotten password ..."
        self.report.verbose(msg)
        # Username Enumeration via Forgotten Password
        self.postdata = {"name": "N0t3xist!1234", "form_id": "user_pass"}
        # HTTP POST Request
        self.requester.request(self.url + self.forgottenPsw, data=self.postdata)
        # print "[*] Trying Credentials: "+user+" "+pwd
        if re.findall(re.compile('Sorry,.*N0t3xist!1234.*is not recognized'), self.requester.htmltext):
            msg = "Forgotten Password Allows Username Enumeration: " + self.url + self.forgottenPsw
            self.report.info(msg)
            self.report.WriteTextFile(msg)

    # Find directory listing in default directories and module directories
    def DruDirsListing(self):
        msg = "Checking for Directory Listing Enabled ..."
        self.report.info(msg)
        self.report.WriteTextFile(msg)
        for folder in self.defaultFolders:
            self.genericchecker.DirectoryListing(folder)
        for plugin in self.pluginsFound:
            self.genericchecker.DirectoryListing('/modules/' + plugin)

    # Find modules checking the source code of the main page
    def DruModulesIndex(self):
        msg = "Checking Drupal mudules in the index page"
        self.report.verbose(msg)
        self.requester.request(self.url, data=None)
        self.pluginsFound = re.findall(
            re.compile('/modules/(.+?)/'), self.requester.htmltext)
        self.pluginsFound = sorted(set(self.pluginsFound))

    # Template to find plugins version
    # Convert DruPluginsFound in a dictionary
    def DruModulesVersion(self):
        self.pluginsFoundVers = {}
        for pluginFound in self.pluginsFound:
            self.pluginsFoundVers[pluginFound] = None
        self.pluginsFound = self.pluginsFoundVers

    # Find modules via dictionary attack
    def DruModules(self):
        msg = "Search Drupal Modules ..."
        self.report.message(msg)
        if not initializer.FullScan:
            self.plugins = self.plugins_small
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
        q.join()
