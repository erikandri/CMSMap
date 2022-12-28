#! /usr/bin/env python3
import queue
import re
import time

from .bruteforcer import BruteForcer
from .exploitdbsearch import ExploitDBSearch
from .genericchecks import GenericChecks
# Import Object
from .initialize import initializer
from .report import Report
from .requester import Requester
# Import Class
from .threadscanner import ThreadScanner


class WPScan:
    # Scan WordPress site
    def __init__(self, is_random_user_agent: bool = False, is_color: bool = False):
        self.pluginsFoundVers = None
        self.postdata = None
        self.defaultFolders = None
        self.defaultFiles = None
        self.versions = None
        self.plugins_small = None
        self.url = None
        self.currentVer = None
        self.latestVer = None
        self.pluginPath = "/wp-content/plugins/"
        self.themePath = "/wp-content/themes/"
        self.feed = "/?feed=rss2"
        self.author = "/?author="
        self.forgottenPsw = "/wp-login.php?action=lostpassword"
        self.usernames = []
        self.pluginsFound = []
        self.themesFound = []
        self.timthumbsFound = []
        self.notValidLen = []
        self.XMLRPCEnable = True
        self.theme = None
        self.notExistingCode = 404
        self.confFiles = [line.strip() for line in open(initializer.confFiles, encoding='utf-8')]
        self.plugins = [line.strip() for line in open(initializer.wp_plugins, encoding='utf-8')]
        self.themes = [line.strip() for line in open(initializer.wp_themes, encoding='utf-8')]
        self.themes_small = [line.strip() for line in open(initializer.wp_themes_small, encoding='utf-8')]
        self.timthumbs = [line.strip() for line in open(initializer.wp_timthumbs, encoding='utf-8')]
        self.report = Report(color=is_color)
        self.bruter = BruteForcer(is_random_user_agent=is_random_user_agent, is_color=is_color)
        self.requester = Requester(is_random_user_agent=is_random_user_agent)
        self.genericchecker = GenericChecks(is_random_user_agent=is_random_user_agent, is_color=is_color)
        self.searcher = ExploitDBSearch(is_color=is_color)

    # WordPress checks
    def WPrun(self):
        msg = "CMS Detection: WordPress"
        self.report.info(msg)
        self.searcher.cmstype = "Wordpress"
        self.searcher.pluginPath = self.pluginPath
        self.WPGetLocalFiles()
        self.WPVersion()
        self.WPCurrentTheme()
        self.WPConfigFiles()
        self.WPHello()
        self.WPFeed()
        self.WPAuthor()
        self.bruter.usrlist = self.usernames
        self.bruter.pswlist = initializer.weakpsw
        self.WPXMLRPC_check()
        if self.XMLRPCEnable:
            if self.bruter.dictattack is not None:
                self.bruter.WPXMLRPC_brute()
            self.WPXMLRPC_pingback()
            self.WPXMLRPC_BF()
        elif self.bruter.dictattack is not None:
            self.bruter.WPrun()
        self.WPForgottenPassword()
        self.genericchecker.AutocompleteOff('/wp-login.php')
        self.WPDefaultFiles()
        if initializer.FullScan:
            self.genericchecker.CommonFiles()
        self.WPpluginsIndex()
        self.WPplugins()
        self.WPpluginsVersion()
        self.searcher.query = self.pluginsFound
        self.searcher.OfflinePlugins()
        if initializer.FullScan:
            self.WPTimThumbs()
        self.WPDirsListing()

    # Grab the small plugins, versions and default files generated at run time
    def WPGetLocalFiles(self):
        self.plugins_small = [line.strip() for line in open(initializer.wp_plugins_small, encoding='utf-8')]
        self.versions = [line.strip() for line in open(initializer.wp_versions, encoding='utf-8')]
        self.defaultFiles = [line.strip() for line in open(initializer.wp_defaultFiles, encoding='utf-8')]
        self.defaultFolders = [line.strip() for line in open(initializer.wp_defaultFolders, encoding='utf-8')]

    # Find WordPress version and check it on exploit-db
    def WPVersion(self):
        msg = "Checking WordPress version ..."
        self.report.verbose(msg)
        self.requester.request(self.url + '/readme.html', data=None)
        regex = '<br />.* (\d+\.\d+[\.\d+]*)\n</h1>'
        pattern = re.compile(regex)
        self.currentVer = re.findall(pattern, self.requester.htmltext)
        if self.currentVer:
            msg = "Wordpress Version: " + self.currentVer[0]
            self.report.info(msg)
        else:
            self.requester.request(self.url, data=None)
            self.currentVer = re.findall('<meta name="generator" content="WordPress (\d+\.\d+[\.\d+]*)"',
                                         self.requester.htmltext)
            if self.currentVer:
                msg = "Wordpress Version: " + self.currentVer[0]
                self.report.info(msg)
        if self.currentVer:
            if self.currentVer[0] in self.versions:
                for ver in self.versions:
                    self.searcher.query = ver
                    self.searcher.OfflineCore()
                    if ver == self.currentVer[0]:
                        break

    # Find WordPress theme and check it on exploit-db
    def WPCurrentTheme(self):
        msg = "Checking WordPress theme ..."
        self.report.verbose(msg)
        self.requester.request(self.url, data=None)
        regex = '/wp-content/themes/(.+?)/'
        pattern = re.compile(regex)
        CurrentTheme = re.findall(pattern, self.requester.htmltext)
        if CurrentTheme:
            self.theme = CurrentTheme[0]
            msg = "Wordpress Theme: " + self.theme
            self.report.info(msg)
            self.searcher.query = self.theme
            self.searcher.OfflineTheme()

    # Find old or temp WordPress config files left on the web root
    def WPConfigFiles(self):
        msg = "Checking old WordPress config files ..."
        self.report.verbose(msg)
        for file in self.confFiles:
            self.requester.request(self.url + "/wp-config" + file, data=None)
            if self.requester.status_code == 200 and len(self.requester.htmltext) not in self.notValidLen:
                msg = "Configuration File Found: " + self.url + "/wp-config" + file
                self.report.high(msg)

    # Find default WordPress files
    def WPDefaultFiles(self):
        self.defFilesFound = []
        msg = "Checking WordPres default files..."
        self.report.verbose(msg)
        msg = "Default WordPress Files:"
        self.report.message(msg)
        for file in self.defaultFiles:
            self.requester.request(self.url + file, data=None)
            if self.requester.status_code == 200 and len(self.requester.htmltext) not in self.notValidLen:
                self.defFilesFound.append(self.url + file)
        for file in self.defFilesFound:
            msg = file
            self.report.info(msg)

    # Find WordPress users checking the dc:creator field in Feed function
    def WPFeed(self):
        msg = "Enumerating Wordpress usernames via \"Feed\" ..."
        self.report.verbose(msg)
        self.requester.request(self.url + self.feed, data=None)
        wpUsers = re.findall("<dc:creator>[<!\[CDATA\[]*(.+?)[\]\]>]*</dc:creator>",
                             self.requester.htmltext)
        if wpUsers:
            self.usernames = wpUsers + self.usernames
            self.usernames = sorted(set(self.usernames))

    # Find WordPress users checking the first 50 authors blogs
    def WPAuthor(self):
        msg = "Enumerating Wordpress usernames via \"Author\" ..."
        self.report.verbose(msg)
        for user in range(1, 50):
            self.requester.request(self.url + self.author + str(user), data=None)
            wpUser = re.findall("author author-(.+?) ", self.requester.htmltext, re.IGNORECASE)
            if wpUser:
                self.usernames = wpUser + self.usernames
            wpUser = re.findall("Posts by (.+?) Feed", self.requester.htmltext, re.IGNORECASE)
            if wpUser:
                self.usernames = wpUser + self.usernames
        self.usernames = sorted(set(self.usernames))
        # if users are found, print them (it includes the users found by WPFeed)
        if self.usernames:
            msg = "WordPress usernames identified: "
            self.report.message(msg)
            for user in self.usernames:
                msg = user
                self.report.medium(msg)

    # Check it is possible to enumerate users via Forgotten password functionality
    def WPForgottenPassword(self):
        msg = "Checking WordPress forgotten password ..."
        self.report.verbose(msg)
        # Use an invalid, not-existing, not-registered user
        self.postdata = {"user_login": "N0t3xist!1234"}
        self.requester.request(self.url + self.forgottenPsw, data=self.postdata)
        if re.findall(re.compile('Invalid username'), self.requester.htmltext):
            msg = "Forgotten Password Allows Username Enumeration: " + self.url + self.forgottenPsw
            self.report.info(msg)

    # Find full path via the default hello plugin
    def WPHello(self):
        self.requester.request(self.url + "/wp-content/plugins/hello.php", data=None)
        fullPath = re.findall(re.compile('Fatal error.*>/(.+?/)hello.php'), self.requester.htmltext)
        if fullPath:
            msg = "Wordpress Hello Plugin Full Path Disclosure: " + "/" + fullPath[0] + "hello.php"
            self.report.low(msg)

            # Find directory listing in default directories and plugin directories

    def WPDirsListing(self):
        msg = "Checking for Directory Listing Enabled ..."
        self.report.info(msg)
        self.report.WriteTextFile(msg)
        for folder in self.defaultFolders:
            self.genericchecker.DirectoryListing(folder)
        if self.theme:
            self.genericchecker.DirectoryListing('/wp-content/themes/' + self.theme)
        for plugin in self.pluginsFound:
            self.genericchecker.DirectoryListing('/wp-content/plugins/' + plugin)

    # Find plugins checking the source code of the main page
    def WPpluginsIndex(self):
        msg = "Checking WordPress plugins in the index page"
        self.report.verbose(msg)
        self.requester.request(self.url, data=None)
        self.pluginsFound = re.findall(re.compile('/wp-content/plugins/(.+?)/'), self.requester.htmltext)

    # Find plugins via a dictionary attack
    def WPplugins(self):
        msg = "Searching Wordpress Plugins ..."
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
        for i in self.plugins:
            q.put(i)
        while not q.empty():
            time.sleep(1)
        q.join()
        self.pluginsFound = sorted(set(self.pluginsFound))

    # self.pluginsFound are now a dictionary {"plugin_name":"plugin_version"}
    # Attempt to find plugins version
    def WPpluginsVersion(self):
        self.pluginsFoundVers = {}
        for pluginFound in self.pluginsFound:
            self.requester.request(self.url + self.pluginPath + pluginFound + "/readme.txt", data=None)
            pluginVer = re.findall('Stable tag: (\d+\.\d+[\.\d+]*)', self.requester.htmltext)
            # Add plugin version
            if pluginVer:
                self.pluginsFoundVers[pluginFound] = pluginVer[0]
            else:
                # Match has not been found
                self.pluginsFoundVers[pluginFound] = None
        self.pluginsFound = self.pluginsFoundVers

    # Find WordPress TimThumbs via a dictionary attack
    def WPTimThumbs(self):
        msg = "Searching Wordpress TimThumbs ..."
        self.report.message(msg)
        # Create Code
        q = queue.Queue()
        # Spawn all threads into code
        for u in range(initializer.threads):
            t = ThreadScanner(self.url, "/", "", self.timthumbsFound, self.notExistingCode, self.notValidLen, q)
            t.daemon = True
            t.start()
        # Add all plugins to the queue
        for r, i in enumerate(self.timthumbs):
            q.put(i)
        q.join()
        if self.timthumbsFound:
            for timthumbsFound in self.timthumbsFound:
                msg = self.url + "/" + timthumbsFound
                self.report.medium(msg)
            msg = " Timthumbs Potentially Vulnerable to File Upload: http://www.exploit-db.com/wordpress-timthumb-exploitation"
            self.report.medium(msg)

    # Find other WordPress installed via a dictionary attack
    def WPThemes(self):
        msg = "Searching Wordpress Themes ..."
        self.report.message(msg)
        if not initializer.FullScan:
            self.themes = self.themes_small
        # Create Code
        q = queue.Queue()
        # Spawn all threads into code
        for u in range(initializer.threads):
            t = ThreadScanner(self.url, self.themePath, "/", self.themesFound, self.notExistingCode, self.notValidLen,
                              q)
            t.daemon = True
            t.start()
        # Add all theme to the queue
        for r, i in enumerate(self.themes):
            q.put(i)
        q.join()
        for themesFound in self.themesFound:
            msg = themesFound
            self.report.info(msg)

    # Check if XML-RPC services are enabled
    def WPXMLRPC_check(self):
        msg = "Checking if XML-RPC services are enabled ..."
        self.report.verbose(msg)
        self.postdata = '''<methodCall><methodName>wp.getUsersBlogs</methodName><params>
                        <param><value><string>ThisIsATest</string></value></param>
                        <param><value><string>ThisIsATest</string></value></param></params></methodCall>
                        '''
        self.requester.request(self.url + '/xmlrpc.php', data=self.postdata)
        if re.search('<value><string>XML-RPC services are disabled', self.requester.htmltext):
            msg = "XML-RPC services are disabled"
            self.report.verbose(msg)
            self.XMLRPCEnable = False
        else:
            msg = "XML-RPC services are enabled"
            self.report.medium(msg)

    # Check if the XML-RPC Pingback is enabled
    def WPXMLRPC_pingback(self):
        msg = "Checking XML-RPC Pingback Vulnerability ..."
        self.report.verbose(msg)
        self.postdata = '''<methodCall><methodName>pingback.ping</methodName><params>
                        <param><value><string>http://N0tB3th3re0484940:22/</string></value></param>
                        <param><value><string>''' + self.url + '''</string></value></param>
                        </params></methodCall>'''
        self.requester.request(self.url + '/xmlrpc.php', data=self.postdata)
        if re.search('<name>16</name>', self.requester.htmltext):
            msg = "Website vulnerable to XML-RPC Pingback Force Vulnerability"
            self.report.low(msg)

    # Check if it is possible to brute-froce the logins via XML-RPC
    def WPXMLRPC_BF(self):
        msg = "Checking XML-RPC Brute Force Vulnerability ..."
        self.report.verbose(msg)
        self.postdata = '''<methodCall><methodName>wp.getUsersBlogs</methodName><params>
                        <param><value><string>admin</string></value></param>
                        <param><value><string></string></value></param>
                        </params></methodCall>'''
        self.requester.request(self.url + '/xmlrpc.php', data=self.postdata)
        if re.search('<int>403</int>', self.requester.htmltext):
            msg = "Website vulnerable to XML-RPC Brute Force Vulnerability"
            self.report.medium(msg)
            if self.currentVer:
                if self.currentVer[0] < '4.4':
                    msg = "Website vulnerable to XML-RPC Amplification Brute Force Vulnerability"
                    self.report.medium(msg)


wpscan = WPScan()
