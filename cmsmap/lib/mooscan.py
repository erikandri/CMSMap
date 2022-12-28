#! /usr/bin/env python3
import hashlib
import os
import subprocess

from .exploitdbsearch import searcher
from .genericchecks import GenericChecks
# Import Objects
from .initialize import initializer
from .report import Report
from .requester import Requester


# Import Class


class MooScan:
    # Scan Moodle site
    def __init__(self, is_random_user_agent: bool = False, is_color: bool = False):
        self.url = None
        self.usernames = []
        # Plugins can be in /local /blocks /mod
        self.pluginPath = "/local"
        self.pluginsFound = []
        self.notValidLen = []
        self.notExistingCode = 404
        self.confFiles = [line.strip() for line in open(initializer.confFiles, encoding='utf-8')]
        # No plugins for moodle
        # self.plugins = [line.strip() for line in open(initializer.moo_plugins, encoding='utf-8')]
        self.report = Report(color=is_color)
        self.genericchecker = GenericChecks(is_random_user_agent=is_random_user_agent, is_color=is_color)
        self.requester = Requester(is_random_user_agent=is_random_user_agent)

    # Moodle checks
    def Moorun(self):
        msg = "CMS Detection: Moodle"
        self.report.info(msg)
        searcher.cmstype = "Moodle"
        searcher.pluginPath = self.pluginPath
        self.MooGetLocalFiles()
        self.MooConfigFiles()
        self.MooDefaultFiles()
        self.MooVersion()
        self.MooDirsListing()

    # Grab the versions and default files generated at run time
    def MooGetLocalFiles(self):
        self.versions = [line.strip() for line in open(initializer.moo_versions, encoding='utf-8')]
        self.defaultFiles = [line.strip() for line in open(initializer.moo_defaultFiles, encoding='utf-8')]
        self.defaultFolders = [line.strip() for line in open(initializer.moo_defaultFolders, encoding='utf-8')]

    # Find old or temp Moodle config files left on the web root
    def MooConfigFiles(self):
        msg = "Checking Moodle old configuration files ..."
        self.report.verbose(msg)
        for file in self.confFiles:
            self.requester.request(self.url + "/config" + file, data=None)
            if self.requester.status_code == 200 and len(self.requester.htmltext) not in self.notValidLen:
                msg = "Configuration File Found: " + self.url + "/config" + file
                self.report.high(msg)

    # Find default Moodle files (large number, prompt the user if display them all)
    def MooDefaultFiles(self):
        self.defFilesFound = []
        msg = "Checking Moodle default files ..."
        self.report.verbose(msg)
        msg = "Moodle Default Files: "
        self.report.message(msg)
        msg = "Moodle is likely to have a large number of default files"
        self.report.message(msg)
        msg = "Would you like to list them all?"
        self.report.message(msg)
        if not initializer.default:
            if input("[y/N]: ").lower().startswith('y'):
                # Check for default files
                for r, file in enumerate(self.defaultFiles):
                    self.requester.request(self.url + file, data=None)
                    if self.requester.status_code == 200 and len(self.requester.htmltext) not in self.notValidLen:
                        self.defFilesFound.append(file)
                for file in self.defFilesFound:
                    msg = self.url + file
                    self.report.info(msg)

    # Find Moodle version 
    def MooVersion(self):
        # Check if self.defFilesFound is not empty
        if self.defFilesFound:
            defFileHashes = {}
            top3 = 0
            top3versions = []
            firstmatch = False
            # Create list of Moodle versions {('version': hash_value)}
            for defFile in self.defFilesFound:
                self.requester.request(self.url + defFile, data=None)
                hash_object = hashlib.sha256(self.requester.htmltext.encode('utf-8'))
                hash_digest = hash_object.hexdigest()
                defFileHashes[defFile] = hash_digest
            msg = "Checking Moodle version ..."
            self.report.verbose(msg)
            FNULL = open(os.devnull, 'w')
            p = subprocess.Popen("git -C " + initializer.cmsmapPath + "/tmp/moodle checkout master -f", stdout=FNULL,
                                 stderr=FNULL, shell=True)
            p.communicate()
            # Compare discovered default files with default files against each version of Moodle
            for mver in self.versions:
                msg = "Checking version: " + mver
                self.report.verbose(msg)
                matches = 0
                p = subprocess.Popen("git -C " + initializer.cmsmapPath + "/tmp/moodle checkout tags/" + mver,
                                     stdout=FNULL, stderr=FNULL, shell=True)
                p.communicate()
                for defFile, defFileHash in defFileHashes.items():
                    filepath = initializer.cmsmapPath + "/tmp/moodle" + defFile
                    hash_digest = ""
                    if os.path.isfile(filepath):
                        f = open(filepath, "rb")
                        hash_object = hashlib.sha256(f.read())
                        hash_digest = hash_object.hexdigest()
                    if hash_digest == defFileHash:
                        matches = matches + 1
                # Margin error of 1 file
                if matches >= (len(defFileHashes) - 1):
                    top3versions.append((mver, matches))
                    firstmatch = True
                if firstmatch:
                    top3 = top3 + 1
                    if top3 == 3:
                        top3versions = sorted(top3versions, key=lambda ver: ver[1], reverse=True)
                        msg = "Detected version of Moodle appears to be: "
                        self.report.info(msg)
                        for moodle_vers in top3versions:
                            msg = str(moodle_vers[0])
                            self.report.info(msg)
                        break

            p = subprocess.Popen("git -C " + initializer.cmsmapPath + "/tmp/moodle checkout master -f", stdout=FNULL,
                                 stderr=FNULL, shell=True, universal_newlines=True)
            output, error = p.communicate()

    # Find directory listing in default directories and components directories
    def MooDirsListing(self):
        msg = "Checking for Directory Listing Enabled ..."
        self.report.info(msg)
        self.report.WriteTextFile(msg)
        for folder in self.defaultFolders:
            self.genericchecker.DirectoryListing(folder)


mooscan = MooScan()
