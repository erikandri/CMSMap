#! /usr/bin/env python3
import os
import re
import subprocess
import sys

from .initialize import initializer
from .report import Report


class CoreUpdate:
    # Perfom updates
    def __init__(self, is_color: bool = False):
        self.edbpath = initializer.edbpath
        self.edbtype = initializer.edbtype
        self.cmsmapPath = initializer.cmsmapPath
        self.wp_plugins = initializer.wp_plugins
        self.wp_plugins_small = initializer.wp_plugins_small
        self.wp_themes_small = initializer.wp_themes_small
        self.wp_versions = initializer.wp_versions
        self.joo_plugins = initializer.joo_plugins
        self.joo_plugins_small = initializer.joo_plugins_small
        self.joo_versions = initializer.joo_versions
        self.dru_plugins = initializer.dru_plugins
        self.dru_plugins_small = initializer.dru_plugins_small
        self.dru_versions = initializer.dru_versions
        self.moo_versions = initializer.moo_versions
        self.ospath = initializer.ospath
        self.report = Report(color=is_color)

    # Force update of plugins from the local exploit-db, fetch the CMSs versions from remote Git
    # and run git pull from CMSmap git repo
    def forceCMSmapUpdate(self):
        if initializer.forceCMSmapUpdate == 'P':
            self.UpdateLocalPlugins()
            self.UpdateCMSVersions()
            self.UpdateDefaultFiles()
        elif initializer.forceCMSmapUpdate == 'C':
            self.UpdateCMSmap()
        elif initializer.forceCMSmapUpdate == 'PC':
            self.UpdateCMSmap()
            self.UpdateCMSVersions()
            self.UpdateLocalPlugins()
            self.UpdateDefaultFiles()
        else:
            msg = "Not Valid Option Provided. Use (C)MSmap, (P)lugins or (PC) for both"
            self.report.message(msg)
            msg = "Example: " + os.path.basename(sys.argv[0]) + " -U PC"
            self.report.message(msg)
        self.SortUniqueFile()
        sys.exit(0)

    # Run git pull from the CMSmap git repo
    def UpdateCMSmap(self):
        # Ensure that with Git there are no issue for updating the plugin list
        success = False
        if not self.ospath + ".git":
            msg = "Git Repository Not Found. Please download the latest version of CMSmap from GitHub repository"
            self.report.error(msg)
            msg = "Example: git clone https://github.com/erikandri/CMSMap.git"
            self.report.error(msg)
        else:
            msg = "Updating CMSmap to the latest version from GitHub repository... "
            self.report.message(msg)
            os.chdir(self.ospath)
            process = os.system("git pull")
            if process == 0:
                success = True
        if success:
            msg = "CMSmap is now updated to the latest version!"
            self.report.message(msg)
        else:
            msg = " Updated could not be completed. Please download the latest version of CMSmap from GitHub repository"
            self.report.error(msg)
            msg = " Example: git clone https://github.com/erikandri/CMSMap.git"
            self.report.error(msg)

    # Run sort-uniq on the plugins files
    @staticmethod
    def SortUniqueFile():
        for new_list in [
            initializer.wp_plugins, initializer.wp_plugins_small, initializer.wp_themes_small,
            initializer.wp_defaultFiles, initializer.wp_defaultFolders,
            initializer.joo_plugins, initializer.joo_plugins_small, initializer.joo_defaultFiles,
            initializer.joo_defaultFolders,
            initializer.dru_plugins, initializer.dru_plugins_small,
            initializer.moo_defaultFiles, initializer.moo_defaultFolders
        ]:
            readlist = sorted(set([line.strip() for line in open(new_list)]))
            f = open(new_list, "w")
            for plugin in readlist:
                f.write("%s\n" % plugin)
            f.close()

    # Check if the local exploit-db is updated. If not, ask the user to update it and it will also fetch the CMSs versions from remote Git
    # or APT. Then udpate plugins from the local exploit-db
    def UpdateExploitDB(self):
        if self.edbtype.lower() == "git":
            if os.path.exists(self.edbpath + ".git"):
                p = subprocess.Popen("git -C " + self.edbpath + " remote update", stdout=subprocess.PIPE, shell=True)
                p.communicate()
                p = subprocess.Popen("git -C " + self.edbpath + " status -uno", stdout=subprocess.PIPE, shell=True,
                                     universal_newlines=True)
                output, error = p.communicate()
                if re.search('behind', output):
                    msg = "ExploitDB and CMSmap plugins are not updated to the latest version"
                    self.report.message(msg)
                    msg = "Would you like to update it?"
                    self.report.message(msg)
                    if not initializer.default:
                        if input("[y/N]: ").lower().startswith('y'):
                            os.system("git -C " + self.edbpath + " pull")
                            self.UpdateCMSVersions()
                            self.UpdateLocalPlugins()
                            self.UpdateTmpCMS()
            else:
                msg = "ExploitDB Git repository was not found"
                self.report.error(msg)
                msg = "Clone ExploitDB repository: git clone https://github.com/offensive-security/exploit-database"
                self.report.message(msg)
                msg = "Then set the ExploitDB path \"edbpath\" in cmsmap.conf"
                self.report.message(msg)
                msg = "ie: edbpath = /opt/exploitdb/"
                self.report.message(msg)
                sys.exit(1)
        elif self.edbtype.lower() == "apt":
            if os.path.exists(self.edbpath):
                p = subprocess.Popen(
                    "apt-get install exploitdb -s",
                    stdout=subprocess.PIPE,
                    shell=True, universal_newlines=True)
                output, error = p.communicate()
                if re.search('Inst exploitdb', output):
                    msg = "ExploitDB and CMSmap plugins are not updated to the latest version"
                    self.report.message(msg)
                    msg = "Would you like to update it?"
                    self.report.message(msg)
                    if not initializer.default:
                        if input("[y/N]: ").lower().startswith('y'):
                            os.system("apt-get install exploitdb")
                            self.UpdateCMSVersions()
                            self.UpdateLocalPlugins()
                            self.UpdateTmpCMS()
            else:
                msg = "ExploitDB APT path was not found"
                self.report.error(msg)
                msg = "Set the ExploitDB path \"edbpath\" in cmsmap.conf"
                self.report.message(msg)
                msg = "ie: edbpath = /usr/share/exploitdb/"
                self.report.message(msg)
                sys.exit(1)
        else:
            msg = "ExploitDB GIT or APT settings not found"
            self.report.error(msg)
            msg = "Would you like to clone the ExploitDB GIT repository now?"
            self.report.message(msg)
            if input("[y/N]: ").lower().startswith('y'):
                msg = "Where would you like to save it?"
                self.report.message(msg)
                answer = input("Default: /opt/exploit-database: ")
                if not answer.strip():
                    self.edbpath = "/opt/exploit-database"
                    self.edbtype = "git"
                    initializer.config.set("exploitdb", "edbpath", self.edbpath)
                    if not os.path.exists(self.edbpath):
                        os.makedirs(self.edbpath)
                    p = subprocess.Popen(
                        "git clone https://github.com/offensive-security/exploit-database" + self.edbpath,
                        stdout=subprocess.PIPE,
                        shell=True)
                    p.communicate()
                else:
                    if answer.lower().startswith('/'):
                        self.edbpath = os.path.join(
                            os.path.normpath(answer), "")
                        if not os.path.exists(self.edbpath):
                            os.makedirs(self.edbpath)
                        p = subprocess.Popen(
                            "git clone https://github.com/offensive-security/exploit-database" + self.edbpath,
                            stdout=subprocess.PIPE,
                            shell=True)
                        p.communicate()
                with open(os.path.join(initializer.cmsmapPath, "cmsmap.conf"), 'wr') as self.configFile:
                    initializer.config.set("exploitdb", "edbpath", os.path.normpath(self.edbpath))
                    initializer.config.set("exploitdb", "edbtype", "git")
                    initializer.config.write(self.configFile)
                    self.UpdateCMSVersions()
                    self.UpdateLocalPlugins()
                    self.UpdateTmpCMS()
            else:
                msg = "OK. Ensure that either the APT \"exploitdb\" package or ExploitDB GIT repository is installed"
                self.report.message(msg)
                msg = "Then set the \"edbtype\" and \"edbpath\" settings in cmsmap.conf"
                self.report.message(msg)
                sys.exit(1)

    # Update CMS versions from remote Git repos
    def UpdateCMSVersions(self):
        local_versions = [('wordpress', initializer.wp_versions, 'tag | sort -rbVu'),
                          ('joomla', initializer.joo_versions, 'tag | sort -rbVu | grep -vE "search|vPBF|11|12|13"'),
                          ('drupal', initializer.dru_versions, 'tag | sort -rbVu | grep -v start'),
                          ('moodle', initializer.moo_versions, 'tag | sort -rbVu')]

        for cms_type, cms_file, sorted_versions in local_versions:
            msg = "Updating " + cms_type + " versions"
            self.report.message(msg)
            p = subprocess.Popen("git -C " + self.cmsmapPath + "/tmp/" + cms_type + " " + sorted_versions,
                                 stdout=subprocess.PIPE, shell=True, universal_newlines=True)
            output, error = p.communicate()
            f = open(cms_file, "w")
            f.write(output)
            f.close()

    # If *_plugins_smalls.txt, *_versions.txt, *_defaultfiles.txt, defaultfolders.txt do not exist, generate them
    def CheckLocalFiles(self):
        for file_plugin_small in [initializer.wp_plugins_small,
                                  initializer.joo_plugins_small,
                                  initializer.dru_plugins_small]:
            if not os.path.isfile(file_plugin_small):
                self.UpdateLocalPlugins()
        for file_version in [initializer.wp_versions,
                             initializer.joo_versions,
                             initializer.dru_versions,
                             initializer.moo_versions]:
            if not os.path.isfile(file_version):
                self.UpdateTmpCMS()
                self.UpdateCMSVersions()
        for file_default in [initializer.wp_defaultFiles,
                             initializer.wp_defaultFolders,
                             initializer.joo_defaultFiles,
                             initializer.joo_defaultFolders,
                             initializer.dru_defaultFiles,
                             initializer.dru_defaultFolders,
                             initializer.moo_defaultFiles,
                             initializer.moo_defaultFolders]:
            if not os.path.isfile(file_default):
                self.UpdateDefaultFiles()
        self.SortUniqueFile()

    # Update Plugins from local exploit-db
    def UpdateLocalPlugins(self):
        local_plugins = [('wordpress',
                          "grep -iREho wp-content/plugins/\(.+?\)/ " + self.edbpath +
                          "/exploits/php | cut -d '/' -f 3 | sort -u | tail -n+3",
                          initializer.wp_plugins_small),
                         ('joomla',
                          "grep -iREho \?option=\(com_\\w*\)\& " + self.edbpath +
                          "/exploits/ | cut -d '&' -f 1 | cut -d '=' -f 2 | sort -u ",
                          initializer.joo_plugins_small),
                         ('drupal',
                          "grep -iREho \/components\/\(com_\\w*\)\/ " + self.edbpath +
                          "/exploits/ | cut -d '/' -f 3 |  cut -d'.' -f1 | sort -u",
                          initializer.dru_plugins_small)]
        for cms_type, grep_cmd, cms_small_plugin_path in local_plugins:
            msg = "Updating " + cms_type + " small plugins"
            self.report.message(msg)
            p = subprocess.Popen(grep_cmd, stdout=subprocess.PIPE, shell=True, universal_newlines=True)
            output, error = p.communicate()
            f = open(cms_small_plugin_path, "a")
            f.write(output)
            f.close()

    # Download and update local GIT repos of CMSs for default files and CMS version detection
    def UpdateTmpCMS(self):
        msg = "Update CMSs in tmp folder"
        self.report.verbose(msg)
        git_repos = {'wordpress': 'https://github.com/wordpress/wordpress',
                     'joomla': 'https://github.com/joomla/joomla-cms',
                     'drupal': 'https://github.com/drupal/drupal',
                     'moodle': 'https://github.com/moodle/moodle'}
        for repo_key, repo_value in git_repos.items():
            if not os.path.exists(self.cmsmapPath + "/tmp/" + repo_key + "/.git"):
                msg = repo_key + " git repo has not been found. Cloning..."
                self.report.message(msg)
                p = subprocess.Popen("git clone " + repo_value + " " + self.cmsmapPath + "/tmp/" + repo_key,
                                     stdout=subprocess.PIPE,
                                     shell=True, universal_newlines=True)
                p.communicate()
            else:
                p = subprocess.Popen("git -C " + self.cmsmapPath + "/tmp/" + repo_key + " remote update",
                                     stdout=subprocess.PIPE, shell=True)
                p.communicate()
                p = subprocess.Popen("git -C " + self.cmsmapPath + "/tmp/" + repo_key + " status -uno",
                                     stdout=subprocess.PIPE, shell=True,
                                     universal_newlines=True)
                output, error = p.communicate()
                if re.search('behind', output):
                    os.system("git -C " + self.cmsmapPath + "/tmp/" + repo_key + " pull")

                    # Update default files and folder from the local GIT repos of CMSs

    def UpdateDefaultFiles(self):
        default_files = [('wordpress', initializer.wp_defaultFiles, initializer.wp_defaultFolders),
                         ('joomla', initializer.joo_defaultFiles, initializer.joo_defaultFolders),
                         ('drupal', initializer.dru_defaultFiles, initializer.dru_defaultFolders),
                         ('moodle', initializer.moo_defaultFiles, initializer.moo_defaultFolders)]
        for cms_type, defaultFiles, defaultFolders in default_files:
            msg = "Updating " + cms_type + " default files"
            self.report.message(msg)
            p = subprocess.Popen("find " + self.cmsmapPath +
                                 "/tmp/" + cms_type + " -type f -name '*.txt' -o -name '*.html' -o -name '*.sql'| sed 's|" + self.cmsmapPath +
                                 "/tmp/" + cms_type + "||g'", stdout=subprocess.PIPE, shell=True,
                                 universal_newlines=True)
            output, error = p.communicate()
            f = open(defaultFiles, "a")
            f.write(output)
            f.close()

            msg = "Updating " + cms_type + " default folders"
            self.report.message(msg)
            p = subprocess.Popen("find " + self.cmsmapPath +
                                 "/tmp/" + cms_type + " -maxdepth 2 -type d | sed 's|" + self.cmsmapPath +
                                 "/tmp/" + cms_type + "||g'", stdout=subprocess.PIPE, shell=True,
                                 universal_newlines=True)
            output, error = p.communicate()
            f = open(defaultFolders, "a")
            f.write(output)
            f.close()
