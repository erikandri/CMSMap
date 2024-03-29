#!/usr/bin/python3
import argparse
import datetime
import os
import socket
import sys
import time
import urllib
import urllib.error
import urllib.request
from argparse import RawTextHelpFormatter
from urllib.parse import urlparse

import requests

from .lib.bruteforcer import BruteForcer
from .lib.coreupdate import CoreUpdate
from .lib.exploitdbsearch import ExploitDBSearch
from .lib.genericchecks import GenericChecks
from .lib.initialize import initializer
from .lib.postexploit import PostExploit
from .lib.report import Report
from .lib.scanner import Scanner
from .version import __version__


def main():
    report = Report()
    # command line arguments

    if sys.argv[1:]:
        examples = """Examples:
  cmsmap.py https://example.com
  cmsmap.py https://example.com -f W -F --noedb -d
  cmsmap.py https://example.com -i targets.txt -o output.txt
  cmsmap.py https://example.com -u admin -p passwords.txt
  cmsmap.py -k hashes.txt -w passwords.txt
        """
        try:
            parser = argparse.ArgumentParser(
                description="CMSmap tool v" + str(__version__) + " - Simple CMS Scanner\nAuthor: Mike Manzotti\nUpdated By: Erik Andri Budiman",
                formatter_class=RawTextHelpFormatter,
                add_help=False,
                epilog=examples)
            # Groups
            argsscan = parser.add_argument_group("Scan")
            argsbrute = parser.add_argument_group("Brute-Force")
            argspostexp = parser.add_argument_group("Post Exploitation")
            argsothers = parser.add_argument_group("Others")
            # Scan Arguments
            argsscan.add_argument("target", help="target URL (e.g. 'https://example.com:8080/')", nargs='?')
            argsscan.add_argument("-f", "--force", help="force scan (W)ordpress, (J)oomla or (D)rupal or (M)oodle", metavar="W/J/D/M", default=None)
            argsscan.add_argument("-F", "--fullscan", help="full scan using large plugin lists. False positives and slow!", action="store_true", default=False)
            argsscan.add_argument("-t", "--threads", help="number of threads (Default 5)", metavar="", default=5)
            argsscan.add_argument("-a", "--agent", help="set custom user-agent", metavar="", default=False)
            argsscan.add_argument("--random-user-agent", action="store_true", help="enable random user-agent for each request", default=False)
            argsscan.add_argument("-H", "--header", help="add custom header (e.g. 'Authorization: Basic ABCD...')", metavar="")
            argsscan.add_argument("-i", "--input", help="scan multiple targets listed in a given file", metavar="")
            argsscan.add_argument("-o", "--output", help="save output in a file", metavar="")
            argsscan.add_argument("-E", "--noedb", help="enumerate plugins without searching exploits", action="store_true", default=False)
            argsscan.add_argument("-c", "--nocleanurls", help="disable clean urls for Drupal only", action="store_true", default=False)
            argsscan.add_argument("-s", "--nosslcheck", help="don't validate the server's certificate", action="store_true", default=False)
            argsscan.add_argument("-d", "--dictattack", help="run low intense dictionary attack during scanning (5 attempts per user)", action="store_true", default=False)
            # Brute-Force Arguments
            argsbrute.add_argument("-u", "--usr", help="username or username file", metavar="")
            argsbrute.add_argument("-p", "--psw", help="password or password file", metavar="")
            argsbrute.add_argument("-x", "--noxmlrpc", help="brute forcing WordPress without XML-RPC", action="store_false", default=True)
            # Post Exploitation Arguments
            argspostexp.add_argument("-k", "--crack", help="password hashes file (Require hashcat installed. For WordPress and Joomla only)", metavar="")
            argspostexp.add_argument("-w", "--wordlist", help="wordlist file", metavar="")
            # Others Arguments
            argsothers.add_argument("-v", "--verbose", help="verbose mode (Default false)", action="store_true", default=False)
            argsothers.add_argument("-h", "--help", help="show this help message and exit", action="help")
            argsothers.add_argument("-D", "--default", help="run CMSmap with default options", action="store_true", default=False)
            argsothers.add_argument("-U", "--update", help="use (C)MSmap, (P)lugins or (PC) for both", metavar="")
            argsothers.add_argument("--color", action="store_true", help="use color for ouput stdout", default=False)
            args = parser.parse_args()
        except Exception as e:
            print(f"EXCEPTION: {e}")
            sys.exit(1)

    else:
        msg = "No options provided. Run " + os.path.basename(sys.argv[0]) + " -h for help"
        report.error(msg)
        sys.exit(1)

    report = Report(color=args.color)
    postexploiter = PostExploit(is_color=args.color)
    updater = CoreUpdate(is_color=args.color)
    searcher = ExploitDBSearch(is_color=args.color, url=args.target)
    bruter = BruteForcer(is_random_user_agent=args.random_user_agent, is_color=args.color, url=args.target)
    scanner = Scanner(is_random_user_agent=args.random_user_agent, is_color=args.color, url=args.target)
    genericchecker = GenericChecks(is_random_user_agent=args.random_user_agent, is_color=args.color, url=args.target)
    initializer.verbose = args.verbose
    initializer.url = args.target
    initializer.threads = args.threads
    initializer.BruteForcingAttack = bruter.usrlist = args.usr
    initializer.CrackingPasswords = hashfile = args.crack
    initializer.wordlist = args.wordlist
    initializer.threads = int(args.threads)
    initializer.output = report.fn = args.output
    initializer.forceCMSmapUpdate = args.update
    initializer.FullScan = args.fullscan
    initializer.NoExploitdb = args.noedb
    initializer.disableCleanURLs = args.nocleanurls
    initializer.nosslcheck = args.nosslcheck
    initializer.default = args.default
    scanner.url = args.target
    scanner.file = args.input
    scanner.force = args.force
    bruter.wpnoxmlrpc = args.noxmlrpc
    bruter.dictattack = args.dictattack
    bruter.pswlist = args.psw

    if args.header:
        initializer.headers.update({
            args.header.split(":")[0]:
                args.header.split(":")[1]
        })

    start = time.time()
    msg = "Date & Time: " + time.strftime('%d/%m/%Y %H:%M:%S')
    report.status(msg)

    if not initializer.NoExploitdb:
        updater.UpdateExploitDB()
    updater.CheckLocalFiles()

    if initializer.forceCMSmapUpdate:
        updater.forceCMSmapUpdate()
    elif initializer.BruteForcingAttack:
        if scanner.file is not None:
            targets = [line.strip() for line in open(scanner.file, encoding='utf-8')]
        else:
            targets = [args.target]
        for url in targets:
            if url.endswith("/"):
                url = url[:-1]
            try:
                searcher = ExploitDBSearch(is_color=args.color, url=args.target)
                bruter = BruteForcer(is_random_user_agent=args.random_user_agent, is_color=args.color, url=args.target)
                scanner = Scanner(is_random_user_agent=args.random_user_agent, is_color=args.color, url=args.target)
                genericchecker = GenericChecks(is_random_user_agent=args.random_user_agent, is_color=args.color, url=args.target)
                initializer.url = genericchecker.url = scanner.url = bruter.url = searcher.url = url
                addr = socket.gethostbyname(urlparse(url).hostname)
                msg = "Target: " + scanner.url + " (" + addr + ")"
                report.status(msg)
                if scanner.force is None:
                    scanner.FindCMSType()
                else:
                    bruter.force = scanner.force
                    bruter.Start()
            except urllib.error.HTTPError or urllib.error.URLError as e:
                msg = "Unable to scan: " + scanner.url
                report.error(msg)
                report.error(str(e.reason))
            except socket.gaierror as e:
                msg = "Unable to resolve: " + scanner.url
                report.error(msg)
                msg = str(e)
                report.error(msg)
    elif initializer.CrackingPasswords:
        postexploiter.CrackingHashesType(hashfile, initializer.wordlist)
    elif scanner.file is not None:
        targets = [line.strip() for line in open(scanner.file, encoding='utf-8')]
        for url in targets:
            if url.endswith("/"):
                url = url[:-1]
            try:
                searcher = ExploitDBSearch(is_color=args.color, url=args.target)
                bruter = BruteForcer(is_random_user_agent=args.random_user_agent, is_color=args.color, url=args.target)
                scanner = Scanner(is_random_user_agent=args.random_user_agent, is_color=args.color, url=args.target)
                genericchecker = GenericChecks(is_random_user_agent=args.random_user_agent, is_color=args.color, url=args.target)
                initializer.url = genericchecker.url = scanner.url = bruter.url = searcher.url = url
                addr = socket.gethostbyname(urlparse(url).hostname)
                msg = "Threads: " + str(initializer.threads)
                report.info(msg)
                msg = "Target: " + scanner.url + " (" + addr + ")"
                report.status(msg)
                scanner.RunScanner()
            except urllib.error.HTTPError or urllib.error.URLError as e:
                msg = "Unable to scan: " + scanner.url
                report.error(msg)
                report.error(str(e.reason))
            except socket.gaierror as e:
                msg = "Unable to resolve: " + scanner.url
                report.error(msg)
                msg = str(e)
                report.error(msg)
    else:
        if args.target.endswith("/"):
            args.target = args.target[:-1]
        try:
            hostname = str(urlparse(url=args.target).hostname)
            addr = socket.gethostbyname(hostname)
            initializer.url = genericchecker.url = scanner.url = bruter.url = searcher.url = args.target
            msg = "Threads: " + str(initializer.threads)
            report.info(msg)
            msg = "Target: " + scanner.url + " (" + addr + ")"
            report.status(msg)
            scanner.RunScanner()
        except requests.RequestException as e:
            msg = "Unable to scan: " + scanner.url
            report.error(msg)
            for arg in e.args:
                report.error(str(arg.reason))
        except socket.gaierror as e:
            msg = "Unable to resolve: " + scanner.url
            report.error(msg)
            msg = str(e)
            report.error(msg)

    end = time.time()
    diffTime = end - start
    msg = "Date & Time: " + time.strftime('%d/%m/%Y %H:%M:%S')
    report.status(msg)
    msg = "Completed in: " + str(datetime.timedelta(seconds=diffTime)).split(".")[0]
    report.status(msg)
    if initializer.output:
        msg = "Output File Saved in: " + report.fn
        report.status(msg)
