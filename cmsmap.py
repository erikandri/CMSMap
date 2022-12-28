#!/usr/bin/python3
import signal
import sys

from cmsmap.lib.report import Report
from cmsmap.main import main


def exit(signum, frame):
    signal.signal(signal.SIGINT, original_sigint)
    report = Report()
    try:
        msg = "Interrupt caught. CMSmap paused. Do you really want to exit?"
        report.error(msg)
        if input("[y/N]: ").lower().startswith('y'):
            msg = "Bye! Quitting.. "
            report.message(msg)
            sys.exit(0)
    except KeyboardInterrupt:
        msg = "Bye! Quitting.."
        report.message(msg)
        sys.exit(0)
    signal.signal(signal.SIGINT, exit)


if __name__ == "__main__":
    original_sigint = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, exit)
    main()
