#! /usr/bin/env python3
import threading

# Import Object
from .requester import Requester


class ThreadScanner(threading.Thread):
    # Implements Multi-Threads
    # self.url = http://mysite.com
    # pluginPath = /wp-content
    # pluginPathEnd = /
    # pluginFound = wptest
    def __init__(self, url, pluginPath, pluginPathEnd, pluginsFound, notExistingCode, notValidLen, q, is_random_user_agent: bool = False):
        threading.Thread.__init__(self)
        self.url = url
        self.q = q
        self.pluginPath = pluginPath
        self.pluginsFound = pluginsFound
        self.pluginPathEnd = pluginPathEnd
        self.notExistingCode = notExistingCode
        self.notValidLen = notValidLen
        self.requester = Requester(is_random_user_agent=is_random_user_agent)

    def run(self):
        while True:
            # Get plugin from plugin queue
            plugin = self.q.get()
            self.requester.request(self.url + self.pluginPath + plugin + self.pluginPathEnd, data=None)
            if self.requester.status_code == 200 and len(self.requester.htmltext) not in self.notValidLen:
                self.pluginsFound.append(plugin)
            elif self.requester.status_code != self.notExistingCode and len(self.requester.htmltext) not in self.notValidLen:
                self.pluginsFound.append(plugin)
            self.q.task_done()
