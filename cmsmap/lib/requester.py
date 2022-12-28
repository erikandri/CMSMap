#! /usr/bin/env python3
import urllib
import urllib.error
import urllib.request
from urllib import parse

import requests
import requests.cookies
from random_user_agent.params import SoftwareName, OperatingSystem
from random_user_agent.user_agent import UserAgent

# Import Objects
from .initialize import initializer


class Requester:
    def __init__(self, is_random_user_agent: bool = False):
        self.response = requests.Response()
        self.url = None
        self.data = None
        self.req = None
        self.htmltext = None
        self.status_code = None
        self.is_random_user_agent = is_random_user_agent
        self.headers = initializer.headers
        self.cookieJar = requests.cookies.RequestsCookieJar()

    @staticmethod
    def generate_user_agent() -> str:
        """Generate random user agent.

        Returns:
            str: user agent with string format.
        """

        # you can also import SoftwareEngine, HardwareType, SoftwareType, Popularity from random_user_agent.params
        # you can also set number of user agents required by providing limit as parameter

        software_names = [SoftwareName.CHROME.value, SoftwareName.FIREFOX.value]
        operating_systems = [OperatingSystem.WINDOWS.value, OperatingSystem.LINUX.value]

        user_agent_rotator = UserAgent(software_names=software_names, operating_systems=operating_systems, limit=100)

        # Get Random User Agent String.
        user_agent = user_agent_rotator.get_random_user_agent()
        return user_agent

    def request(self, url, data):
        self.url = parse.quote_plus(url, safe=':/')
        self.data = data
        if type(data) is dict:
            data = urllib.parse.urlencode(data)
        if data:
            data = data.encode('utf-8')
        if self.is_random_user_agent:
            self.headers["User-Agent"] = self.generate_user_agent()
        try:
            if initializer.nosslcheck:
                self.response = requests.get(url=self.url, data=data, headers=self.headers, verify=False)
            else:
                self.response = requests.get(url=self.url, data=data, headers=self.headers)
            # self.response.raise_for_status()
            self.htmltext = self.response.text
            self.status_code = self.response.status_code
        except requests.RequestException as e:
            self.response = e.response
            self.htmltext = ""
            self.status_code = 404

    def noredirect(self, url, data):
        self.url = parse.quote_plus(url, safe=':/')
        self.data = data
        if type(data) is dict:
            data = urllib.parse.urlencode(data)
        if data:
            data = data.encode('utf-8')
        if self.is_random_user_agent:
            self.headers["User-Agent"] = self.generate_user_agent()
        try:
            if initializer.nosslcheck:
                self.response = requests.get(url=self.url, data=data, headers=self.headers, verify=False, allow_redirects=False)
            else:
                self.response = requests.get(url=self.url, data=data, headers=self.headers, allow_redirects=False)
            # self.response.raise_for_status()
            self.htmltext = self.response.text
            self.status_code = self.response.status_code
        except requests.RequestException as e:
            self.response = e.response
            self.htmltext = ""
            self.status_code = 404

    def requestcookie(self, url, data):
        self.url = parse.quote_plus(url, safe=':/')
        self.data = data
        if type(data) is dict:
            data = urllib.parse.urlencode(data)
        if data:
            data = data.encode('utf-8')
        if self.is_random_user_agent:
            self.headers["User-Agent"] = self.generate_user_agent()
        try:
            if initializer.nosslcheck:
                self.response = requests.get(url=self.url, data=data, headers=self.headers, cookies=self.cookieJar, verify=False)
            else:
                self.response = requests.get(url=self.url, data=data, headers=self.headers, cookies=self.cookieJar)
            # self.response.raise_for_status()
            self.htmltext = self.response.text
            self.status_code = self.response.status_code
        except requests.RequestException as e:
            self.response = e.response
            self.htmltext = ""
            self.status_code = 404
