#! /usr/bin/env python3
import urllib
import urllib.error
import urllib.request
from urllib import parse

import requests
import requests.cookies

# Import Objects
from .initialize import initializer


class Requester:
    def __init__(self):
        self.response = requests.Response()
        self.url = None
        self.data = None
        self.req = None
        self.htmltext = None
        self.status_code = None
        self.headers = initializer.headers
        self.cookieJar = requests.cookies.RequestsCookieJar()

    def request(self, url, data):
        self.url = parse.quote_plus(url, safe=':/')
        self.data = data
        if type(data) is dict:
            data = urllib.parse.urlencode(data)
        if data:
            data = data.encode('utf-8')
        try:
            if initializer.nosslcheck:
                self.response = requests.get(url=self.url, data=data, headers=self.headers, verify=False)
            else:
                self.response = requests.get(url=self.url, data=data, headers=self.headers)
            self.response.raise_for_status()
            self.htmltext = self.response.text
            self.status_code = self.response.status_code
        except requests.RequestException as e:
            self.response = e.response
            self.htmltext = self.response.text
            self.status_code = self.response.status_code

    def noredirect(self, url, data):
        self.url = parse.quote_plus(url, safe=':/')
        self.data = data
        if type(data) is dict:
            data = urllib.parse.urlencode(data)
        if data:
            data = data.encode('utf-8')
        try:
            if initializer.nosslcheck:
                self.response = requests.get(url=self.url, data=data, headers=self.headers, verify=False, allow_redirects=False)
            else:
                self.response = requests.get(url=self.url, data=data, headers=self.headers, allow_redirects=False)
            self.response.raise_for_status()
            self.htmltext = self.response.text
            self.status_code = self.response.status_code
        except requests.RequestException as e:
            self.response = e.response
            self.htmltext = self.response.text
            self.status_code = self.response.status_code

    def requestcookie(self, url, data):
        self.url = parse.quote_plus(url, safe=':/')
        self.data = data
        if type(data) is dict:
            data = urllib.parse.urlencode(data)
        if data:
            data = data.encode('utf-8')
        try:
            if initializer.nosslcheck:
                self.response = requests.get(url=self.url, data=data, headers=self.headers, cookies=self.cookieJar, verify=False)
            else:
                self.response = requests.get(url=self.url, data=data, headers=self.headers, cookies=self.cookieJar)
            self.response.raise_for_status()
            self.htmltext = self.response.text
            self.status_code = self.response.status_code
        except requests.RequestException as e:
            self.response = e.response
            self.htmltext = self.response.text
            self.status_code = self.response.status_code


requester = Requester()
