# -*- coding: utf-8 -*-
"""
DAG authentication plugin for HTTPie.
"""

import sys
import re
import hmac
import requests
import urllib

from hashlib import sha1
from wsgiref.handlers import format_date_time
from datetime import datetime
from time import mktime
from httpie.plugins import AuthPlugin
import base64


class DAGSignatureV2Auth(requests.auth.HTTPBasicAuth):
    """DAGSignatureV2Auth return to calculate signature v2"""

    service = 'iijgio'

    canonical_resource_keys = [
        # sub-resource
        'acl', 'location', 'partNumber', 'policy', 'uploadId', 'uploads',
        'cors', 'delete', 'space', 'traffic', 'website',
        # for analysis
        'clusterManagement', 'query', 'database', 'table', 'select', 'split',
        # GET request parameters
        'response-content-type',
        'response-content-language',
        'response-expires',
        'response-cache-control',
        'response-content-disposition',
        'response-content-encoding'
    ]

    service_domains = [
        r'(.+)\..*-dag.*\.iijgio\.com',
        r'(.+)\.gss.*\.iijgio\.com',
    ]

    vender_prefixes = [
        'x-iijgio',
        'x-amz'
    ]

    def __call__(self, r):
        """
        See https://docs.website-dag.iijgio.com/storage/api.html#id1
        """
        verb = r.method

        url = requests.utils.urlparse(r.url)
        canonicalized_headers = self.get_canonicalized_headers(r.headers)
        canonicalized_resource = self.get_canonicalized_resource(url, r.headers.get('Host'))

        date = None
        user_meta_date = False
        for vp in self.vender_prefixes:
            date = r.headers.get(vp + '-date')
            if date:
                user_meta_date = True
                break
        if not date:
            date = r.headers.get('Date')
        if not date:
            now = datetime.now()
            r.headers['Date'] = format_date_time(mktime(now.timetuple()))

        string_to_sign = ('%s\n%s\n%s\n%s\n%s%s' % (
            verb,
            r.headers.get('Content-MD5', ''),
            r.headers.get('Content-Type', ''),
            '' if user_meta_date else r.headers.get('Date', ''),
            canonicalized_headers,
            canonicalized_resource
        )).encode('utf-8')
        self.print_debug('String To Sign: %r' % string_to_sign)

        signature = '%s %s:%s' % (
            self.service.upper(),
            self.username,
            base64.b64encode(hmac.new(self.password.encode('latin-1'),
                string_to_sign, sha1).digest()).decode('ascii')
        )
        self.print_debug('Signature: %r' % signature)
        r.headers['Authorization'] = signature
        return r

    def get_canonicalized_headers(self, headers):
        canonicalized_headers = ''
        _headers = {}
        for k, v in headers.items():
            _k = k.lower().rstrip()
            for vp in self.vender_prefixes:
                if _k.startswith(vp):
                    if _k not in _headers:
                        _headers[_k] = []
                    _headers[_k].append(v.strip())
        for k in sorted(_headers):
            canonicalized_headers += '%s:%s\n' % (k, ','.join(_headers[k]))
        self.print_debug('Canonicalized Headers: %r' % canonicalized_headers)
        return canonicalized_headers

    def get_canonicalized_resource(self, url, host):
        if not host:
            host = url.netloc
        canonicalized_resource = ''
        for d in self.service_domains:
            m = re.match(d, host)
            if m and len(m.groups()) > 0:
                canonicalized_resource += '/' + m.group(1)
                break
        canonicalized_resource += url.path
        params = []
        for param in url.query.split('&'):
            key = param
            value = ''
            if '=' in param:
                key, value = param.split('=')
            if key in self.canonical_resource_keys:
                if not value:
                    params.append(key)
                else:
                    params.append('%s=%s' % (key, value))
        if len(params) > 0:
            params.sort()
            canonicalized_resource += '?%s' % '&'.join(params)
        self.print_debug('Canonicalized Resource: %r' % canonicalized_resource)
        return canonicalized_resource

    @staticmethod
    def encode_uri(value):
        return urllib.quote_plus(value)

    @property
    def is_debug(self):
        return '--debug' in sys.argv

    def print_debug(self, text):
        if self.is_debug:
            sys.stderr.write('[httpie-dag] %s\n' % text)


class AWSSignatureV2Auth(DAGSignatureV2Auth):

    service = 'aws'

    canonical_resource_keys = [
        # sub-resource
        'acl', 'location', 'partNumber', 'policy', 'uploadId', 'uploads', 'cors', 'delete',
        'versioning', 'lifecycle', 'versionId', 'versions', 'logging', 'tagging', 'requestPayment',
        'notification', 'torrent', 'website',
        # GET request parameters
        'response-content-type',
        'response-content-language',
        'response-expires',
        'response-cache-control',
        'response-content-disposition',
        'response-content-encoding'
    ]

    service_domains = [
        r'(.+)\..*\.amazonaws\.com',
    ]

    vender_prefixes = [
        'x-amz',
    ]


class DAGAuthPlugin(AuthPlugin):

    name = 'DAG Authentication'
    auth_type = 'dag'
    description = 'DAG Authentication (Amazon AWS Signature Version 2)'

    def get_auth(self, username, password):
        return DAGSignatureV2Auth(username, password)


class AWSAuthPlugin(AuthPlugin):

    name = 'Amazon AWS Authentication'
    auth_type = 'aws'
    description = 'Amazon AWS Authentication (Signature Version 2)'

    def get_auth(self, username, password):
        return AWSSignatureV2Auth(username, password)
