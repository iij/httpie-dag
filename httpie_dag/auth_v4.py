# -*- coding: utf-8 -*-
"""
DAG authentication (signature version 4) plugin for HTTPie.

"""

import sys
import re
import hmac
import requests
import email
import urllib

from hashlib import sha256
from wsgiref.handlers import format_date_time
from datetime import datetime
from time import mktime
from httpie.plugins import AuthPlugin


class DAGSignatureV4Auth(requests.auth.HTTPBasicAuth):

    service = 'iijgio'

    service_domains = [
        'iijgio.com',
        'amazonaws.com',
    ]

    signing_headers = [
        'content-type',
    ]

    vender_prefixes = [
        'x-iijgio',
        'x-amz',
    ]

    def __call__(self, r):
        """
        See http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
        """
        if r.body is None:
            r.body = ''

        date_header = None
        for vp in self.vender_prefixes:
            date_header = r.headers.get(vp + '-date')
            if date_header:
                break
        if not date_header:
            date_header = r.headers.get('Date')
        if not date_header:
            now = datetime.now()
            date_header = format_date_time(mktime(now.timetuple()))
            r.headers['Date'] = date_header

        url = requests.utils.urlparse(r.url)
        canonical_uri = url.path
        canonical_query = self.get_canonical_query(url.query)
        signed_headers, canonical_headers = self.get_canonical_headers(url.netloc, r.headers)
        payload_hash = sha256(r.body).hexdigest()
        self.print_debug('Payload: %r' % r.body)
        canonical_request = '%s\n%s\n%s\n%s\n%s\n%s' % (
            r.method,
            canonical_uri,
            canonical_query,
            canonical_headers,
            signed_headers,
            payload_hash
        )
        self.print_debug('Canonical Request: %r' % canonical_request)
        algorithm, credential_scope, signing_key = self.get_signing_context(self.password, date_header, url.netloc)
        string_to_sign = '%s\n%s\n%s\n%s' % (
            algorithm,
            date_header,
            credential_scope,
            sha256(canonical_request).hexdigest()
        )
        self.print_debug('String To Sign: %r' % string_to_sign)
        signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), sha256).hexdigest()
        r.headers['Authorization'] = '%s Credential=%s/%s, SignedHeaders=%s, Signature=%s' % (
            algorithm, self.username, credential_scope, signed_headers, signature)
        r.headers['%s-content-sha256' % self.vender_prefixes[0]] = payload_hash
        return r

    def get_canonical_query(self, query):
        canonical_query = ''
        params = []
        for param in query.split('&'):
            if not param:
                continue
            key = param
            value = ''
            if '=' in param:
                key, value = param.split('=')
            params.append('%s=%s' % (key, self.encode_uri(value)))
        params.sort()
        canonical_query = '&'.join(params).encode('utf-8')
        self.print_debug('Canonical Query: %r' % canonical_query)
        return canonical_query

    def get_canonical_headers(self, host, headers):
        canonical_headers = ''
        _headers = {
            'host': [host.strip()]
        }
        for k, v in headers.iteritems():
            _k = k.lower()
            if _k in self.signing_headers:
                _headers[_k] = [v]
                continue
            for vp in self.vender_prefixes:
                if _k.startswith(vp):
                    if _k not in _headers:
                        _headers[_k] = []
                    _headers[_k].append(v)
        signed_headers = sorted(_headers)
        for k in signed_headers:
            canonical_headers += '%s:%s\n' % (k, ','.join(_headers[k]))
        self.print_debug('Canonical Headers: %r, Signed Headers: %r' % (canonical_headers, signed_headers))
        return ';'.join(signed_headers), canonical_headers

    def get_signing_context(self, secret_access_key, date_header, location):
        """
        @return tuple of signing context (ALGORITHM, CREDENTIAL_SCOPE, SIGNING_KEY)
        """
        datestamp = self.parse_date(date_header).strftime('%Y%m%d')
        region, service = self.get_service_info(location)
        algorithm = '%s4-HMAC-SHA256' % self.service.upper()
        sign_text = '%s4_request' % self.service
        key = '%s4%s' % (self.service.upper(), secret_access_key)
        date_hash = self.sign(key.encode('utf-8'), datestamp)
        region_hash = self.sign(date_hash, region)
        service_hash = self.sign(region_hash, service)
        signing_key = self.sign(service_hash, sign_text)
        credential_scope = datestamp + '/' + region +'/' + service +'/' + sign_text
        self.print_debug('Signing Key Sources: datestamp=%s, region=%s, service=%s, sign_text=%s' % (
            datestamp, region, service, sign_text
        ))
        self.print_debug('Credential Scope: %s' % credential_scope)
        return algorithm, credential_scope, signing_key

    def get_service_info(self, location):
        """
        @return tuple of service information (REGION, SERVICE)
        """
        region = 'JP-WEST1'
        r = location.split('.')[-3]
        service = r.split('-')[0]
        return region, service

    def sign(self, key, msg):
        return hmac.new(key, msg.encode('utf-8'), sha256).digest()

    def parse_date(self, s_date):
        return datetime(*email.utils.parsedate(s_date)[:6])

    def encode_uri(self, value):
        return urllib.quote_plus(value)

    @property
    def is_debug(self):
        return '--debug' in sys.argv

    def print_debug(self, text):
        if self.is_debug:
            sys.stderr.write('[httpie-dag] %s\n' % text)


class AWSSignatureV4Auth(DAGSignatureV4Auth):

    service = 'aws'

    service_domains = [
        'amazonaws.com',
    ]

    vender_prefixes = [
        'x-amz',
    ]

    def get_service_info(self, location):
        service = 's3'
        region = 'us-east-1'
        r = location.split('.')[-3]
        m = re.match(r'([^-]+)(-(.+))?', r)
        if m:
            service = m.group(1)
            region = m.group(3) or region
        return region, service


class DAGSignatureV4AuthPlugin(AuthPlugin):

    name = 'DAG Signature Version 4'
    auth_type = 'dag:v4'
    description = 'DAG Signature Version 4 Authentication (Amazon AWS Signature Version 4)'

    def get_auth(self, username, password):
        return DAGSignatureV4Auth(username, password)


class AWSSignatureV4AuthPlugin(AuthPlugin):

    name = 'Amazon AWS Signature Version 4'
    auth_type = 'aws:v4'
    description = 'Amazon AWS Signature Version 4 Authentication (Amazon AWS Signature Version 4)'

    def get_auth(self, username, password):
        return AWSSignatureV4Auth(username, password)
