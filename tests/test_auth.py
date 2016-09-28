from unittest import TestCase
from nose.tools import ok_, eq_
from httpie_dag.auth import DAGAuthPlugin, DAGSignatureV2Auth
import requests


class AuthTestCase(TestCase):
    username = 'TestUser'
    password = 'TestPassword'
    test_url = 'http://example.com/'
    test_obj = 'test.txt'
    test_md5 = 'd8e8fca2dc0f896fd7cb4cb0031ba249'
    test_content = 'text/plain'

    def test_get_auth(self):
        dag = DAGAuthPlugin()
        ok_(isinstance(dag.get_auth(self.username, self.password),
                       DAGSignatureV2Auth))

    def test_call(self):
        dag = DAGAuthPlugin()
        r = requests.Request('GET', self.test_url)
        r.headers['Date'] = 'Mon, 06 Jul 2015 01:37:01 GMT'

        r = dag.get_auth(self.username, self.password)(r)
        eq_(r.headers['Authorization'],
            u'IIJGIO TestUser:lXiYhYt11eMa6/+qzPMMUKld9qM=')

    def test_no_date(self):
        dag = DAGAuthPlugin()
        r = requests.Request('GET', self.test_url)
        r.headers['Date'] = ''

        r = dag.get_auth(self.username, self.password)(r)
        ok_('Date' in r.headers)

    def test_no_content_header(self):
        dag = DAGAuthPlugin()
        r = requests.Request('PUT', self.test_url + self.test_obj)
        r.headers['Date'] = 'Mon, 06 Jul 2015 01:37:02 GMT'

        r = dag.get_auth(self.username, self.password)(r)
        eq_(r.headers['Authorization'],
            u'IIJGIO TestUser:I1ff1obNeASRU2YbKT2GkJ2SpVM=')

    def test_content_header(self):
        dag = DAGAuthPlugin()
        r = requests.Request('PUT', self.test_url + self.test_obj)
        r.headers['Date'] = 'Mon, 06 Jul 2015 01:37:02 GMT'
        r.headers['Content-MD5'] = self.test_md5
        r.headers['Content-Type'] = self.test_content

        r = dag.get_auth(self.username, self.password)(r)
        eq_(r.headers['Authorization'],
            u'IIJGIO TestUser:3UMLj21ULyfwG41LdCciw8KIPFU=')

    def test_canonicalized_header_date(self):
        dag = DAGAuthPlugin()
        r = requests.Request('GET', self.test_url)
        r.headers['Date'] = 'Mon, 06 Jul 2015 01:37:02 GMT'
        r.headers['x-iijgio-date'] = 'Thu, 02 Jul 2015 00:52:03 GMT'

        r = dag.get_auth(self.username, self.password)(r)
        eq_(r.headers['Authorization'],
            u'IIJGIO TestUser:Rtrgbymmx31NRzNwJk6+/6qwo8s=')

    def test_canonicalized_header_capital(self):
        dag = DAGAuthPlugin()
        r = requests.Request('PUT', self.test_url + self.test_obj)
        r.headers['Date'] = 'Mon, 06 Jul 2015 01:37:03 GMT'
        r.headers['x-iIjgio-Meta-test'] = 'test'

        r = dag.get_auth(self.username, self.password)(r)
        eq_(r.headers['Authorization'],
            u'IIJGIO TestUser:wn0Sd/Auvn6TvH6lECGVihjS1BE=')

    def test_canonicalized_header_amz_sort(self):
        dag = DAGAuthPlugin()
        r = requests.Request('PUT', self.test_url + self.test_obj)
        r.headers['Date'] = 'Mon, 06 Jul 2015 01:37:03 GMT'
        r.headers['x-iijgio-meta-d'] = '4'
        r.headers['x-iijgio-meta-a'] = '3'
        r.headers['x-amz-meta-a'] = '1'
        r.headers['x-amz-meta-c'] = '2'

        r = dag.get_auth(self.username, self.password)(r)
        eq_(r.headers['Authorization'],
            u'IIJGIO TestUser:QQGxJrACBnATAQzLE22JSFruJcg=')

    def test_canonicalized_header_replace_whitespace_pre_value(self):
        dag = DAGAuthPlugin()
        r = requests.Request('PUT', self.test_url + self.test_obj)
        r.headers['Date'] = 'Fri, 10 Jul 2015 12:19:24 GMT'
        r.headers['x-iIjgio-Meta-test'] = '  test'

        r = dag.get_auth(self.username, self.password)(r)
        eq_(r.headers['Authorization'],
            u'IIJGIO TestUser:48Zkjs2mbSfQlQMKCXffGSW+lJ8=')

    def test_canonicalized_header_replace_whitespace_post_value(self):
        dag = DAGAuthPlugin()
        r = requests.Request('PUT', self.test_url + self.test_obj)
        r.headers['Date'] = 'Fri, 10 Jul 2015 12:35:19 GMT'
        r.headers['x-iIjgio-Meta-test'] = 'test\t '

        r = dag.get_auth(self.username, self.password)(r)
        eq_(r.headers['Authorization'],
            u'IIJGIO TestUser:UfGAbBFv+gmNk7b1NWusbURDhWE=')

    def test_canonicalized_header_replace_whitespace_post_name(self):
        dag = DAGAuthPlugin()
        r = requests.Request('PUT', self.test_url + self.test_obj)
        r.headers['Date'] = 'Fri, 10 Jul 2015 12:19:25 GMT'
        r.headers['x-iIjgio-Meta-test\t\t'] = 'test'

        r = dag.get_auth(self.username, self.password)(r)
        eq_(r.headers['Authorization'],
            u'IIJGIO TestUser:Z13UQybPnJ1TmjtrwTD7TjXAM58=')

    def test_canonicalized_header_replace_whitespace_post_name_pre_value(self):
        dag = DAGAuthPlugin()
        r = requests.Request('PUT', self.test_url + self.test_obj)
        r.headers['Date'] = 'Fri, 10 Jul 2015 12:41:35 GMT'
        r.headers['x-iIjgio-Meta-test \t'] = '  test'

        r = dag.get_auth(self.username, self.password)(r)
        eq_(r.headers['Authorization'],
            u'IIJGIO TestUser:+nRY7FuKp5VVTTIS0ndU7aBknXI=')

    def test_canonicalized_header_donot_replace_whitespace_in_value(self):
        dag = DAGAuthPlugin()
        r = requests.Request('PUT', self.test_url + self.test_obj)
        r.headers['Date'] = 'Wed, 15 Jul 2015 02:35:09 GMT'
        r.headers['x-iIjgio-Meta-test'] = 'te\t st'

        r = dag.get_auth(self.username, self.password)(r)
        eq_(r.headers['Authorization'],
            u'IIJGIO TestUser:Q+49W7P5PmUeTGSQhdTN5OvO5fo=')

    def test_canonicalized_resource_undecorded_uri(self):
        dag = DAGAuthPlugin()
        r = requests.Request('PUT', self.test_url +
                             '%E3%83%86%E3%82%B9%E3%83%88.txt')
        r.headers['Date'] = 'Mon, 06 Jul 2015 01:50:37 GMT'

        r = dag.get_auth(self.username, self.password)(r)
        eq_(r.headers['Authorization'],
            u'IIJGIO TestUser:+e4O77tMMmSHjVQQUeVE0Xiiinw=')

    def test_canonicalized_resource_subresource(self):
        dag = DAGAuthPlugin()
        r = requests.Request('GET', self.test_url + self.test_obj + '?acl')
        r.headers['Date'] = 'Mon, 06 Jul 2015 01:37:04 GMT'

        r = dag.get_auth(self.username, self.password)(r)
        eq_(r.headers['Authorization'],
            u'IIJGIO TestUser:JeuotgmkqjFHgedpnZ7r2KmKsPM=')

    def test_canonicalized_resource_overriding_response_header(self):
        dag = DAGAuthPlugin()
        r = requests.Request('GET', self.test_url + self.test_obj +
                             '?response-cache-control=No-cache&response-content-disposition=attachment%3B%20filename%3Dtesting.txt&response-content-encoding=x-gzip&response-content-language=mi%2C%20en&response-expires=Thu%2C%2001%20Dec%201994%2016:00:00%20GMT')
        r.headers['Date'] = 'Mon, 06 Jul 2015 01:37:04 GMT'

        r = dag.get_auth(self.username, self.password)(r)
        eq_(r.headers['Authorization'],
            u'IIJGIO TestUser:TerzZVu/k5C84P86hPLc4SfjLKc=')

#
"""
source commands
alias httptest="http -v --verify no --auth TestUser:TestPassword --auth-type dag"
httptest GET http://example.com/ > output/call
httptest PUT http://example.com/test.txt > output/no_content_header
httptest PUT http://example.com/test.txt Content-MD5:d8e8fca2dc0f896fd7cb4cb0031ba249 Content-Type:text/plain >output/content_header
httptest GET http://example.com/ x-iijgio-date:'Thu, 02 Jul 2015 00:52:03 GMT' > output/canonicalized_header_date
httptest PUT http://example.com/test.txt x-iIjgio-Meta-test:'test' > output/canonicalized_header_capital
httptest PUT http://example.com/test.txt x-iijgio-meta-d:4 x-iijgio-meta-a:3 x-amz-meta-c:2 x-amz-meta-a:1 > output/canonicalized_header_amz_sort
httptest PUT http://example.com/test.txt "x-iijgio-meta-test:  test" > output/canonicalized_header_replace_whitespace_pre_value
httptest PUT http://example.com/test.txt "x-iijgio-meta-test:test        " > output/canonicalized_header_replace_whitespace_post_value
httptest PUT http://example.com/test.txt "x-iijgio-meta-test         :test" > output/canonicalized_header_replace_whitespace_post_name
httptest PUT http://example.com/test.txt "x-iijgio-meta-test    :  test" > output/canonicalized_header_replace_whitespace_post_name_pre_value
httptest PUT http://example.com/test.txt "x-iijgio-meta-test:te     st" > output/canonicalized_header_donot_replace_whitespace_in_value
httptest PUT http://example.com/\"tesuto\".txt > output/canonicalized_resource_undecorded_uri (\"tesuto is KATAKANA\")
httptest GET http://example.com/test.txt\?acl > output/canonicalized_resource_subresource
httptest GET http://example.com/test.txt\?'response-cache-control=No-cache&response-content-disposition=attachment%3B%20filename%3Dtesting.txt&response-content-encoding=x-gzip&response-content-language=mi%2C%20en&response-expires=Thu%2C%2001%20Dec%201994%2016:00:00%20GMT' > output/canonicalized_resource_overriding_response_header
"""
#
