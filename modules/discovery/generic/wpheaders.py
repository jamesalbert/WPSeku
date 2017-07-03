#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# WPSeku: Wordpress Security Scanner
#
# @url: https://github.com/m4ll0k/WPSeku
# @author: Momo Outaadi (M4ll0k)
#
# WPSeku is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation version 3 of the License.
#
# WPSeku is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with WPSeku; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

from lib import wphttp, wpprint


class wpheaders:
    check = wphttp.check()
    printf = wpprint.wpprint()

    def __init__(self, agent, proxy, redirect, url):
        self.url = url
        self.req = wphttp.wphttp(agent=agent, proxy=proxy, redirect=redirect)

    def run(self):
        self.printf.test("Interesting headers...")
        print("")
        try:
            url = self.check.checkurl(self.url, '')
            r = self.req.send(url)
            if r.headers.get('accept-charset', str()):
                print('Accept-Charset: %s' %
                      (r.headers['accept-charset']))
            if r.headers.get('accept-encoding', str()):
                print('Accept-Encoding: %s' %
                      (r.headers['accept-encoding']))
            if r.headers.get('accept-language', str()):
                print('accept-language: %s' %
                      (r.headers['accept-language']))
            if r.headers.get('accept-ranges', str()):
                print('Accept-Ranges: %s' %
                      (r.headers['accept-ranges']))
            if r.headers.get('access-control-allow-credentials', str()):
                print('Access-Control-Allow-Credentials: %s' %
                      (r.headers['access-control-allow-credentials']))
            if r.headers.get('access-control-allow-headers', str()):
                print('Access-Control-Allow-Headers: %s' %
                      (r.headers['access-control-allow-headers']))
            if r.headers.get('access-control-allow-methods', str()):
                print('Access-Control-Allow-Methods: %s' %
                      (r.headers['access-control-allow-methods']))
            if r.headers.get('access-control-allow-origin', str()):
                print('Access-Control-Allow-Origin: %s' %
                      (r.headers['access-control-allow-origin']))
            if r.headers.get('access-control-expose-headers', str()):
                print('Access-Control-Expose-Headers: %s' %
                      (r.headers['access-control-expose-headers']))
            if r.headers.get('access-control-max-age', str()):
                print('Access-Control-Max-Age: %s' %
                      (r.headers['access-control-max-age']))
            if r.headers.get('age', str()):
                print('Age: %s' % (r.headers['age']))
            if r.headers.get('allow', str()):
                print('Allow: %s' % (r.headers['allow']))
            if r.headers.get('alternates', str()):
                print('Alternates: %s' % (r.headers['alternates']))
            if r.headers.get('authorization', str()):
                print('Authorization: %s' %
                      (r.headers['authorization']))
            if r.headers.get('cache-control', str()):
                print('Cache-Control: %s' %
                      (r.headers['cache-control']))
            if r.headers.get('connection', str()):
                print('Connection: %s' % (r.headers['connection']))
            if r.headers.get('content-encoding', str()):
                print('Content-Encoding: %s' %
                      (r.headers['content-encoding']))
            if r.headers.get('content-language', str()):
                print('Content-Language: %s' %
                      (r.headers['content-language']))
            if r.headers.get('content-length', str()):
                print('Content-Length: %s' %
                      (r.headers['content-length']))
            if r.headers.get('content-location', str()):
                print('Content-Location: %s' %
                      (r.headers['content-location']))
            if r.headers.get('content-md5', str()):
                print('Content-md5: %s' %
                      (r.headers['content-md5']))
            if r.headers.get('content-range', str()):
                print('Content-Range: %s' %
                      (r.headers['content-range']))
            if r.headers.get('content-security-policy', str()):
                print('Content-Security-Policy: %s' %
                      (r.headers['content-security-policy']))
            if r.headers.get('content-security-policy-report-only', str()):
                print('Content-Security-Policy-Report-Only: %s' %
                      (r.headers['content-security-policy-report-only']))
            if r.headers.get('content-type', str()):
                print('Content-Type: %s' %
                      (r.headers['content-type']))
            if r.headers.get('dasl', str()):
                print('Dasl: %s' % (r.headers['dasl']))
            if r.headers.get('date', str()):
                print('Date: %s' % (r.headers['date']))
            if r.headers.get('dav', str()):
                print('Dav: %s' % r.headers.get('dav', str()))
            if r.headers.get('etag', str()):
                print('Etag: %s' % (r.headers['etag']))
            if r.headers.get('from', str()):
                print('From: %s' % (r.headers['from']))
            if r.headers.get('host', str()):
                print('Host: %s' % (r.headers['host']))
            if r.headers.get('keep-alive', str()):
                print('Keep-Alive: %s' % (r.headers['keep-alive']))
            if r.headers.get('last-modified', str()):
                print('Last-Modified: %s' %
                      (r.headers['last-modified']))
            if r.headers.get('location', str()):
                print('Location: %s' % (r.headers['location']))
            if r.headers.get('max-forwards', str()):
                print('Max-Forwards: %s' %
                      (r.headers['max-forwards']))
            if r.headers.get('persistent-auth', str()):
                print('Persistent-Auth: %s' %
                      (r.headers['persistent-auth']))
            if r.headers.get('pragma', str()):
                print('Pragma: %s' % (r.headers['pragma']))
            if r.headers.get('proxy-authenticate', str()):
                print('Proxy-Authenticate: %s' %
                      (r.headers['proxy-authenticate']))
            if r.headers.get('proxy-authorization', str()):
                print('Proxy-Authorization: %s' %
                      (r.headers['proxy-authorization']))
            if r.headers.get('proxy-connection', str()):
                print('Proxy-Connection: %s' %
                      (r.headers['proxy-connection']))
            if r.headers.get('public', str()):
                print('Public: %s' % (r.headers['public']))
            if r.headers.get('range', str()):
                print('Range: %s' % (r.headers['range']))
            if r.headers.get('referer', str()):
                print('Referer: %s' % (r.headers['referer']))
            if r.headers.get('server', str()):
                print('Server: %s' % (r.headers['server']))
            if r.headers.get('set-cookie', str()):
                print('Set-Cookie: %s' % (r.headers['set-cookie']))
            if r.headers.get('status', str()):
                print('Status: %s' % (r.headers['status']))
            if r.headers.get('strict-transport-security', str()):
                print('Strict-Transport-Security: %s' %
                      (r.headers['strict-transport-security']))
            if r.headers.get('transfer-encoding', str()):
                print('Transfer-Encoding: %s' %
                      (r.headers['transfer-encoding']))
            if r.headers.get('upgrade', str()):
                print('Upgrade: %s' % (r.headers['upgrade']))
            if r.headers.get('vary', str()):
                print('Vary: %s' % (r.headers['vary']))
            if r.headers.get('via', str()):
                print('Via: %s' % (r.headers['via']))
            if r.headers.get('warning', str()):
                print('Warning: %s' % (r.headers['warning']))
            if r.headers.get('www-authenticate', str()):
                print('www-Authenticate: %s' %
                      (r.headers['www-authenticate']))
            if r.headers.get('x-content-security-policy', str()):
                print('X-Content-Security-Policy: %s' %
                      (r.headers['x-content-security-policy']))
            if r.headers.get('x-content-type-options', str()):
                print('X-Content-Type-Options: %s' %
                      (r.headers['x-content-type-options']))
            if r.headers.get('x-frame-options', str()):
                print('X-Frame-Options: %s' %
                      (r.headers['x-frame-options']))
            if r.headers.get('x-id', str()):
                print('X-Id: %s' % (r.headers['x-id']))
            if r.headers.get('x-mod-pagespeed', str()):
                print('X-Mod-Pagespeed: %s' %
                      (r.headers['x-mod-pagespeed']))
            if r.headers.get('x-pad', str()):
                print('X-Pad: %s' % (r.headers['x-pad']))
            if r.headers.get('x-page-speed', str()):
                print('X-Page-Speed: %s' %
                      (r.headers['x-page-speed']))
            if r.headers.get('x-permitted-cross-domain-policies', str()):
                print('X-Permitted-Cross-Domain-Policies: %s' %
                      (r.headers['x-permitted-cross-domain-policies']))
            if r.headers.get('x-pingback', str()):
                print('X-Pingback: %s' % (r.headers['x-pingback']))
            if r.headers.get('x-powered-by', str()):
                print('X-Powered-By: %s' %
                      (r.headers['x-powered-by']))
            if r.headers.get('x-robots-tag', str()):
                print('X-Robots-Tag: %s' %
                      (r.headers['x-robots-tag']))
            if r.headers.get('x-ua-compatible', str()):
                print('X-UA-Compatible: %s' %
                      (r.headers['x-ua-compatible']))
            if r.headers.get('x-varnish', str()):
                print('X-Varnish: %s' % (r.headers['x-varnish']))
            if r.headers.get('x-xss-protection', str()):
                print('X-XSS-Protection: %s' %
                      (r.headers['x-xss-protection']))
        except Exception as error:
            pass
        print("")
