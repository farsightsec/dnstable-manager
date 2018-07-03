# Copyright (c) 2015 by Farsight Security, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import urllib2
import httplib
import logging
import socket

logger = logging.getLogger(__name__)

try:
    import ssl
    ssl.CertificateError
except AttributeError:
    logger.debug('Using backported ssl.py')
    import backported.ssl as ssl

ca_file = '/etc/ssl/certs/ca-certificates.crt'
keyfile = None
certfile = None
ciphers = 'EECDH+ECDSA+AESGCM:EECDH+aRSA+AESGCM:EECDH+ECDSA+SHA384:EECDH+ECDSA+SHA256:EECDH+aRSA+SHA384:EECDH+aRSA+SHA256:!EECDH+aRSA+RC4:EECDH:EDH+aRSA:!RC4:!aNULL:!eNULL:!LOW:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS:@STRENGTH'

class HTTPSConnection(httplib.HTTPConnection):
    default_port = httplib.HTTPS_PORT

    def __init__(self, *args, **kwargs):
        httplib.HTTPConnection.__init__(self, *args, **kwargs)

    def connect(self):
        try:
            sock = socket.create_connection((self.host, self.port), self.timeout, self.source_address)
        except socket.error as e:
            raise urllib2.URLError(e)
        if self._tunnel_host:
            self.sock = sock
            self._tunnel()
        try:
            self.sock = ssl.wrap_socket(sock, ssl_version=ssl.PROTOCOL_TLSv1,
                    ca_certs=ca_file, cert_reqs=ssl.CERT_REQUIRED,
                    keyfile=keyfile, certfile=certfile, ciphers=ciphers)
        except (ssl.SSLError, ssl.CertificateError, socket.error) as e:
            raise urllib2.URLError(e)

class HTTPSHandler(urllib2.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(HTTPSConnection, req)
    handler_order = urllib2.HTTPSHandler.handler_order - 1
