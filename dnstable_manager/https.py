import urllib2
import httplib
import ssl
import socket
import os

ca_file = '/etc/ssl/certs/ca-certificates.crt'
keyfile = None
certfile = None
ciphers = 'EECDH+ECDSA+AESGCM:EECDH+aRSA+AESGCM:EECDH+ECDSA+SHA384:EECDH+ECDSA+SHA256:EECDH+aRSA+SHA384:EECDH+aRSA+SHA256:!EECDH+aRSA+RC4:EECDH:EDH+aRSA:!RC4:!aNULL:!eNULL:!LOW:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS:@STRENGTH'

class HTTPSConnection(httplib.HTTPConnection):
    default_port = httplib.HTTPS_PORT

    def __init__(self, *args, **kwargs):
        httplib.HTTPConnection.__init__(self, *args, **kwargs)

    def connect(self):
        sock = socket.create_connection((self.host, self.port), self.timeout, self.source_address)
        if self._tunnel_host:
            self.sock = sock
            self._tunnel()
        self.sock = ssl.wrap_socket(sock, ssl_version=ssl.PROTOCOL_TLSv1,
                ca_certs=ca_file, cert_reqs=ssl.CERT_REQUIRED,
                keyfile=keyfile, certfile=certfile, ciphers=ciphers)

class HTTPSHandler(urllib2.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(HTTPSConnection, req)
    handler_order = urllib2.HTTPSHandler.handler_order - 1
