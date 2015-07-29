import urllib2
import httplib
import ssl
import socket
import os

_ca_file = '/etc/ssl/certs/ca-certificates.crt'

class HTTPSConnection(httplib.HTTPConnection):
    default_port = httplib.HTTPS_PORT

    def __init__(self, *args, **kwargs):
        httplib.HTTPConnection.__init__(self, *args, **kwargs)

    def connect(self):
        sock = socket.create_connection((self.host, self.port), self.timeout, self.source_address)
        if self._tunnel_host:
            self.sock = sock
            self._tunnel()
        self.sock = ssl.wrap_socket(sock, ca_certs=_ca_file, cert_reqs=ssl.CERT_REQUIRED)

class HTTPSHandler(urllib2.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(HTTPSConnection, req)
    handler_order = urllib2.HTTPSHandler.handler_order - 1
