from __future__ import print_function

from cStringIO import StringIO
import email.utils
import mimetools
import mimetypes
import os
import subprocess
import tempfile
import time
import urllib
import urllib2
import unittest

class RsyncHandler(urllib2.BaseHandler):
    def __init__(self, rsync_path='rsync', rsync_rsh=None):
        self.rsync_path = rsync_path
        self.rsync_rsh = rsync_rsh

    def rsync_rsh_open(self, req):
        host = req.get_host()
        if not host:
            raise urllib2.URLError('rsync+ssh error: not host given')
        if ':' in host:
            raise urllib2.URLError('rsync+ssh error: \':\' character not supported in host')

        path, attrs = urllib.splitattr(req.get_selector())
        if not path:
            raise urllib2.URLError('rsync+ssh error: no path given')

        source = '{}:{}'.format(host, path)
        return self.do_rsync(source, attrs=attrs)

    def rsync_open(self, req):
        source, attrs = urllib.splitattr(req.get_full_url())
        return self.do_rsync(source, attrs=attrs)

    def do_rsync(self, source, attrs=[]):
        options = dict()
        for attr in attrs:
            k,_,v = attr.partition('=')
            options[k] = v
        options.setdefault('rsync_path', self.rsync_path)
        options.setdefault('rsync_rsh', self.rsync_rsh)

        cmd_args = [options['rsync_path'], '-t', '--whole-file']

        if options['rsync_rsh']:
            cmd_args.extend(('-e', options['rsync_rsh']))

        destination = tempfile.NamedTemporaryFile(prefix='rsync', delete=True)
        destination.file.close()

        cmd_args.extend((source, destination.name))

        stderr = tempfile.TemporaryFile()
        try:
            subprocess.check_call(cmd_args, stderr=stderr)
        except subprocess.CalledProcessError as e:
            stderr.seek(0)
            raise urllib2.URLError('rsync error: {}'.format(stderr.read()))

        destination.file = open(destination.name)

        headers = StringIO()
        mtype = mimetypes.guess_type(destination.name)[0]
        if mtype:
            print ('Content-type: {}'.format(mtype), file=headers)
        print ('Content-length: {:0d}'.format(os.stat(destination.name).st_size), file=headers)
        print ('Last-modified: {}'.format(email.utils.formatdate(os.stat(destination.name).st_mtime, usegmt=True)), file=headers)
        headers.seek(0)

        return urllib.addinfourl(destination, headers, source)

    handler_order = urllib2.UnknownHandler.handler_order - 1
setattr(RsyncHandler, 'rsync+rsh_open', RsyncHandler.rsync_rsh_open)

def install(*args, **kwargs):
    opener = urllib2.build_opener(RsyncHandler(*args, **kwargs))
    urllib2.install_opener(opener)

install()

# TODO test attributes, validity of arguments?
class TestRsyncHandler(unittest.TestCase):
    file_data = 'test\ndata\n'
    fail_url = 'rsync://fail-url'

    def setUp(self):
        self.orig_check_call = subprocess.check_call
        subprocess.check_call = self.fake_check_call

    def tearDown(self):
        subprocess.check_call = self.orig_check_call

    def fake_check_call(self, argv, **kwargs):
        if argv[-2] == TestRsyncHandler.fail_url:
            raise urllib2.URLError('fail url')
        if os.path.exists(argv[-1]):
            open(argv[-1], 'w').write(TestRsyncHandler.file_data)

    def test_urlopen(self):
        fp = urllib2.urlopen('rsync://localhost/test.txt')
        self.assertEqual(fp.read(), TestRsyncHandler.file_data)

    def test_urlopen_user(self):
        fp = urllib2.urlopen('rsync://foo@localhost/test.txt')
        self.assertEqual(fp.read(), TestRsyncHandler.file_data)

    def test_urlopen_fails(self):
        with self.assertRaises(urllib2.URLError):
            urllib2.urlopen(TestRsyncHandler.fail_url)

    def test_rsh(self):
        fp = urllib2.urlopen('rsync+rsh://foo@localhost/test.txt')
        self.assertEqual(fp.read(), TestRsyncHandler.file_data)

    def test_cookiemonster(self):
        handler = RsyncHandler()
        attrs = ['a=b']
        handler.do_rsync('rsync://localhost/test.txt', attrs=attrs)
        self.assertItemsEqual(attrs, ['a=b'])
