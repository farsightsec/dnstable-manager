from __future__ import print_function

from cStringIO import StringIO
import email.utils
import httplib
import logging
import mimetypes
import os
import pipes
import subprocess
import tempfile
import urllib
import urllib2
import unittest

logger = logging.getLogger(__name__)

class RsyncHandler(urllib2.BaseHandler):
    def __init__(self, rsync_path='rsync', rsync_rsh=None, tmpdir=None):
        self.rsync_path = rsync_path
        self.rsync_rsh = rsync_rsh
        self.tmpdir = tmpdir

    def rsync_rsh_open(self, req):
        logger.debug('Opening rsync+rsh')
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
        logger.debug('Opening rsync')
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

        fn = source.rpartition('/')[2]
        tf = tempfile.mktemp(prefix='rsync--{}.'.format(fn), dir=self.tmpdir)

        cmd_args.extend((source, tf))
        logger.debug('Callling {}'.format(' '.join(map(pipes.quote, cmd_args))))

        stderr = tempfile.TemporaryFile(dir=self.tmpdir)
        try:
            subprocess.check_call(cmd_args, stderr=stderr)

            tf_stat = os.stat(tf)
            fp = open(tf)
        except subprocess.CalledProcessError:
            stderr.seek(0)
            raise urllib2.URLError('rsync error: {}'.format(stderr.read()))
        finally:
            try:
                os.unlink(tf)
            except OSError as e:
                logger.error('Error unlinking {}: {}'.format(tf, e))

        headers = StringIO()
        mtype = mimetypes.guess_type(source)[0]
        if mtype:
            print ('Content-type: {}'.format(mtype), file=headers)
        logger.debug('Content-type: {}'.format(mtype))

        print ('Content-length: {:0d}'.format(tf_stat.st_size), file=headers)
        logger.debug('Content-length: {:0d}'.format(tf_stat.st_size))

        print ('Last-modified: {}'.format(email.utils.formatdate(tf_stat.st_mtime, usegmt=True)), file=headers)
        logger.debug('Last-modified: {}'.format(email.utils.formatdate(tf_stat.st_mtime, usegmt=True)))

        headers.seek(0)
        msg = httplib.HTTPMessage(fp=headers, seekable=True)

        return urllib.addinfourl(fp, msg, source)

    handler_order = urllib2.UnknownHandler.handler_order - 1
setattr(RsyncHandler, 'rsync+rsh_open', RsyncHandler.rsync_rsh_open)

def install(*args, **kwargs):
    logger.debug('Installing RsyncHandler')
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
        if not os.path.exists(argv[-1]):
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
