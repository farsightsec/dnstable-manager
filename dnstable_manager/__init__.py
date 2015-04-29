from __future__ import print_function
from cStringIO import StringIO
import heapq
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
import urllib
import urllib2
import urlparse

from dnstable_manager.fileset import File, Fileset

# TODO Central download manager would enable multiple DNSTableManager
# instances to share a pool of outgoing connections.

# TODO Better error handling is needed, including exception handling and
# backoff.

def relative_uri(uri, fn):
    path,query = urllib.splitquery(uri)
    path,attrs = urllib.splitattr(path)
    if fn.startswith('/'):
        scheme,_,path = path.partition(':')
        host,path = urllib.splithost(path)
        new_uri = '{}://{}/{}'.format(scheme, host, fn[1:])
    else:
        parent = path.rpartition('/')[0]
        new_uri = '{}/{}'.format(parent, fn)
    if attrs:
        new_uri = '{};{}'.format(new_uri, ';'.join(attrs))
    return new_uri

class TestRelativeUri(unittest.TestCase):
    def test_relative_uri(self):
        self.assertEquals(relative_uri('http://foo/bar', 'baz'), 'http://foo/baz')
        self.assertEquals(relative_uri('http://foo/bar/baz', 'abc'), 'http://foo/bar/abc')
        self.assertEquals(relative_uri('http://foo/bar/baz', '/abc'), 'http://foo/abc')

    def test_relative_uri_attrs(self):
        self.assertEquals(relative_uri('http://foo/bar;a=b', 'baz'), 'http://foo/baz;a=b')
        self.assertEquals(relative_uri('http://foo/bar;a=b;c=d', 'baz'), 'http://foo/baz;a=b;c=d')
        self.assertEquals(relative_uri('http://foo/bar/baz;a=b;c=d', '/abc'), 'http://foo/abc;a=b;c=d')

class DNSTableManager:
    def __init__(self, fileset_uri, destination, base=None, extension='mtbl', frequency=1800):
        self.print_lock = threading.RLock()

        self.fileset_uri = fileset_uri

        self.destination = destination

        if base:
            self.base = base
        else:
            self.base = os.path.splitext(os.path.basename(urlparse.urlsplit(fileset_uri)[2]))[0]

        self.extension = extension
        self.frequency = frequency

        self.fileset = Fileset(self.fileset_uri, self.destination, self.base, self.extension)

        self.pending_downloads = set()
        self.active_downloads = dict()
        self.max_downloads = 4

    def run(self):
        last_remote_load = 0
        while True:
            now = time.time()
            self.fileset.load_local_fileset()
            if now - last_remote_load >= self.frequency:
                self.fileset.load_remote_fileset()
                last_remote_load = now

            for f in sorted(self.fileset.missing_files()):
                if f not in self.pending_downloads and f not in self.active_downloads:
                    self.log('Enqueuing {}'.format(f.name))
                    self.pending_downloads.add(f)

            for f,thread in self.active_downloads.items():
                if not thread.isAlive():
                    del self.active_downloads[f]
                    thread.join()

            for f in heapq.nlargest(self.max_downloads - len(self.active_downloads), self.pending_downloads):
                self.pending_downloads.remove(f)

                thread = threading.Thread(target=self.download, args=(f.name,))
                thread.setDaemon(False)
                thread.start()
                self.active_downloads[f] = thread

            self.fileset.prune_obsolete_files()
            self.fileset.prune_redundant_files()
            self.fileset.write_local_fileset()
            self.fileset.purge_deleted_files()

            time.sleep(1)

    def download(self, fn):
        out_fname = os.path.join(self.destination, fn)
        uri = relative_uri(self.fileset_uri, fn)

        self.log('Downloading {}'.format(fn))

        fp = urllib2.urlopen(uri)
        out = tempfile.NamedTemporaryFile(prefix='.{}.'.format(fn), dir=self.destination)

        shutil.copyfileobj(fp, out)
        out.file.close()
        os.chmod(out.name, 0o644)
        os.rename(out.name, out_fname)
        out.delete = False

        self.log('Download of {} complete'.format(fn))

    def log(self, msg, stream=sys.stdout):
        with self.print_lock:
            print (msg, file=stream)

class TestDNSTableManager(unittest.TestCase):
    @staticmethod
    def noop(self, *args, **kwargs): pass

    def setUp(self):
        self.orig_urlopen = urllib2.urlopen
        self.orig_sleep = time.sleep

    def tearDown(self):
        urllib2.urlopen = self.orig_urlopen
        time.sleep = self.orig_sleep

    def test_run(self):
        uri_base = 'http://example.com'
        fileset_uri = '{}/dns.fileset'.format(uri_base)
        fileset = (
            'dns.2014.Y.mtbl',
            'dns.201501.M.mtbl',
            'dns.20150201.W.mtbl',
            'dns.20150208.D.mtbl',
            'dns.20150209.0000.H.mtbl',
            'dns.20150209.0100.X.mtbl',
            'dns.20150209.0110.m.mtbl'
            )

        def my_urlopen(uri):
            if uri == fileset_uri:
                return StringIO('\n'.join(fileset + ('',)))
            else:
                self.assertTrue(uri.startswith('{}/'.format(uri_base)))
                return StringIO('{}'.format(uri[1+len(uri_base):]))
        urllib2.urlopen = my_urlopen

        class Success(Exception): pass
        def my_sleep(timeout):
            self.orig_sleep(0.01)
            time.sleep = my_sleep_done
        def my_sleep_done(timeout):
            self.orig_sleep(0.01)
            raise Success
        time.sleep = my_sleep

        td = tempfile.mkdtemp(prefix='test-dnstable-manager-run.')
        try:
            m = DNSTableManager(fileset_uri, td)
            m.log = TestDNSTableManager.noop
            self.assertRaises(Success, m.run)
            for fn in fileset:
                self.assertEqual(open(os.path.join(td, fn)).read(), fn)
        finally:
            shutil.rmtree(td, ignore_errors=True)

    def test_download(self):
        f = tempfile.NamedTemporaryFile(prefix='dns.test-dnstable-manager-download.', suffix='.mtbl')
        test_data = 'abc\n123\n'
        test_uri = 'http://example.com/{}'.format(os.path.basename(f.name))
        def my_urlopen(uri):
            self.assertEquals(uri, test_uri)
            return StringIO(test_data)
        urllib2.urlopen = my_urlopen

        m = DNSTableManager('http://example.com/dns.fileset', os.path.dirname(f.name))
        m.log = TestDNSTableManager.noop
        m.download(os.path.basename(f.name))
        self.assertEquals(open(f.name).read(), test_data)
