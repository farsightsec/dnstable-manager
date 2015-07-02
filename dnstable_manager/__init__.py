from __future__ import print_function
from cStringIO import StringIO
import os
import shutil
import tempfile
import threading
import time
import unittest
import urllib2
import urlparse

from dnstable_manager.download import DownloadManager
from dnstable_manager.fileset import Fileset
import jsonschema
import option_merge
import pkg_resources
import yaml

def get_config(filename=None, stream=None, validate=True):
    configs = [yaml.safe_load(pkg_resources.resource_stream(__name__, 'default-config.yaml'))]

    if filename:
        configs.append(yaml.safe_load(open(filename)))

    if stream:
        configs.append(yaml.safe_load(stream))

    config = option_merge.MergedOptions.using(*configs)

    if validate:
        schema = yaml.safe_load(pkg_resources.resource_stream(__name__, 'config-schema.yaml'))
        jsonschema.validate(config, schema)

    return config

class TestGetConfig(unittest.TestCase):
    def test_get_config_default(self):
        with self.assertRaises(jsonschema.ValidationError):
            get_config()

class DNSTableManager:
    def __init__(self, fileset_uri, destination, base=None, extension='mtbl', frequency=1800, download_manager=None):
        self.fileset_uri = fileset_uri

        self.destination = destination

        if base:
            self.base = base
        else:
            self.base = os.path.splitext(os.path.basename(urlparse.urlsplit(fileset_uri)[2]))[0]

        self.extension = extension
        self.frequency = frequency

        self.fileset = Fileset(self.fileset_uri, self.destination, self.base, self.extension)

        if download_manager:
            self.download_manager = download_manager
        else:
            self.download_manager = DownloadManager()
            self.download_manager.start()

        self.thread = None

    def start(self):
        if self.thread:
            raise Exception

        self.thread = threading.Thread(target=self.run)
        self.thread.setDaemon(False)
        self.thread.start()

    def join(self):
        if not self.thread:
            raise Exception

        self.thread.join()
        self.thread = None

    def run(self):
        last_remote_load = 0
        while True:
            now = time.time()
            self.fileset.load_local_fileset()
            if now - last_remote_load >= self.frequency:
                self.fileset.load_remote_fileset()
                last_remote_load = now

            for f in sorted(self.fileset.missing_files(), reverse=True):
                if f not in self.download_manager:
                    self.download_manager.enqueue(f)

            self.fileset.prune_obsolete_files()
            self.fileset.prune_redundant_files()
            self.fileset.write_local_fileset()
            self.fileset.purge_deleted_files()

            time.sleep(1)

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
            d = DownloadManager()
            d.start()
            m = DNSTableManager(fileset_uri, td, download_manager=d)
            self.assertRaises(Success, m.run)
            self.orig_sleep(0.1)
            for fn in fileset:
                self.assertEqual(open(os.path.join(td, fn)).read(), fn)
            d.stop(blocking=True)
        finally:
            shutil.rmtree(td, ignore_errors=True)
