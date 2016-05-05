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

from __future__ import print_function

from cStringIO import StringIO
import httplib
import os
import shutil
import tempfile
import time
import unittest
import urllib
import urllib2

from dnstable_manager import get_config, DNSTableManager
from dnstable_manager.download import DownloadManager
import jsonschema

class TestGetConfig(unittest.TestCase):
    def test_get_config_default(self):
        with self.assertRaises(jsonschema.ValidationError):
            get_config()

class TestDNSTableManager(unittest.TestCase):
    @staticmethod
    def noop(self, *args, **kwargs): pass

    def setUp(self):
        self.orig_urlopen = urllib2.urlopen
        self.orig_sleep = time.sleep
        self.td = tempfile.mkdtemp(prefix='test-dnstable-manager.')

    def tearDown(self):
        urllib2.urlopen = self.orig_urlopen
        time.sleep = self.orig_sleep
        shutil.rmtree(self.td, ignore_errors=True)

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

        def my_urlopen(uri, timeout=None):
            msg = httplib.HTTPMessage(StringIO())
            if uri == fileset_uri:
                return urllib.addinfourl(StringIO('\n'.join(fileset + ('',))),
                        msg, uri)
            else:
                self.assertTrue(uri.startswith('{}/'.format(uri_base)))
                return urllib.addinfourl(StringIO('{}'.format(uri[1+len(uri_base):])),
                        msg, uri)
        urllib2.urlopen = my_urlopen

        class Success(Exception): pass
        def my_sleep(timeout):
            self.orig_sleep(0.01)
            time.sleep = my_sleep_done
        def my_sleep_done(timeout):
            self.orig_sleep(0.01)
            raise Success
        time.sleep = my_sleep

        d = DownloadManager()
        d.start()
        m = DNSTableManager(fileset_uri, self.td, download_manager=d)
        self.assertRaises(Success, m.run)
        self.orig_sleep(0.1)
        for fn in fileset:
            self.assertEqual(open(os.path.join(self.td, fn)).read(), fn)
        d.stop(blocking=True)

    def test_clean_tempfiles(self):
        m = DNSTableManager(os.path.join('file://', self.td), self.td, base='dns', download_manager=None)
        closed_file = os.path.join(self.td, '.dns.2000.Y.mtbl.XXXXXX')
        opened_file = os.path.join(self.td, '.dns.2001.Y.mtbl.XXXXXX')
        open(closed_file, 'w')
        of = open(opened_file, 'w')

        m.clean_tempfiles()
        of.close()

        self.assertTrue(os.path.exists(opened_file))
        self.assertFalse(os.path.exists(closed_file))
