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
import base64
import hashlib
import httplib
import os
import tempfile
import unittest
import urllib
import urllib2

from . import get_uri
from dnstable_manager.download import DownloadManager
from dnstable_manager.fileset import File

class TestDownloadManager(unittest.TestCase):
    @staticmethod
    def noop(self, *args, **kwargs): pass

    def setUp(self):
        self.orig_urlopen = urllib2.urlopen

    def tearDown(self):
        urllib2.urlopen = self.orig_urlopen

    def test_download(self):
        tf = tempfile.NamedTemporaryFile(prefix='dns-test-dnstable-manager_download-', suffix='.2015.Y.mtbl', delete=True)
        test_data = 'abc\n123\n'
        digest = base64.b64encode(hashlib.sha256(test_data).digest())
        digest_file = tf.name + '.sha256'
        f = File(os.path.basename(tf.name), dname=os.path.dirname(tf.name))
        f.uri = 'http://example.com/{}'.format(f.name)
        seen_uris = list()
        def my_urlopen(obj, timeout=None):
            uri = get_uri(obj)
            seen_uris.append(uri)
            return urllib.addinfourl(StringIO(test_data), httplib.HTTPMessage(StringIO('Content-Length: {}\r\nDigest: SHA-256={}'.format(len(test_data), digest))), f.uri)
        urllib2.urlopen = my_urlopen

        m = DownloadManager()
        try:
            m._download(f)
            self.assertItemsEqual(seen_uris, [f.uri])
            self.assertEquals(open(tf.name).read(), test_data)
            self.assertTrue(os.path.isfile(digest_file), 'Digest file missing: {}'.format(digest_file))
            with open(digest_file) as df:
                test_digest,test_name = df.readline().strip().split()
                self.assertEqual(test_digest.decode('hex'), digest.decode('base64'))
                self.assertEqual(test_name, f.name)
        finally:
            m.stop()
            try:
                os.unlink(digest_file)
            except OSError:
                pass

    def test_download_apikey(self):
        tf = tempfile.NamedTemporaryFile(prefix='dns-test-dnstable-manager_download-', suffix='.2015.Y.mtbl', delete=True)
        test_data = 'abc\n123\n'
        digest = base64.b64encode(hashlib.sha256(test_data).digest())
        digest_file = tf.name + '.sha256'
        apikey = 'TEST API KEY'
        f = File(os.path.basename(tf.name), dname=os.path.dirname(tf.name), apikey=apikey)
        self.assertEqual(f.apikey, apikey)
        f.uri = 'http://example.com/{}'.format(f.name)
        seen_uris = list()
        headers = list()
        def my_urlopen(obj, timeout=None):
            headers.extend(obj.header_items())
            uri = get_uri(obj)
            seen_uris.append(uri)
            return urllib.addinfourl(StringIO(test_data), httplib.HTTPMessage(StringIO('Content-Length: {}\r\nDigest: SHA-256={}'.format(len(test_data), digest))), f.uri)
        urllib2.urlopen = my_urlopen

        m = DownloadManager()
        try:
            m._download(f)
            self.assertItemsEqual(seen_uris, [f.uri])

            for k,v in headers:
                if k.lower() == 'x-api-key':
                    self.assertEqual(v, apikey)
                    break
            else:
                self.fail('X-API-Key header missing')

            self.assertEquals(open(tf.name).read(), test_data)
            self.assertTrue(os.path.isfile(digest_file), 'Digest file missing: {}'.format(digest_file))
            with open(digest_file) as df:
                test_digest,test_name = df.readline().strip().split()
                self.assertEqual(test_digest.decode('hex'), digest.decode('base64'))
                self.assertEqual(test_name, f.name)
        finally:
            m.stop()
            try:
                os.unlink(digest_file)
            except OSError:
                pass

    def test_download_bad_content_length(self):
        tf = tempfile.NamedTemporaryFile(prefix='dns-test-dnstable-manager_download-', suffix='.2015.Y.mtbl', delete=True)
        test_data = 'abc\n123\n'
        f = File(os.path.basename(tf.name), dname=os.path.dirname(tf.name))
        f.uri = 'http://example.com/{}'.format(f.name)
        def my_urlopen(obj, timeout=None):
            uri = get_uri(obj)
            self.assertEquals(uri, f.uri)
            return urllib.addinfourl(StringIO(test_data), httplib.HTTPMessage(StringIO('Content-Length: {}'.format(len(test_data)+1))), f.uri)
        urllib2.urlopen = my_urlopen

        m = DownloadManager()
        try:
            m._download(f)
            self.assertIn(f, m._failed_downloads)
        finally:
            m.stop()

    def test_download_bad_digest(self):
        tf = tempfile.NamedTemporaryFile(prefix='dns-test-dnstable-manager_download-', suffix='.2015.Y.mtbl', delete=True)
        test_data = 'abc\n123\n'
        digest_file = tf.name + '.sha256'
        digest = 'INVALID'
        f = File(os.path.basename(tf.name), dname=os.path.dirname(tf.name))
        f.uri = 'http://example.com/{}'.format(f.name)
        def my_urlopen(obj, timeout=None):
            uri = get_uri(obj)
            self.assertEquals(uri, f.uri)
            return urllib.addinfourl(StringIO(test_data), httplib.HTTPMessage(StringIO('Content-Length: {}\r\nDigest: SHA-256={}'.format(len(test_data), digest))), f.uri)
        urllib2.urlopen = my_urlopen

        m = DownloadManager()
        try:
            m._download(f)
            self.assertIn(f, m._failed_downloads)
        finally:
            m.stop()
            try:
                os.unlink(digest_file)
            except OSError:
                pass
