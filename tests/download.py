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
import tempfile
import unittest
import urllib
import urllib2

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
        f = File(os.path.basename(tf.name), dname=os.path.dirname(tf.name))
        f.uri = 'http://example.com/{}'.format(f.name)
        def my_urlopen(uri, timeout=None):
            self.assertEquals(uri, f.uri)
            return urllib.addinfourl(StringIO(test_data), httplib.HTTPMessage(StringIO()), f.uri)
        urllib2.urlopen = my_urlopen

        m = DownloadManager()
        try:
            m._download(f)
            self.assertEquals(open(tf.name).read(), test_data)
        finally:
            m.stop()
