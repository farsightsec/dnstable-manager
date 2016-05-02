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

import os
import subprocess
import urllib2
import unittest

from dnstable_manager.rsync import RsyncHandler

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
