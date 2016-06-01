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

import base64
from cStringIO import StringIO
import unittest

import dnstable_manager.util as du

def _iterfileobj(data, length):
    def t(self):
        src = StringIO(data)
        dst = StringIO()

        for chunk in du.iterfileobj(src, length=length):
            self.assertLessEqual(len(chunk), length)
            self.assertGreater(len(chunk), 0)
            dst.write(chunk)

        self.assertEqual(dst.getvalue(), data)
    return t

class TestIterFileObj(unittest.TestCase): pass

for length in (2, 32, 1024, 16*1024):
    data = base64.b64decode('qoiMsxenAEPPiamMzviaf13rCA6s2xtJrYjGBMZ=') * (length+1)
    assert(len(data) % length > 0)
    setattr(TestIterFileObj, 'test_iterfileobj(len={})'.format(length), _iterfileobj(data, length))
