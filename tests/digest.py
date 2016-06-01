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
# limitations under the License.import base64

import base64
from cStringIO import StringIO
import hashlib
import textwrap
import unittest

import dnstable_manager.digest as dd

def _test_digest(algorithm, passed_algorithm, invalid=False):
    def t(self):
        text = textwrap.dedent('''\
                fwKMyjBG1gjQqEUpcL1UFj3e9tyjVuD8vE3WtU6CjpyuV
                nn78zKqeuYc0H8dLopt11DHRzlBBBpowwVZMYjl3BW8wm
                Kj0ovutecEjWrQsjygPwGl7uKLMAxhyzYp9udfJtxAPoD
                T3Uk3D4yaexKDeKkuSYaIIGk0safQMrBoP6UYMT3B9rJM
                DoDe0vQxqfoOSmPgfGc4bBgau6mF9yc8Bg804zjnbKXbW
                uXytE27bdUf942xsf8tTVW9xwhfsIMexjoE5hazQWmDCd
                RHYOiYmaDTlmI4mwknzLEPPVJVXwOUPU8Sy1BXV3ZQ3Ur
                YNb2o5vWbWy8QoCjpzIeFn4TakzJm71bOy76GiI9eOAcB
                TJunbclmdi9hRk4TO5KPdLS3XucJcS0xiigPbOj4OLLMb
                zIO75BYeS0MyjQPNplYvsNLAuLHUAZWBVQRxIdU4xoaFI
                xALV4Ryb94Z4C1gMy4r8MK6dp8N5dYRKfSRRAQxx2ZULo
                aEA8Wyx2uMexsJVbi4mqpOt4hVh3l1ZcM18kZByFEJjKt
                fVvIVE3YYujPaLhXE7JbbaAPoJsrMvB4BBrIABjmAFNSf
                mobzY6nd0RGxJtJYUd6kZaNsxFm7TGTQOB5YTXZ6223ev
                tjXBOwsL3HDCRYEkaPwYlRkPoR2MmnF4ONTXjjK6YPrLW
                YAZtHXDNrLBlmjQWGAP1GQ669bE77HQ58tlXuzMSvqiQt
                qmN0s9oyaUVokcTBFIJPYorLLMhhOwaF6h72QRZWDBIgG
                R5hqwvVPhBUcmmVheKTOv18RzS91TqaOL94VZT8N0lv0M
                4O5KZpkqiy1YpOS61BvCFr7IWdwmI98QKdbdpMLUAydXQ
                OFVG60va76U2PyphDe22sBRbmwnzwjGf8yNXzb2nhsMhb
                GB6EKRy7JadeKpzqCg7iJdqUqOoQbgvgzMJDYRuTiQJtu
                hB9uyyPbWGb4sc1pzYTjED0kLSl4PjImdvuasWWfegwYr
                knVt0HLP1PypZxwxcpsi8rdlLeupMHK2eGNLgvOIaomWB
                ARVRKS3KHVuGCD36CfSNzWIorOfjF3j53Bfb9Qk4XJWO7\
                        ''')

        if invalid:
            digest = 'INVALID'
        else:
            digest = base64.b64encode(hashlib.new(algorithm, text).digest())

        try:
            for line_no,(expected,actual) in enumerate(zip(StringIO(text), dd.check_digest(StringIO(text), passed_algorithm, digest))):
                self.assertEqual(expected, actual, msg='Line {}: {!r} != {!r})'.format(line_no+1, expected, actual))
        except dd.DigestError:
            if invalid:
                pass
            else:
                raise
    return t

def _test_digest_extension(expected, algorithm, invalid=False):
    def t(self):
        extension = dd.digest_extension(algorithm)
        try:
            self.assertEqual(extension, expected)
        except dd.DigestError:
            if invalid:
                pass
            else:
                raise
    return t

class TestDigest(unittest.TestCase):
    test_no_algorithm = _test_digest('sha256', None)
    test_invalid_algorithm = _test_digest('sha256', 'MD5')

for bits in (224, 256, 384, 512):
    setattr(TestDigest, 'test_digest(sha{})'.format(bits), _test_digest('sha{}'.format(bits), 'sha{}'.format(bits)))
    setattr(TestDigest, 'test_digest(SHA-{})'.format(bits), _test_digest('sha{}'.format(bits), 'SHA-{}'.format(bits)))
    setattr(TestDigest, 'test_digest_invalid(sha{})'.format(bits), _test_digest('sha{}'.format(bits), 'sha{}'.format(bits), invalid=True))
    setattr(TestDigest, 'test_digest_extension(sha{})'.format(bits), _test_digest_extension('sha{}'.format(bits), 'sha{}'.format(bits)))
    setattr(TestDigest, 'test_digest_extension(SHA-{})'.format(bits), _test_digest_extension('sha{}'.format(bits), 'SHA-{}'.format(bits)))
