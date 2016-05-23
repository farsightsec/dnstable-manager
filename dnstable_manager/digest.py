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
import hashlib
import logging

logger = logging.getLogger(__name__)

class DigestError(Exception): pass

def check_digest(iterator, algorithm, digest):
    logger.debug('algorithm={}, checksum={}'.format(algorithm, digest))

    if algorithm is None:
        logger.debug('No algorithm provided. Skipping digest check.')
        for chunk in iterator:
            yield chunk
        return
    elif algorithm.lower() in ('sha-224', 'sha224'):
        digest_obj = hashlib.sha224()
    elif algorithm.lower() in ('sha-256', 'sha256'):
        digest_obj = hashlib.sha256()
    elif algorithm.lower() in ('sha-384', 'sha384'):
        digest_obj = hashlib.sha384()
    elif algorithm.lower() in ('sha-512', 'sha512'):
        digest_obj = hashlib.sha512()
    else:
        logger.debug('Unsupported algorithm: {}'.format(algorithm))
        for chunk in iterator:
            yield chunk
        return

    for chunk in iterator:
        digest_obj.update(chunk)
        yield chunk

    real_digest = base64.b64encode(digest_obj.digest())
    if real_digest != digest:
        raise DigestError('Digest mismatch: {} != {}'.format(real_digest, digest))

def digest_extension(algorithm):
    if algorithm.lower() in ('sha-224', 'sha224'):
        return 'sha224'
    elif algorithm.lower() in ('sha-256', 'sha256'):
        return 'sha256'
    elif algorithm.lower() in ('sha-384', 'sha384'):
        return 'sha384'
    elif algorithm.lower() in ('sha-512', 'sha512'):
        return 'sha512'
    else:
        raise DigestError('Unknown algorithm: {}'.format(algorithm))

DIGEST_EXTENSIONS = ('sha224', 'sha256', 'sha384', 'sha512')
