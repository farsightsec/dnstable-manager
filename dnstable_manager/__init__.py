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

import errno
import httplib
import logging
import os
import socket
import threading
import time
import traceback
import urllib2
import urlparse

from dnstable_manager.download import DownloadManager
from dnstable_manager.fileset import Fileset, FilesetError
import jsonschema
import option_merge
import pkg_resources
import psutil
import yaml

logger = logging.getLogger(__name__)

class ConfigException(Exception): pass

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

        filesets = set()
        for fileset,fileset_config in config['filesets'].items():
            t = (fileset_config['destination'], fileset_config['base'])
            if t in filesets:
                raise ConfigException('Fileset {} collides with {}/{}.*'.format(fileset, *t))
            filesets.add(t)

            if not os.path.isdir(fileset_config['destination']):
                raise ConfigException('{} is not a directory'.format(fileset_config['destination']))

        for attr in ('ssl_ca_file', 'ssl_keyfile', 'ssl_certfile'):
            if attr in config['downloader']:
                try:
                    open(config['downloader'][attr])
                except IOError as e:
                    raise ConfigException('{attr} {filename}: {strerror}'.format(
                        attr=attr, filename=e.filename, strerror=e.strerror))

    return config

class DNSTableManager:
    def __init__(self, fileset_uri, destination, base=None, extension='mtbl', frequency=1800, download_timeout=None, retry_timeout=60, apikey=None, validator=None, digest_required=True, minimal=True, download_manager=None):
        self.fileset_uri = fileset_uri

        if not os.path.isdir(destination):
            raise OSError(errno.ENOENT, 'Not a directory: \'{}\''.format(destination))

        self.destination = destination

        if base:
            self.base = base
        else:
            self.base = os.path.splitext(os.path.basename(urlparse.urlsplit(fileset_uri)[2]))[0]

        self.extension = extension
        self.frequency = frequency
        self.download_timeout = download_timeout
        self.retry_timeout = retry_timeout
        self.minimal = minimal

        self.fileset = Fileset(uri=self.fileset_uri,
                dname=self.destination,
                base=self.base,
                extension=self.extension,
                apikey=apikey,
                validator=validator,
                timeout=download_timeout,
                digest_required=digest_required)

        if download_manager:
            self.download_manager = download_manager
        else:
            self.download_manager = DownloadManager(download_timeout=download_timeout, retry_timeout=retry_timeout)
            self.download_manager.start()

        self.thread = None

    def start(self):
        if self.thread:
            raise Exception

        self.thread = threading.Thread(target=self.run)
        self.thread.setDaemon(True)
        self.thread.start()

    def join(self):
        if not self.thread:
            raise Exception

        self.thread.join()
        self.thread = None

    def run(self):
        next_remote_load = 0
        while True:
            now = time.time()
            self.fileset.load_local_fileset()

            try:
                if now >= next_remote_load:
                    self.fileset.load_remote_fileset()
                    next_remote_load = now + self.frequency
            except (FilesetError, urllib2.URLError, urllib2.HTTPError, httplib.HTTPException, socket.error) as e:
                logger.error('Failed to load remote fileset {}: {}'.format(self.fileset_uri, str(e)))
                logger.debug(traceback.format_exc())
                next_remote_load = now + self.retry_timeout

            for f in sorted(self.fileset.missing_files(), reverse=True):
                if f not in self.download_manager:
                    self.download_manager.enqueue(f)

            self.fileset.prune_obsolete_files(minimal=self.minimal)
            self.fileset.prune_redundant_files(minimal=self.minimal)

            try:
                self.fileset.write_local_fileset()
                if not self.minimal:
                    self.fileset.write_local_fileset(minimal=False)
            except (IOError, OSError) as e:
                logger.error('Failed to write fileset {}: {}'.format(self.fileset.get_fileset_name(), str(e)))
                logger.debug(traceback.format_exc())

            try:
                self.fileset.purge_deleted_files()
            except OSError as e:
                logger.error('Failed to purge deleted files in {}: {}'.format(self.destination, str(e)))
                logger.debug(traceback.format_exc())

            time.sleep(1)

    def clean_tempfiles(self):
        open_files = set()
        for p in psutil.process_iter():
            try:
                for f in p.get_open_files():
                    open_files.add(f.path)
            except psutil.AccessDenied:
                pass

        for filename in self.fileset.list_temporary_files():
            if filename in open_files:
                logger.debug('Not unlinking tempfile {!r}: In use.'.format(filename))
                continue

            logger.debug('Unlinking tempfile: {!r}'.format(filename))
            os.unlink(filename)
