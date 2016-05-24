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

import heapq
import logging
import os
import tempfile
import time
import threading
import traceback
import urllib2

from .digest import check_digest, digest_extension
from .util import iterfileobj
import terminable_thread

logger = logging.getLogger(__name__)

class DownloadError(Exception): pass

class DownloadManager:
    def __init__(self, max_downloads=4, download_timeout=None, retry_timeout=60):
        self._pending_downloads = set()
        self._active_downloads = dict()

        self._failed_downloads = dict()

        self._max_downloads = max_downloads
        self._download_timeout = download_timeout
        self._retry_timeout = retry_timeout
        self._lock = threading.RLock()
        
        self._main_thread = None
        self._action_required = threading.Condition()
        self._terminate = threading.Event() 

    def start(self):
        logger.debug('Starting DownloadManager {}'.format(self))
        if self._main_thread:
            raise Exception('already running')

        self._terminate.clear()

        self._main_thread = threading.Thread(target=self._run)
        self._main_thread.setDaemon(True)
        self._main_thread.start()

    def stop(self, blocking=False, timeout=None):
        logger.debug('Stopping DownloadManager {}'.format(self))
        self._terminate.set()
        with self._action_required:
            logger.debug('Notifying all run loops')
            self._action_required.notifyAll()
        if blocking or timeout:
            return self.join(timeout=timeout)

    def join(self, timeout=None):
        logger.debug('Joining DownloadManager {}'.format(self))
        return self._main_thread.join(timeout=timeout)

    def _run(self):
        logger.debug('Running DownloadManager {}'.format(self))
        while not self._terminate.is_set():
            with self._lock:
                for f,thread in self._active_downloads.items():
                    if not thread.isAlive():
                        del self._active_downloads[f]
                        logger.debug('Joining {}'.format(thread))
                        thread.join()
                for f,thread in self._failed_downloads.items():
                    if not thread.isAlive():
                        del self._failed_downloads[f]
                        logger.debug('Joining {}'.format(thread))
                        thread.join()

            with self._lock:
                for f in heapq.nlargest(self._max_downloads - len(self._active_downloads), self._pending_downloads):
                    self._pending_downloads.remove(f)

                    thread = terminable_thread.Thread(target=self._download, args=(f,))
                    thread.setDaemon(True)
                    thread.start()

                    self._active_downloads[f] = thread

            with self._action_required:
                logger.debug('Waiting DownloadManager {}'.format(self))
                self._action_required.wait()
                logger.debug('Awoken DownloadManager {}'.format(self))

        logger.debug('Completing DownloadManager run {}'.format(self))
        with self._lock:
            for f,thread in self._active_downloads.items():
                if thread.isAlive():
                    thread.terminate()
                thread.join()
                del self._active_downloads[f]
            for f,thread in self._failed_downloads.items():
                if thread.isAlive():
                    thread.terminate()
                thread.join()
                del self._failed_downloads[f]
        
    def _download(self, f):
        logger.debug('Downloading {}'.format(f))
        try:
            target = f.target()

            logger.info('Downloading {} to {}'.format(f.uri, target))

            fp = urllib2.urlopen(f.uri, timeout=self._download_timeout)
            out = tempfile.NamedTemporaryFile(prefix='.{}.'.format(f.name), dir=f.dname, delete=True)

            algorithm = None
            digest = None
            digest_file = None
            if 'Digest' in fp.headers:
                algorithm,_,digest = fp.headers['Digest'].partition('=')
                digest_file = '{}.{}'.format(target, digest_extension(algorithm))
            elif f.digest_required:
                raise DownloadError('Digest header missing and digest_required=True')

            logger.debug('Copying urlopen of {} to {}'.format(f.uri, out.name))
            for chunk in check_digest(iterfileobj(fp), algorithm, digest):
                out.write(chunk)

            if 'Content-Length' in fp.headers:
                try:
                    expected_len = int(fp.headers['Content-Length'])
                    if out.tell() != expected_len:
                        raise DownloadError('Content length mismatch: {} != {}'.format(out.tell(), expected_len))
                except ValueError:
                    logger.debug('Skipping content length check, invalid header: {}'.format(fp.headers['Content-Length']))
            else:
                logger.debug('Skipping content length check, header missing')

            out.file.close()
            os.chmod(out.name, 0o644)

            mtime_tz = fp.info().getdate_tz('Last-Modified')
            if mtime_tz:
                mtime = time.mktime(mtime_tz[:-1]) + mtime_tz[-1]
                logger.debug('Setting mtime of {} to {}'.format(out.name, time.ctime(mtime)))
                os.utime(out.name, (mtime, mtime))

            f.validate(out.name)

            if digest_file:
                logger.debug('Writing digest={} to {}'.format(digest, digest_file))
                tmp_digest_file = tempfile.NamedTemporaryFile(prefix='.{}.'.format(os.path.basename(digest_file)), dir=f.dname, delete=True)
                print ('{}  {}'.format(digest.decode('base64').encode('hex'), os.path.basename(target)), file=tmp_digest_file)
                tmp_digest_file.file.close()
                os.chmod(tmp_digest_file.name, 0o644)
                os.rename(tmp_digest_file.name, digest_file)
                tmp_digest_file.delete = False

            try:
                logger.debug('Renaming {} to {}'.format(out.name, target))
                os.rename(out.name, target)
                out.delete = False
            except:
                try:
                    os.unlink(digest_file)
                except OSError:
                    pass
                raise

            logger.info('Download of {} to {} complete'.format(f.uri, target))
        except (KeyboardInterrupt, SystemExit) as e:
            logger.debug('Re-Raising {}'.format(str(e)))
            raise
        except Exception as e:
            logger.error('Download of {} failed: {}'.format(f.uri, str(e)))
            logger.debug(traceback.format_exc())

            expire_thread = terminable_thread.Thread(target=self._expire_failed_download, args=(f,))
            expire_thread.setDaemon(True)
            expire_thread.start()
            with self._lock:
                self._failed_downloads[f] = expire_thread
        finally:
            with self._action_required:
                logger.debug('Notifying run loop')
                self._action_required.notify()

    def _expire_failed_download(self, f, timeout=None):
        if timeout is None:
            timeout = self._retry_timeout
        logger.debug('Waiting {timeout} to retry {uri}'.format(timeout=timeout, uri=f.uri))
        time.sleep(timeout)
        logger.info('Failure timeout for {uri} complete'.format(uri=f.uri))
        with self._action_required:
            logger.debug('Notifying run loop')
            self._action_required.notify()

    def __contains__(self, filename):
        with self._lock:
            return filename in self._pending_downloads or filename in self._active_downloads or filename in self._failed_downloads

    def enqueue(self, f):
        logger.info('Enqueuing {}'.format(os.path.basename(f.name)))

        with self._lock:
            self._pending_downloads.add(f)

        with self._action_required:
            logger.debug('Notifying run loop')
            self._action_required.notify()

