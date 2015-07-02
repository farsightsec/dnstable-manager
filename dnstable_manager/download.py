from __future__ import print_function

from cStringIO import StringIO
import heapq
import logging
import os
import shutil
import tempfile
import time
import threading
import traceback
import unittest
import urllib2

from dnstable_manager.fileset import File
import terminable_thread

logger = logging.getLogger(__name__)

class DownloadManager:
    def __init__(self, max_downloads=4, retry_timeout=60):
        self._pending_downloads = set()
        self._active_downloads = dict()

        self._failed_downloads = dict()

        self._max_downloads = max_downloads
        self._retry_timeout = retry_timeout
        self._lock = threading.RLock()
        
        self._main_thread = None
        self._action_required = threading.Condition()
        self._terminate = threading.Event() 

    def start(self):
        if self._main_thread:
            raise Exception('already running')

        self._terminate.clear()

        self._main_thread = threading.Thread(target=self._run)
        self._main_thread.setDaemon(False)
        self._main_thread.start()

    def stop(self, blocking=False, timeout=None):
        self._terminate.set()
        with self._action_required:
            self._action_required.notifyAll()
        if blocking or timeout:
            return self.join(timeout=timeout)

    def join(self, timeout=None):
        return self._main_thread.join(timeout=timeout)

    def _run(self):
        while not self._terminate.is_set():
            with self._lock:
                for f,thread in self._active_downloads.items():
                    if not thread.isAlive():
                        del self._active_downloads[f]
                        thread.join()
                for f,thread in self._failed_downloads.items():
                    if not thread.isAlive():
                        del self._failed_downloads[f]
                        thread.join()

            with self._lock:
                for f in heapq.nlargest(self._max_downloads - len(self._active_downloads), self._pending_downloads):
                    self._pending_downloads.remove(f)

                    thread = terminable_thread.Thread(target=self._download, args=(f,))
                    thread.setDaemon(False)
                    thread.start()

                    self._active_downloads[f] = thread

            with self._action_required:
                self._action_required.wait()

        with self._lock:
            for f,thread in self._active_downloads.items():
                thread.terminate()
                thread.join()
                del self._active_downloads[f]
            for f,thread in self._failed_downloads.items():
                thread.terminate()
                thread.join()
                del self._failed_downloads[f]
        
    def _download(self, f):
        try:
            if f.dname:
                target = os.path.join(f.dname, f.name)
            else:
                target = f.name

            logger.info('Downloading {}'.format(f.uri))

            fp = urllib2.urlopen(f.uri)
            out = tempfile.NamedTemporaryFile(prefix='.{}.'.format(f.name), dir=f.dname)

            shutil.copyfileobj(fp, out)
            out.file.close()
            os.chmod(out.name, 0o644)
            os.rename(out.name, target)
            out.delete = False

            logger.info('Download of {} complete'.format(f.uri))

            with self._action_required:
                self._action_required.notify()
        except KeyboardInterrupt:
            raise
        except SystemExit:
            raise
        except:
            logger.error('Download of {} failed'.format(f.uri))
            logger.debug(traceback.format_exc())

            expire_thread = terminable_thread.Thread(target=self._expire_failed_download, args=(f,))
            expire_thread.setDaemon(False)
            expire_thread.start()
            with self._lock:
                self._failed_downloads[f] = expire_thread
        finally:
            with self._action_required:
                self._action_required.notify()

    def _expire_failed_download(self, f, timeout=None):
        if timeout is None:
            timeout = self._retry_timeout
        logger.debug('Waiting {timeout} to retry {uri}'.format(timeout=timeout, uri=f.uri))
        time.sleep(timeout)
        logger.info('Failure timeout for {uri} complete'.format(uri=f.uri))
        with self._action_required:
            self._action_required.notify()

    def __contains__(self, filename):
        with self._lock:
            return filename in self._pending_downloads or filename in self._active_downloads or filename in self._failed_downloads

    def enqueue(self, f):
        logger.info('Enqueuing {}'.format(os.path.basename(f.name)))

        with self._lock:
            self._pending_downloads.add(f)

        with self._action_required:
            self._action_required.notify()

class TestDownloadManager(unittest.TestCase):
    @staticmethod
    def noop(self, *args, **kwargs): pass

    def setUp(self):
        self.orig_urlopen = urllib2.urlopen

    def tearDown(self):
        urllib2.urlopen = self.orig_urlopen

    def test_download(self):
        tf = tempfile.NamedTemporaryFile(prefix='dns-test-dnstable-manager_download-', suffix='.2015.Y.mtbl')
        test_data = 'abc\n123\n'
        f = File(os.path.basename(tf.name), dname=os.path.dirname(tf.name))
        f.uri = 'http://example.com/{}'.format(f.name)
        def my_urlopen(uri):
            self.assertEquals(uri, f.uri)
            return StringIO(test_data)
        urllib2.urlopen = my_urlopen

        m = DownloadManager()
        m._download(f)
        self.assertEquals(open(tf.name).read(), test_data)
