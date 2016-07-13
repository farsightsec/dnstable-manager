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

import base64
from cStringIO import StringIO
import datetime
import hashlib
import httplib
import os
import shutil
import tempfile
import unittest
import urllib
import urllib2

from . import get_uri
from dnstable_manager.digest import DIGEST_EXTENSIONS
from dnstable_manager.fileset import File, Fileset, FilesetError, ParseError, compute_overlap, parse_datetime, relative_uri

class TestParseDatetime(unittest.TestCase):
    def test_parse_datetime_minute(self):
        self.assertEquals(parse_datetime('20060102.1501'), datetime.datetime(2006, 1, 2, 15, 1))

    def test_parse_datetime_hour(self):
        self.assertEquals(parse_datetime('20060102.1500'), datetime.datetime(2006, 1, 2, 15, 0))

    def test_parse_datetime_day(self):
        self.assertEqual(parse_datetime('20060102'), datetime.datetime(2006, 1, 2, 0, 0))

    def test_parse_datetime_month(self):
        self.assertEqual(parse_datetime('200601'), datetime.datetime(2006, 1, 1, 0, 0))

    def test_parse_datetime_year(self):
        self.assertEqual(parse_datetime('2006'), datetime.datetime(2006, 1, 1, 0, 0))

    def test_parse_datetime_invalid(self):
        self.assertRaises(ParseError, parse_datetime, '')
        self.assertRaises(ParseError, parse_datetime, '2')
        self.assertRaises(ParseError, parse_datetime, '20')
        self.assertRaises(ParseError, parse_datetime, '200')
        self.assertRaises(ParseError, parse_datetime, '20060')
        self.assertRaises(ParseError, parse_datetime, '200600')
        self.assertRaises(ParseError, parse_datetime, '200613')
        self.assertRaises(ParseError, parse_datetime, '2006010')
        self.assertRaises(ParseError, parse_datetime, '20060100')
        self.assertRaises(ParseError, parse_datetime, '20060132')
        self.assertRaises(ParseError, parse_datetime, '20060102.')
        self.assertRaises(ParseError, parse_datetime, '20060102.1')
        self.assertRaises(ParseError, parse_datetime, '20060102.15')
        self.assertRaises(ParseError, parse_datetime, '20060102.150')
        self.assertRaises(ParseError, parse_datetime, '20060102.2500')
        self.assertRaises(ParseError, parse_datetime, '20060102.0060')
        self.assertRaises(ParseError, parse_datetime, '20060102.1500.')

class TestRelativeUri(unittest.TestCase):
    def test_relative_uri(self):
        self.assertEquals(relative_uri('http://foo/bar', 'baz'), 'http://foo/baz')
        self.assertEquals(relative_uri('http://foo/bar/baz', 'abc'), 'http://foo/bar/abc')
        self.assertEquals(relative_uri('http://foo/bar/baz', '/abc'), 'http://foo/abc')

    def test_relative_uri_attrs(self):
        self.assertEquals(relative_uri('http://foo/bar;a=b', 'baz'), 'http://foo/baz;a=b')
        self.assertEquals(relative_uri('http://foo/bar;a=b;c=d', 'baz'), 'http://foo/baz;a=b;c=d')
        self.assertEquals(relative_uri('http://foo/bar/baz;a=b;c=d', '/abc'), 'http://foo/abc;a=b;c=d')

class TestComputeOverlap(unittest.TestCase):
    def test_compute_overlap(self):
        files = set(File(f) for f in (
            'dns.2014.Y.mtbl',
            'dns.201501.M.mtbl',
            'dns.20150201.W.mtbl',
            'dns.20150208.D.mtbl',
            'dns.20150209.0000.H.mtbl',
            'dns.20150209.0100.X.mtbl',
            'dns.20150209.0110.m.mtbl'
                ))
        overlap = set(File(f) for f in (
            'dns.201401.M.mtbl',
            'dns.20150108.W.mtbl',
            'dns.20150202.D.mtbl',
            'dns.20150208.0100.H.mtbl',
            'dns.20150209.0020.X.mtbl',
            'dns.20150209.0109.m.mtbl'
            ))
        self.assertItemsEqual(compute_overlap(files.union(overlap)), overlap)

    def test_compute_overlap_disjoint(self):
        files = set(File(f) for f in (
            'dns.2014.Y.mtbl',
            'dns.201501.M.mtbl',
            'dns.20150201.W.mtbl',
            'dns.20150208.D.mtbl',
            'dns.20150209.0000.H.mtbl',
            'dns.20150209.0100.X.mtbl',
            'dns.20150209.0110.m.mtbl'
                ))
        self.assertItemsEqual(compute_overlap(files), [])

class TestFile(unittest.TestCase):
    def test_init_year(self):
        f = File('test.2000.Y.txt')
        self.assertEqual(f.name, 'test.2000.Y.txt')
        self.assertEqual(f.tl, 'Y')
        self.assertEqual(f.datetime, datetime.datetime(2000,1,1,0,0))

    def test_init_minute(self):
        f = File('test.20000102.0304.m.txt')
        self.assertEqual(f.name, 'test.20000102.0304.m.txt')
        self.assertEqual(f.tl, 'm')
        self.assertEqual(f.datetime, datetime.datetime(2000,1,2,3,4))

    def test_init_invalid(self):
        self.assertRaises(ParseError, File, 'test.Y.txt')
        self.assertRaises(ParseError, File, 'test.200.Y.txt')

    def test_cmp(self):
        f1 = File('test.2000.Y.txt')
        f2 = File('test.199901.M.txt')
        f3 = File('test.200001.M.txt')
        self.assertLess(f1, f2)
        self.assertLess(f1, f3)
        self.assertLess(f2, f3)
        self.assertEqual(f1, File('test.2000.Y.txt'))

    def test_hash(self):
        f1 = File('test.2000.Y.txt')
        f2 = File('test.2000.Y.txt')
        f3 = File('test.200001.M.txt')
        self.assertEqual(hash(f1), hash(f1))
        self.assertEqual(hash(f1), hash(f2))
        self.assertNotEqual(hash(f1), hash(f3))

class TestFileset(unittest.TestCase):
    @staticmethod
    def noop(self, *args, **kwargs): pass

    def setUp(self):
        self.orig_unlink = os.unlink
        self.orig_urlopen = urllib2.urlopen
        self.td = tempfile.mkdtemp(prefix='test-fileset-load-local.')

    def tearDown(self):
        os.unlink = self.orig_unlink
        urllib2.urlopen = self.orig_urlopen
        shutil.rmtree(self.td, ignore_errors=True)

    def test_load_local_fileset(self):
        fileset = (
            'dns.2014.Y.mtbl',
            'dns.201501.M.mtbl',
            'dns.20150201.W.mtbl',
            'dns.20150208.D.mtbl',
            'dns.20150209.0000.H.mtbl',
            'dns.20150209.0100.X.mtbl',
            'dns.20150209.0110.m.mtbl'
            )

        for fn in fileset:
            open(os.path.join(self.td, fn), 'w')

        fs = Fileset(None, self.td)
        fs.load_local_fileset()

        self.assertItemsEqual(fs.all_local_files, (File(fn) for fn in fileset))
        self.assertItemsEqual(fs.minimal_local_files, (File(fn) for fn in fileset))

    def test_prune_obsolete_files(self):
        files = set(File(f) for f in (
            'dns.2014.Y.mtbl',
            'dns.201501.M.mtbl',
            'dns.20150201.W.mtbl',
            'dns.20150208.D.mtbl',
            'dns.20150209.0000.H.mtbl',
            'dns.20150209.0100.X.mtbl',
            'dns.20150209.0110.m.mtbl'
            ))
        obsolete = set(File(f) for f in (
            'dns.2012.Y.mtbl',
            'dns.20130108.W.mtbl',
            'dns.20130202.D.mtbl',
            'dns.20130208.0100.H.mtbl',
            'dns.20130209.0020.X.mtbl',
            'dns.20130209.0109.m.mtbl'
            ))

        fs = Fileset(None, self.td)
        fs.all_local_files = files.union(obsolete)
        fs.minimal_local_files = files.union(obsolete)
        fs.remote_files = files
        fs.prune_obsolete_files()

        self.assertItemsEqual(fs.all_local_files, files)
        self.assertItemsEqual(fs.minimal_local_files, files)
        self.assertItemsEqual(fs.remote_files, files)
        self.assertItemsEqual(fs.pending_deletions, obsolete)

    def test_prune_obsolete_files_full(self):
        remote_files = set(File(f) for f in (
            'dns.2014.Y.mtbl',
            'dns.201401.M.mtbl',
            'dns.20140201.D.mtbl',
            'dns.20140201.0000.H.mtbl',
            'dns.20140201.0100.X.mtbl',
            'dns.20140201.0110.m.mtbl',
            'dns.2015.Y.mtbl',
            ))
        files = set(File(f) for f in (
            'dns.2014.Y.mtbl',
            'dns.201401.M.mtbl',
            'dns.20140201.D.mtbl',
            'dns.20140201.0000.H.mtbl',
            'dns.20140201.0100.X.mtbl',
            'dns.20140201.0110.m.mtbl',
            'dns.201501.M.mtbl',
            'dns.20150201.W.mtbl',
            'dns.20150208.D.mtbl',
            'dns.20150209.0000.H.mtbl',
            'dns.20150209.0100.X.mtbl',
            'dns.20150209.0110.m.mtbl',
            ))
        obsolete = set(File(f) for f in (
            'dns.2012.Y.mtbl',
            'dns.20130108.W.mtbl',
            'dns.20130202.D.mtbl',
            'dns.20130208.0100.H.mtbl',
            'dns.20130209.0020.X.mtbl',
            'dns.20130209.0109.m.mtbl',
            'dns.20150101.D.mtbl',
            'dns.20150101.0000.H.mtbl',
            'dns.20150101.0100.X.mtbl',
            'dns.20150101.0110.m.mtbl',
            ))

        fs = Fileset(None, self.td)
        fs.all_local_files = files.union(obsolete)
        fs.minimal_local_files = files.union(obsolete)
        fs.remote_files = remote_files
        fs.prune_obsolete_files(minimal=False)

        self.assertItemsEqual(fs.all_local_files, files)
        self.assertItemsEqual(fs.minimal_local_files, files)
        self.assertItemsEqual(fs.remote_files, remote_files)
        self.assertItemsEqual(fs.pending_deletions, obsolete)

    def test_prune_redundant_files(self):
        files = set(File(f) for f in (
            'dns.2014.Y.mtbl',
            'dns.201501.M.mtbl',
            'dns.20150201.W.mtbl',
            'dns.20150208.D.mtbl',
            'dns.20150209.0000.H.mtbl',
            'dns.20150209.0100.X.mtbl',
            'dns.20150209.0110.m.mtbl'
            ))
        redundant = set(File(f) for f in (
            'dns.201401.M.mtbl',
            'dns.20150108.W.mtbl',
            'dns.20150202.D.mtbl',
            'dns.20150208.0100.H.mtbl',
            'dns.20150209.0020.X.mtbl',
            'dns.20150209.0109.m.mtbl'
            ))

        fs = Fileset(None, self.td)
        fs.minimal_local_files = files.union(redundant)
        fs.prune_redundant_files()

        self.assertItemsEqual(fs.minimal_local_files, files)
        self.assertItemsEqual(fs.pending_deletions, redundant)

    def test_prune_redundant_files_full(self):
        files = set(File(f) for f in (
            'dns.2014.Y.mtbl',
            'dns.201501.M.mtbl',
            'dns.20150201.W.mtbl',
            'dns.20150208.D.mtbl',
            'dns.20150209.0000.H.mtbl',
            'dns.20150209.0100.X.mtbl',
            'dns.20150209.0110.m.mtbl'
            ))
        redundant = set(File(f) for f in (
            'dns.201401.M.mtbl',
            'dns.20150108.W.mtbl',
            'dns.20150202.D.mtbl',
            'dns.20150208.0100.H.mtbl',
            'dns.20150209.0020.X.mtbl',
            'dns.20150209.0109.m.mtbl'
            ))

        fs = Fileset(None, self.td)
        fs.all_local_files = files.union(redundant)
        fs.minimal_local_files = files.union(redundant)
        fs.prune_redundant_files(minimal=False)

        self.assertItemsEqual(fs.all_local_files, files.union(redundant))
        self.assertItemsEqual(fs.minimal_local_files, files)
        self.assertItemsEqual(fs.pending_deletions, [])

    def test_write_local_fileset(self):
        files = set(File(f) for f in (
            'dns.2014.Y.mtbl',
            'dns.201501.M.mtbl',
            'dns.20150201.W.mtbl',
            'dns.20150208.D.mtbl',
            'dns.20150209.0000.H.mtbl',
            'dns.20150209.0100.X.mtbl',
            'dns.20150209.0110.m.mtbl'
            ))
        redundant = set(File(f) for f in (
            'dns.201401.M.mtbl',
            'dns.20150108.W.mtbl',
            'dns.20150202.D.mtbl',
            'dns.20150208.0100.H.mtbl',
            'dns.20150209.0020.X.mtbl',
            'dns.20150209.0109.m.mtbl'
            ))

        fs = Fileset(None, self.td)
        fs.all_local_files = files.union(redundant)
        fs.minimal_local_files = files
        fs.write_local_fileset()

        fileset_path = os.path.join(self.td, 'dns.fileset')
        full_fileset_path = os.path.join(self.td, 'dns-full.fileset')

        self.assertTrue(os.path.exists(fileset_path))
        self.assertFalse(os.path.exists(full_fileset_path))

        fileset = set(File(f.strip()) for f in open(fileset_path))

        self.assertItemsEqual(files, fileset)

    def test_write_local_fileset_full(self):
        files = set(File(f) for f in (
            'dns.2014.Y.mtbl',
            'dns.201501.M.mtbl',
            'dns.20150201.W.mtbl',
            'dns.20150208.D.mtbl',
            'dns.20150209.0000.H.mtbl',
            'dns.20150209.0100.X.mtbl',
            'dns.20150209.0110.m.mtbl'
            ))
        redundant = set(File(f) for f in (
            'dns.201401.M.mtbl',
            'dns.20150108.W.mtbl',
            'dns.20150202.D.mtbl',
            'dns.20150208.0100.H.mtbl',
            'dns.20150209.0020.X.mtbl',
            'dns.20150209.0109.m.mtbl'
            ))

        fs = Fileset(None, self.td)
        fs.all_local_files = files.union(redundant)
        fs.minimal_local_files = files

        fs.write_local_fileset(minimal=False)

        fileset_path = os.path.join(self.td, 'dns.fileset')
        full_fileset_path = os.path.join(self.td, 'dns-full.fileset')

        self.assertFalse(os.path.exists(fileset_path))
        self.assertTrue(os.path.exists(full_fileset_path))

        fileset = set(File(f.strip()) for f in open(full_fileset_path))

        self.assertItemsEqual(files.union(redundant), fileset)

    def test_purge_deleted_files(self):
        files = set(File(f) for f in (
            'dns.2014.Y.mtbl',
            'dns.201501.M.mtbl',
            'dns.20150201.W.mtbl',
            'dns.20150208.D.mtbl',
            'dns.20150209.0000.H.mtbl',
            'dns.20150209.0100.X.mtbl',
            'dns.20150209.0110.m.mtbl'
            ))

        class Fail(Exception): pass
        to_delete = set(os.path.join(self.td, fn.name) for fn in files)

        for fn in set(to_delete):
            for extension in DIGEST_EXTENSIONS:
                to_delete.add('{}.{}'.format(fn, extension))

        def my_unlink(fn):
            self.assertIn(fn, to_delete)
            to_delete.remove(fn)
        os.unlink = my_unlink

        fs = Fileset(None, self.td)
        fs.pending_deletions = files
        fs.purge_deleted_files()

        self.assertItemsEqual(fs.pending_deletions, [])
        self.assertItemsEqual(to_delete, [])

    def test_load_remote_fileset(self):
        fileset_uri = 'http://example.com/dns.fileset'
        files = (
            'dns.2014.Y.mtbl',
            'dns.201501.M.mtbl',
            'dns.20150201.W.mtbl',
            'dns.20150208.D.mtbl',
            'dns.20150209.0000.H.mtbl',
            'dns.20150209.0100.X.mtbl',
            'dns.20150209.0110.m.mtbl'
            )

        def my_urlopen(obj, timeout=None):
            uri = get_uri(obj)
            self.assertEqual(uri, fileset_uri)
            fp = StringIO('\n'.join(files + ('',)))
            digest = base64.b64encode(hashlib.sha256(fp.getvalue()).digest())
            msg = httplib.HTTPMessage(fp=StringIO('Content-Length: {}\r\nDigest: SHA-256={}'.format(len(fp.getvalue()), digest)), seekable=True)
            return urllib.addinfourl(fp, msg, uri)
        urllib2.urlopen = my_urlopen

        fs = Fileset(fileset_uri, self.td)
        fs.load_remote_fileset()

        self.assertItemsEqual(fs.remote_files, (File(f) for f in files))

    def test_load_remote_fileset_apikey(self):
        fileset_uri = 'http://example.com/dns.fileset'
        files = (
            'dns.2014.Y.mtbl',
            'dns.201501.M.mtbl',
            'dns.20150201.W.mtbl',
            'dns.20150208.D.mtbl',
            'dns.20150209.0000.H.mtbl',
            'dns.20150209.0100.X.mtbl',
            'dns.20150209.0110.m.mtbl'
            )
        apikey = 'TEST APIKEY'

        headers = []

        def my_urlopen(obj, timeout=None):
            headers.extend(obj.header_items())
            uri = get_uri(obj)
            self.assertEqual(uri, fileset_uri)
            fp = StringIO('\n'.join(files + ('',)))
            digest = base64.b64encode(hashlib.sha256(fp.getvalue()).digest())
            msg = httplib.HTTPMessage(fp=StringIO('Content-Length: {}\r\nDigest: SHA-256={}'.format(len(fp.getvalue()), digest)), seekable=True)
            return urllib.addinfourl(fp, msg, uri)
        urllib2.urlopen = my_urlopen

        fs = Fileset(fileset_uri, self.td, apikey=apikey)
        self.assertEqual(fs.apikey, apikey)
        fs.load_remote_fileset()

        for k,v in headers:
            if k.lower() == 'x-api-key':
                self.assertEqual(v, apikey)
                break
        else:
            self.fail('X-API-Key header missing')

        self.assertItemsEqual(fs.remote_files, (File(f) for f in files))

    def test_load_remote_fileset_bad_content_length(self):
        fileset_uri = 'http://example.com/dns.fileset'
        files = (
            'dns.2014.Y.mtbl',
            'dns.201501.M.mtbl',
            'dns.20150201.W.mtbl',
            'dns.20150208.D.mtbl',
            'dns.20150209.0000.H.mtbl',
            'dns.20150209.0100.X.mtbl',
            'dns.20150209.0110.m.mtbl'
            )

        def my_urlopen(obj, timeout=None):
            uri = get_uri(obj)
            self.assertEqual(uri, fileset_uri)
            fp = StringIO('\n'.join(files + ('',)))
            msg = httplib.HTTPMessage(fp=StringIO('Content-Length: {}'.format(len(fp.getvalue())+1)), seekable=True)
            return urllib.addinfourl(fp, msg, uri)
        urllib2.urlopen = my_urlopen

        fs = Fileset(fileset_uri, self.td)
        with self.assertRaisesRegexp(FilesetError, r'content length mismatch'):
            fs.load_remote_fileset()

    def test_load_remote_fileset_bad_digest(self):
        fileset_uri = 'http://example.com/dns.fileset'
        files = (
            'dns.2014.Y.mtbl',
            'dns.201501.M.mtbl',
            'dns.20150201.W.mtbl',
            'dns.20150208.D.mtbl',
            'dns.20150209.0000.H.mtbl',
            'dns.20150209.0100.X.mtbl',
            'dns.20150209.0110.m.mtbl'
            )

        def my_urlopen(obj, timeout=None):
            uri = get_uri(obj)
            self.assertEqual(uri, fileset_uri)
            fp = StringIO('\n'.join(files + ('',)))
            msg = httplib.HTTPMessage(fp=StringIO('Content-Length: {}\r\nDigest: SHA-256=INVALID'.format(len(fp.getvalue()))), seekable=True)
            return urllib.addinfourl(fp, msg, uri)
        urllib2.urlopen = my_urlopen

        fs = Fileset(fileset_uri, self.td)
        with self.assertRaisesRegexp(FilesetError, r'Digest mismatch'):
            fs.load_remote_fileset()

    def test_missing_files(self):
        files = set(File(f) for f in (
            'dns.2014.Y.mtbl',
            'dns.201501.M.mtbl',
            'dns.20150201.W.mtbl',
            'dns.20150208.D.mtbl',
            'dns.20150209.0000.H.mtbl',
            'dns.20150209.0100.X.mtbl',
            'dns.20150209.0110.m.mtbl'
            ))
        missing = set(File(f) for f in (
            'dns.2012.Y.mtbl',
            'dns.20130108.W.mtbl',
            'dns.20130202.D.mtbl',
            'dns.20130208.0100.H.mtbl',
            'dns.20130209.0020.X.mtbl',
            'dns.20130209.0109.m.mtbl'
            ))

        fs = Fileset(None, self.td)
        fs.all_local_files = set(files)
        fs.minimal_local_files = set(files)
        fs.remote_files = files.union(missing)

        self.assertItemsEqual(fs.missing_files(), missing)

    def test_list_tempfiles(self):
        fs = Fileset(None, self.td)
        files = set((
            'dns.2014.Y.mtbl',
            'dns.201501.M.mtbl',
            'dns.20150201.W.mtbl',
            'dns.20150208.D.mtbl',
            'dns.20150209.0000.H.mtbl',
            'dns.20150209.0100.X.mtbl',
            'dns.20150209.0110.m.mtbl'
            ))
        for fn in files:
            open(os.path.join(self.td, fn), 'w')
            open(os.path.join(self.td, '.{}'.format(fn)), 'w')

        tempfiles = set(tempfile.mkstemp(dir=self.td, prefix='.{}.'.format(fn))[1] for fn in files)
        self.assertItemsEqual(fs.list_temporary_files(), tempfiles)
