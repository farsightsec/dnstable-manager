from __future__ import print_function
import calendar
from cStringIO import StringIO
import datetime
import errno
import glob
import os
import shutil
import sys
import tempfile
import time
import unittest
import urllib
import urllib2

def parse_datetime(s):
    """
    Parse a Y/M/D/H string and return a datetime object. The length of the
    input string implicitly identifies the time frequency (Y/M/D/H).

    Examples:

    >>> parse_datetime('20060102.1500')     # hour
    datetime.datetime(2006, 1, 2, 15, 0)
    >>> parse_datetime('20060102')          # day
    datetime.datetime(2006, 1, 2, 0, 0)
    >>> parse_datetime('200601')            # month
    datetime.datetime(2006, 1, 1, 0, 0)
    >>> parse_datetime('2006')              # year
    datetime.datetime(2006, 1, 1, 0, 0)
    >>>
    """
    fmt_times = ((13, '%Y%m%d.%H%M'), (8, '%Y%m%d'), (6, '%Y%m'), (4, '%Y'))
    for len_fmt, fmt in fmt_times:
        try:
            if len(s) == len_fmt:
                return datetime.datetime.utcfromtimestamp(calendar.timegm(time.strptime(s, fmt)))
        except ValueError:
            pass
    raise ValueError("Time data '{}' does not match any of the time formats".format(s))

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
        self.assertRaises(ValueError, parse_datetime, '')
        self.assertRaises(ValueError, parse_datetime, '2')
        self.assertRaises(ValueError, parse_datetime, '20')
        self.assertRaises(ValueError, parse_datetime, '200')
        self.assertRaises(ValueError, parse_datetime, '20060')
        self.assertRaises(ValueError, parse_datetime, '200600')
        self.assertRaises(ValueError, parse_datetime, '200613')
        self.assertRaises(ValueError, parse_datetime, '2006010')
        self.assertRaises(ValueError, parse_datetime, '20060100')
        self.assertRaises(ValueError, parse_datetime, '20060132')
        self.assertRaises(ValueError, parse_datetime, '20060102.')
        self.assertRaises(ValueError, parse_datetime, '20060102.1')
        self.assertRaises(ValueError, parse_datetime, '20060102.15')
        self.assertRaises(ValueError, parse_datetime, '20060102.150')
        self.assertRaises(ValueError, parse_datetime, '20060102.2500')
        self.assertRaises(ValueError, parse_datetime, '20060102.0060')
        self.assertRaises(ValueError, parse_datetime, '20060102.1500.')

def relative_uri(uri, fn):
    path,query = urllib.splitquery(uri)
    path,attrs = urllib.splitattr(path)
    if fn.startswith('/'):
        scheme,_,path = path.partition(':')
        host,path = urllib.splithost(path)
        new_uri = '{}://{}/{}'.format(scheme, host, fn[1:])
    else:
        parent = path.rpartition('/')[0]
        new_uri = '{}/{}'.format(parent, fn)
    if attrs:
        new_uri = '{};{}'.format(new_uri, ';'.join(attrs))
    return new_uri

class TestRelativeUri(unittest.TestCase):
    def test_relative_uri(self):
        self.assertEquals(relative_uri('http://foo/bar', 'baz'), 'http://foo/baz')
        self.assertEquals(relative_uri('http://foo/bar/baz', 'abc'), 'http://foo/bar/abc')
        self.assertEquals(relative_uri('http://foo/bar/baz', '/abc'), 'http://foo/abc')

    def test_relative_uri_attrs(self):
        self.assertEquals(relative_uri('http://foo/bar;a=b', 'baz'), 'http://foo/baz;a=b')
        self.assertEquals(relative_uri('http://foo/bar;a=b;c=d', 'baz'), 'http://foo/baz;a=b;c=d')
        self.assertEquals(relative_uri('http://foo/bar/baz;a=b;c=d', '/abc'), 'http://foo/abc;a=b;c=d')

def compute_overlap(files):
    years = set()
    quarters = set()
    months = set()
    weeks = set()
    days = set()
    hours = set()
    decaminutes = set()

    # Helper functions year_overlap(), month_overlap(), and day_overlap()
    # that check if their timestamp parameter is overlapped by a year,
    # month, or day timestamp.
    def year_overlap(dt):
        for y in years:
            if dt.year == y.year:
                return True
        return False

    def quarter_overlap(dt):
        if year_overlap(dt):
            return True
        dt_q = int((dt.month-1) / 3) * 3 + 1
        for q in quarters:
            if dt.year == q.year and dt_q == q.month:
                return True
        return False

    def month_overlap(dt):
        if quarter_overlap(dt):
            return True
        for m in months:
            if dt.year == m.year and dt.month == m.month:
                return True
        return False

    def week_overlap(dt):
        if month_overlap(dt):
            return True
        dt_wd = int((dt.day-1) / 7) * 7 + 1
        for w in weeks:
            if dt.year == w.year and dt.month == w.month and dt_wd == w.day:
                return True
        return False

    def day_overlap(dt):
        if week_overlap(dt):
            return True
        for d in days:
            if dt.year == d.year and dt.month == d.month and dt.day == d.day:
                return True
        return False

    def hour_overlap(dt):
        if day_overlap(dt):
            return True
        for h in hours:
            if dt.year == h.year and dt.month == h.month and dt.day == h.day and dt.hour == h.hour:
                return True
        return False

    def decaminute_overlap(dt):
        if hour_overlap(dt):
            return True
        dt_dm = int(dt.minute / 10) * 10
        for d in decaminutes:
            if dt.year == d.year and dt.month == d.month and dt.day == d.day and dt.hour == d.hour and dt_dm == d.minute:
                return True
        return False

    for f in sorted(files):
        if f.tl == 'Y':
            years.add(f.datetime)
        elif f.tl == 'M':
            if year_overlap(f.datetime):
                yield f
            else:
                months.add(f.datetime)
        elif f.tl == 'M':
            if quarter_overlap(f.datetime):
                yield f
            else:
                months.add(f.datetime)
        elif f.tl == 'W':
            if month_overlap(f.datetime):
                yield f
            else:
                weeks.add(f.datetime)
        elif f.tl == 'D':
            if week_overlap(f.datetime):
                yield f
            else:
                days.add(f.datetime)
        elif f.tl == 'H':
            if day_overlap(f.datetime):
                yield f
            else:
                hours.add(f.datetime)
        elif f.tl == 'X':
            if hour_overlap(f.datetime):
                yield f
            else:
                decaminutes.add(f.datetime)
        elif f.tl == 'm':
            if decaminute_overlap(f.datetime):
                yield f

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

class File(object):
    """
    Helper class for Fileset which wraps the parsing of Y/M/D/H filenames.
    """

    _valid_tl = ('Y', 'Q', 'M', 'W', 'D', 'H', 'X', 'm')

    def __init__(self, name, dname=None, uri=None):
        self.name = name
        self.dname = dname
        self.uri = uri
        self._init_tl()
        self._init_datetime()

    def __repr__(self):
        return '<File %r, tl %r, %r, dir %r, uri %r>' % (self.name, self.tl, self.datetime, self.dname, self.uri)

    def _init_tl(self):
        try:
            tl = self.name.split('.')[-2]
        except IndexError:
            raise ValueError('Unable to parse time letter from file name {}'.format(self.name))

        if not tl in File._valid_tl:
            raise ValueError('Time letter {} not in valid set {}'.format(tl, File._valid_tl))
        self.tl = tl

    def _init_datetime(self):
        base_name = os.path.basename(self.name)

        # Strip off the leading filename component and the two trailing filename components.
        # E.g., 'dns.20060102.1500.H.mtbl' -> '20060102.1500'
        # E.g., 'dns.2006.Y.mtbl' -> '2006'
        datetime_string = '.'.join(base_name.split('.')[1:-2])

        try:
            self.datetime = parse_datetime(datetime_string)
        except ValueError:
            raise ValueError('Unable to extract datetime from filename {}'.format(base_name))

    def __cmp__(self, other):
        return cmp(File._valid_tl.index(self.tl), File._valid_tl.index(other.tl)) or cmp(self.datetime, other.datetime) or cmp(self.name, other.name)

    def __hash__(self):
        return hash(self.tl) ^ hash(self.datetime) ^ hash(self.name)

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
        self.assertRaises(ValueError, File, 'test.Y.txt')
        self.assertRaises(ValueError, File, 'test.200.Y.txt')

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

class Fileset(object):
    def __init__(self, uri, dname, base='dns', extension='mtbl'):
        """
        Create a new Fileset object.

        'dname' is the destination directory containing files.
        'base' is the filename prefix (e.g., "dns", "dnssec").
        'extension' is the filename suffix (e.g., "mtbl").

        The Fileset will be initialized with all files named like
        '{dname}/{base}.*.[YMWDHXm].{extension}'.
        """

        self.uri = uri
        self.dname = dname
        self.base = base
        self.extension = extension

        self.local_files = set()
        self.remote_files = set()
        self.pending_deletions = set()

        if not os.path.isdir(dname):
            raise Exception('Unable to open fileset directory: {}'.format(dname))

    def load_local_fileset(self):
        g_expr = '{}/{}.*.[YQMWDHXm].{}'.format(self.dname, self.base, self.extension)
        self.local_files = set(File(os.path.basename(fname)) for fname in glob.glob(g_expr))

    def prune_obsolete_files(self):
        self.pending_deletions.update(self.local_files.difference(self.remote_files).difference(compute_overlap(self.local_files.union(self.remote_files))))
        self.local_files.difference_update(self.pending_deletions)

    def prune_redundant_files(self):
        self.pending_deletions.update(compute_overlap(self.local_files))
        self.local_files.difference_update(self.pending_deletions)

    def write_local_fileset(self):
        fileset_fname = os.path.join(self.dname, self.base + '.fileset')
        
        # Read the old fileset, if it exists.
        try:
            old_fileset = set(open(fileset_fname).readlines())
        except IOError as e:
            if e.errno == errno.ENOENT:
                old_fileset = set()
            else:
                raise

        if old_fileset.symmetric_difference(f.name for f in self.local_files) or not os.path.exists(fileset_fname):
            with tempfile.NamedTemporaryFile(prefix='.{}.'.format(os.path.basename(fileset_fname)), dir=os.path.dirname(fileset_fname), delete=True) as out:
                for f in sorted(self.local_files):
                    print (f.name, file=out)
                out.file.close()
                os.chmod(out.name, 0o644)
                os.rename(out.name, fileset_fname)
                out.delete = False

    def purge_deleted_files(self):
        for f in sorted(self.pending_deletions):
            fn = os.path.join(self.dname, f.name)
            self.log('Unlinking {}'.format(fn))
            try:
                os.unlink(fn)
            except OSError as e:
                if e.errno == errno.ENOENT:
                    self.log('File vanished {}'.format(fn))
                else:
                    raise
            self.pending_deletions.remove(f)

    def load_remote_fileset(self):
        self.log('Retrieving {}'.format(self.uri))
        fp = urllib2.urlopen(self.uri)
        self.remote_files = set()
        for fname in fp:
            fname = fname.rstrip()

            # TODO log warnings
            if os.path.basename(fname) != fname:
                continue
            if not fname.startswith('{}.'.format(self.base)):
                continue
            if not fname.endswith('.{}'.format(self.extension)):
                continue

            self.remote_files.add(File(fname, dname=self.dname, uri=relative_uri(self.uri, fname)))

    def missing_files(self):
        return self.remote_files.difference(self.local_files)

    def log(self, msg, stream=sys.stdout):
        print (msg, file=stream)

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

        self.assertItemsEqual(fs.local_files, (File(fn) for fn in fileset))

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
        fs.local_files = files.union(obsolete)
        fs.remote_files = files
        fs.prune_obsolete_files()

        self.assertItemsEqual(fs.local_files, files)
        self.assertItemsEqual(fs.remote_files, files)
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
        fs.local_files = files.union(redundant)
        fs.prune_redundant_files()

        self.assertItemsEqual(fs.local_files, files)
        self.assertItemsEqual(fs.pending_deletions, redundant)

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
        fs.local_files = files.union(redundant)
        fs.prune_redundant_files()

        self.assertItemsEqual(fs.local_files, files)
        self.assertItemsEqual(fs.pending_deletions, redundant)

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
        def my_unlink(fn):
            self.assertIn(fn, to_delete)
            to_delete.remove(fn)
        os.unlink = my_unlink

        fs = Fileset(None, self.td)
        fs.log = TestFileset.noop
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

        def my_urlopen(uri):
            self.assertEqual(uri, fileset_uri)
            return StringIO('\n'.join(files + ('',)))
        urllib2.urlopen = my_urlopen

        fs = Fileset(fileset_uri, self.td)
        fs.load_remote_fileset()

        self.assertItemsEqual(fs.remote_files, (File(f) for f in files))

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
        fs.local_files = set(files)
        fs.remote_files = files.union(missing)

        self.assertItemsEqual(fs.missing_files(), missing)
