Farsight DNSTable Manager
=========================

This tool is designed to maintain local copies of DNSTable filesets.
Given an URL it will periodically download a remote fileset descriptor and
all files referenced within.  It will maintain a local fileset file that
references all files present on the local system and correctly handles files
as they are merged over time (eg. from hourly to daily).

Installation
------------

Installation via Debian package requires the Farsight apt repository to be
installed.:

    apt-get install dnstable-manager
    # create /etc/dnstable-manager/dnstable-manager.yaml

    service dnstable-manager restart
    # OR
    apt-get install dnstable-manager-run # if you don't have systemd

Otherwise, you can use Python's package manager:

    python setup.py install
    # create /etc/dnstable-manager/dnstable-manager.yaml
    # configure your system to run dnstable-manager as a service

Running DNSTable Manager
------------------------

dnstable-manager works best when run as a systemd or runit service.  Both
configurations are included in the source tree and debian packages.  The
--config option is required.:

    usage: dnstable-manager [-h] [--config CONFIG] [--verbosity]
    
    Maintains local copies of remote filesets. Supports http, https, ftp, file,
    rsync, rsync+rsh uri schemas.
    
    optional arguments:
      -h, --help       show this help message and exit
      --config CONFIG  Path to configuration file.
      --verbosity, -v  Verbosity level. Repeat to increase.

Example:

    dnstable-manager --config /etc/dnstable-manager/dnstable-manager.yaml

Configuration
-------------

Configuration of dnstable-manager is done with a single YAML file specified
with the --config parameter on the command line.  It consists of three
sections:

```yaml
    manager:
        log_stream: 'stderr' or 'stdout'
        log_file: path to rotatable log file
        syslog: 'true' or 'false'
	syslog_facility: uppercase_name_of_facility
        log_level: one of 'CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG'
    downloader:
        max_downloads: integer, at least 3 recommended
        download_timeout: time in seconds
        retry_timeout: time in seconds
        tempdir: directory on filesystem with enough space, needed for rsync
        rsync_rsh: command line for RSYNC_RSH variable
	ssl_ca_file: ssl ca for validation
	ssl_keyfile: ssl client key
	ssl_certfile: ssl client cetificate
	ssl_ciphers: allows you to override the list of ssl ciphers to be used (default is considered secure at time of writing)
    filesets:
        name of fileset:
            uri: REQUIRED, remote uri to fileset, rsync+rsh protocol supported
            realm: optional HTTP authentication realm
            username: HTTP authentication username
	    password: HTTP authentication password
            destination: REQUIRED, local destination dir of fileset
	    base: REQUIRED, prefix of fileset name (e.g. dns, dnssec, dns--com)
	    extension: REQUIRED, suffix of files in set (e.g. mtbl)
            frequency: REQUIRED, how often to download the fileset
            validator: validation command (filename is passed as argv[1])
            minimal: optional boolean to enable base-full.fileset
```
