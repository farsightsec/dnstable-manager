Farsight DNSTable Manager
-------------------------

This tool is designed to maintain local copies of DNSTable filesets.
Given an URL it will periodically download a remote fileset descriptor and
all files referenced within.  It will maintain a local fileset file that
references all files present on the local system and correctly handles files
as they are merged over time (eg. from hourly to daily).
