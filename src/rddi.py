#!/usr/bin/env python

# Copyright (c) 2002 - 2006, Netherlands Forensic Institute
# 
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. Neither the name of the Institute nor the names of its contributors
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

import os, re, string, sys, types

DEFAULT_PORT = "4832"
DEFAULT_INTERVAL = "5"
DEFAULT_OUT = None
DEFAULT_LOG = "rdd-%u.log" % os.getpid()
DEFAULT_BLKSIZE = "512k"
DEFAULT_MINBLKSIZE = "512"
DEFAULT_MAXERR = 0
DEFAULT_RECOVERYLEN = 3

class Cmd:
	def __init__(self):
		self.mode = None
		self.verb = None
		self.progress = None
		self.md5 = None
		self.sha1 = None
		self.host = None
		self.src = None
		self.dst = None
		self.log = None
		self.blksize = None
		self.offset = None
		self.count = None
		self.short = "rdd"
		self.long = "rdd"
		self.minblksize = None
		self.maxerr = None

	def add_opt(self, sopt, lopt, arg=None):
		if arg:
			self.short = self.short + (" %s %s" % (sopt, arg))
			self.long = self.long + (" %s %s" % (lopt, arg))
		else:
			self.short = self.short + (" %s" % sopt)
			self.long = self.long + (" %s" % lopt)

	def add_raw(self, str):
		self.short = self.short + (" %s" % str)
		self.long = self.long + (" %s" % str)

	def build_cmdline(self):
		cmd = "rdd"
		if self.mode == "client":
			self.add_opt("-C", "--client")
		elif self.mode == "server":
			self.add_opt("-S", "--server")
	
		if self.verb:
			self.add_opt("-v", "--verbose")
		if self.progress:
			self.add_opt("-P", "--progress", self.progress)
		if self.md5:
			self.add_opt("--md5", "--md5")
		if self.sha1:
			self.add_opt("--sha1", "--sha1")
		if self.blksize:
			self.add_opt("-b", "--block-size", self.blksize)
		if self.minblksize:
			self.add_opt("-m", "--min-block-size", self.minblksize)
		if self.maxerr:
			self.add_opt("-M", "--max-error", self.maxerr)
		if self.offset:
			self.add_opt("-o", "--offset", self.offset)
		if self.count:
			self.add_opt("-c", "--count", self.count)
		if self.port:
			self.add_opt("-p", "--port", self.port)
		if self.log:
			self.add_opt("-l", "--log-file",  self.log)
		if self.src:
			self.add_raw(self.src)
		if self.host and self.dst:
			self.add_raw("%s:%s" % (self.host, self.dst))
		elif self.dst:
			self.add_raw("%s" % self.dst)
	
	def long_cmd(self):
		return self.long

	def short_cmd(self):
		return self.short

intro_text = """
This is the rdd command-line wizard.  It will help you
construct a sensible rdd command line.  The wizard will ask
a series of questions and will eventually print a command line
that is based on your answers.  Optionally, the wizard will also
run this command.

Type '?' to obtain help information about a question.

Rdd comes with a man page.  Type 'man rdd' in another window to read it.
"""

size_help = """
The %s is given in bytes.  You may use the following
multipliers: b or B (512-byte block or sector); k or K (kilobyte);
m or M (megabyte); g or G (gigabyte).  There should be no space between
a number and its multiplier.
"""

mode_text = """
In which mode do you want to run rdd [local|client|server]?
"""
mode_help = """
In local mode, you can copy data within a single file system.
(If you have NFS mount points, your file system may span
multiple hosts.)

In client mode, you can copy a file across the network to a server host.
On the server host, you must start a server process that will receive
and process the data that you send to it.

In server mode, you can receive a file from an rdd client on
another host.
"""

verb_text = """Do you want rdd to be verbose?"""
verb_help = """
In verbose mode, rdd prints more informative messages than it
normally does.  This may be useful for debugging a problem or just
for understanding what's happening.
"""

source_text = """Input file:"""
source_help = """
This is the name of the file from which data will be read.
"""

desthost_text = """Destination host:"""
desthost_help = """
You can specify the destination host's DNS host name (e.g.,
foo.bar) or its IPv4 address in dotted quad notation (e.g.,
192.168.1.1).  The DNS host name will work only if your client
host knows how to resolve DNS host names to IPv4 addresses.
"""

port_text = """At which TCP port does the rdd server listen?"""
port_help = """
By default, rdd clients and servers assume that rdd requests
must be sent to TCP port 3482 on the server host.  If you
want to use another port, then you should specify another
number, both at the client and the server side.  Remember
that ports 0-1023 are reserved for privileged uses.  Port
numbers higher than 65535 are invalid.
"""

destfile_text = """Output file:"""
destfile_help = """
This is the name of the output file.  All directories leading up to
the output file should already exist; rdd will not create missing
directories.

If you do not want to create an output file, just hit ENTER.

If you use output splitting, rdd will prefix the name of each output
file with a sequence number.  Do not specify such prefixes manually.
For example, /tmp/disk.img will automatically be converted to
/tmp/000-disk.img, /tmp/001-disk.img, and so on.
"""

hash_text = """Hash the data?"""
hash_help = """
A (cryptographic) hash is a fixed-length, digital finger print
of a sequence of bytes that is computed by a well-defined
hash algorithm.
It is very difficult to find two inputs that
have the same hash value (in a reasonable amount of time).

Computing a cryptographic hash over the data allows you to
verify the data's integrity at another time by recomputing
the hash value.

The hash is computed only over the data that is read.  Rdd does not
guarantee that the data that it reads will be written to disk (or to the
network correctly).  To make sure that you have stored the data correctly,
we recommend that you recompute the hash value over the stored data
and compare it to the hash value computed by rdd.  They should be
equal.

You can use the following hash algorithms: MD5 and SHA1.
"""

logfile_text = """Log file:"""
logfile_help = """
This is the name of file in which rdd's messages will be logged.
These messages will always be visible on your screen.
If you do not wish to log rdd messages to a file, just hit ENTER.
"""

md5_text = """Use MD5?"""
md5_help = """
MD5 is a cryptographic hash algorithm.  It generates a 128-bit
hash value from an arbitrary input stream.  For a full description, see
RFC 1321.  MD5 is widely used, but has known weaknesses.  SHA1 is
considered stronger, but is not used as widely.  Many hash-value databases
consist only of MD5 hash values.
"""

sha1_text = """Use SHA1?"""
sha1_help = """
SHA-1 is a cryptographic hash algorithm.  It generates a 160-bit
hash value from an arbitrary input stream.  For a full description, see
FIP 180 (a U.S. Federal Information Processing standard).
SHA1 is considered a strong hash algorithm.
"""

inetd_text = """Use (x)inetd to start the rdd server process?"""
inetd_help = """
If you say yes here, you will have to configure (x)inetd
to start rdd.  Make sure that (x)inetd passes the options
'-S' (server mode) and '-i' (inetd) to rdd.
"""

overwrite_text = """Overwrite existing files?"""
overwrite_help = """
If you say no here, rdd will refuse to overwrite existing files.
This is the default behavior, because it prevents silly accidents.
If you say yes, rdd will overwrite existing files without asking
for your confirmation.
"""

progress_text = """
How often should rdd report progress [seconds; 0 means never]?
"""
progress_help = """
If you say 0 here, rdd will not print periodic progress messages.

If you specify some positive number s, rdd will print a progress
line every s seconds (approximately).  The progress line tells you
how much of the data has already been copied and gives the current
copy speed.
"""

section_text = """
Do you wish to copy all input data or do you wish to select a section
of the input data?
"""
section_help = """
With rdd, you can choose to copy a subsequence of the input data.
You can select a single, contiguous range of bytes.

If you wish to select a subsequence of your input data for
copying, say yes.  Otherwise, say no.
"""

run_text = """Run now?"""
run_help = """
Type 'yes' to run your rdd command now.
Type 'no' to quit.
"""

blksize_text = """Block size?"""
blksize_help = """
The block size specifies how much data rdd will read and write
at a time.  The block size should be (significantly) less than
the size of your machine's physical memory.  I cannot give
exact guidelines, but very small block sizes will slow down the copying and
very large block sizes waste memory without improving performance.
""" + (size_help % "block size")

minblksize_text = """Minimum block size?"""
minblksize_help = """
When read errors occur, rdd will progressively reduce its block size.
This way, the amount of data lost to read errors is reduced.
You must specify the minimum block size.  Rdd will not use blocks
that are smaller than this size.  If a read error occurs, at least
this many bytes of data will be lost. 
""" + (size_help % "block size")

maxerr_text = """Quit after how many read errors?"""
maxerr_help = """
By default, rdd will not exit after read errors.  With this option,
you can force rdd to exit after a specified number of read errors.
If you specify 0, rdd allows infinitely many read errors.
"""

slice_text = """Process entire input file?"""
slice_help = """
Say 'yes' if you want to process all bytes in the input file.
Say 'no' if you want to process a subsequence of the input file.
"""

offset_text = """Input file offset (in bytes)?"""
offset_help = """
Specify at which input file offset rdd should start reading data.
""" + (size_help % "offset")

count_text = """How many bytes to read?"""
count_help = """
Specify how many input bytes should be read.
""" + (size_help % "count")

recover_text = """Do you want to modify any recovery options?"""
recover_help = """
Recovery options include the minimum recovery block size, 
the retry count, and the maximum number of read errors.
"""

Q = {
	"blksize" : (blksize_text, blksize_help),
	"count" : (count_text, count_help),
	"destfile" : (destfile_text, destfile_help),
	"desthost" : (desthost_text, desthost_help),
	"hash" : (hash_text, hash_help),
	"logfile" : (logfile_text, logfile_help),
	"maxerr" : (maxerr_text, maxerr_help),
	"md5" : (md5_text, md5_help),
	"minblksize" : (minblksize_text, minblksize_help),
	"mode" : (mode_text, mode_help),
	"offset" : (offset_text, offset_help),
	"port" : (port_text, port_help),
	"progress" : (progress_text, progress_help),
	"recover" : (recover_text, recover_help),
	"run" : (run_text, run_help),
	"sha1" : (sha1_text, sha1_help),
	"slice" : (slice_text, slice_help),
	"source" : (source_text, source_help),
	"verb" : (verb_text, verb_help),
}

def ask(elt, answers, default=None):
	q, help = Q[elt]
	q = string.strip(q)
	if default:
		q = q + (" [%s]" % default)
	q = "\n*** " + q + "  "
	sys.stdout.write(q)
	fp = sys.stdin
	while 1:
		ans = fp.readline()
		ans = string.strip(ans)
		if ans == "?":
			fprint(help, 4)
		elif ans == "":
			if default != None:
				return default
		elif type(answers) == types.StringType:
			if re.match(answers, ans, re.I) != None:
				return ans
		elif type(answers) in (types.TupleType, types.ListType):
			ans = string.lower(ans)
			if ans in answers:
				return ans
		else:
			assert 0
		# No valid or no final answer; ask again
		sys.stdout.write(q)
	return ans

def ask_yn(elt, default=None):
	ans = ask(elt, ("([yY]|[yY][eE][sS]|[nN]|[nN][oO])"), default)
	ans = string.lower(ans)
	if ans[0] == "y":
		return 1
	else:
		return 0

def ask_num(elt, default=None):
	return ask(elt, "\d+", default)

def ask_file(elt, default=None):
	return ask(elt, ".+", default)

def ask_opt_file(elt, default=None):
	if default == None:
		default = ""
	f = ask_file(elt, default)
	if len(f) == 0:
		return None
	else:
		return f

def format(str, indent):
	spaces = " " * indent
	width = 75 - indent
	fp_wr, fp_rd = os.popen2("fmt -%u" % width)
	fp_wr.write(str)
	fp_wr.close()
	formatted  = ""
	for line in fp_rd.readlines():
		formatted = formatted + spaces + line
	fp_rd.close()
	return formatted

def fprint(txt, indent=0):
	print string.rstrip(format(txt, indent))

def ask_hash(cmd):
	if not ask_yn("hash", "yes"):
		cmd.md5 = None
		cmd.sha1 = None
		return
	if not ask_yn("md5", "yes"):
		cmd.md5 = None
		sha_default = "yes"
	else:
		cmd.md5 = 1
		sha_default = "no"
	if not ask_yn("sha1", sha_default):
		cmd.sha1 = None
	else:
		cmd.sha1 = 1

def ask_size(elt, default=None):
	return ask(elt, "\d+[bBkKmMgG]?", default)
	
def ask_recover(cmd):
	if ask_yn("recover", "no"):
		cmd.blksize = ask_size("minblksize", DEFAULT_MINBLKSIZE)
		cmd.max_err = ask_num("maxerr", DEFAULT_MAXERR)

def ask_slice(cmd):
	if not ask_yn("slice", "yes"):
		cmd.offset = ask_size("offset")
		cmd.count = ask_size("count")
	else:
		cmd.offset = None
		cmd.count = None

def toplevel():
	global mode, verb, src, dst, host, port, progress, log
	global blksize, offset, count

	cmd = Cmd()

	print
	fprint(intro_text)

	cmd.mode = ask("mode", ("local", "client", "server"), "local")
	cmd.verb = ask_yn("verb", "no")
	cmd.progress = ask_num("progress", DEFAULT_INTERVAL)
	ask_hash(cmd)

	if cmd.mode == "local":
		cmd.src = ask_file("source")
		cmd.port = None
		cmd.host = None
		cmd.dst = ask_opt_file("destfile", DEFAULT_OUT)
		cmd.log = ask_opt_file("logfile", DEFAULT_LOG)
		cmd.blksize = ask_size("blksize", DEFAULT_BLKSIZE)
		ask_recover(cmd)
		ask_slice(cmd)
	elif cmd.mode == "client":
		cmd.src = ask_file("source")
		cmd.host = ask_file("desthost", "localhost")
		cmd.port = ask_num("port", DEFAULT_PORT)
		cmd.dst = ask_opt_file("destfile", DEFAULT_OUT)
		cmd.log = ask_opt_file("logfile", DEFAULT_LOG)
		cmd.blksize = ask_size("blksize", DEFAULT_BLKSIZE)
		ask_recover(cmd)
		ask_slice(cmd)
	elif cmd.mode == "server":
		cmd.src = None
		cmd.host = None
		cmd.port = ask_num("port", DEFAULT_PORT)
		cmd.dst = None
		cmd.log = ask_opt_file("logfile", DEFAULT_LOG)
		cmd.blksize = None
		cmd.offset, cmd.count = None, None

	cmd.build_cmdline()
	cmd_short = cmd.short_cmd()
	cmd_long = cmd.long_cmd()
	print "Command lines:\n\n\t%s\n\n\t%s" % (cmd_short, cmd_long)

	if ask_yn("run", "no"):
		os.system(cmd_short)

toplevel()
