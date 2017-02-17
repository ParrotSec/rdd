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

import getopt, os, re, string, sys

KBYTE = 1024

DEFAULT_BLOCKSIZE = 256 * KBYTE

infile = None
outfile = None
title = None
debug = 0

def error(msg):
	sys.stderr.write(msg + "\n")
	sys.exit(1)

def warn(msg):
	sys.stderr.write(msg + "\n")

def usage():
	sys.stderr.write("Usage: plot-md5.py <options> infile\n"
			+ "\t-o <output file>\n"
			+ "\t-t <title>\n"
			)
	sys.exit(1)

def commandLine():
	global debug, infile, outfile, title

	opts, args = getopt.getopt(sys.argv[1:], "do:t:")
	for opt, val in opts:
		if opt == "-d":
			debug = 1
		elif opt == "-o":
			outfile = val
		elif opt == "-t":
			title = val

	if len(args) == 1:
		infile, = args
	else:
		usage()

def readHashes(path):
	hashes = {}
	fp = file(path, "r")
	for line in fp:
		line = line.strip()
		id, md5 = line.split()
		if not (md5 in hashes):
			hashes[md5] = 1
		else:
			hashes[md5] += 1
	fp.close()
	return hashes

def byCount((m1, c1), (m2, c2)):
	return cmp(c1, c2)

def plot(hashes, outfile, title):
	if outfile == None:
		outfile = "/dev/null"
		persist = 1
		output = "x11"
	else:
		persist = 0
		output = "png"

	if title == None:
		title = infile

	if debug:
		fp = sys.stdout
	elif persist:
		fp = os.popen("gnuplot -persist >%s" % outfile, "w")
	else:
		fp = os.popen("gnuplot >%s" % outfile, "w")
	fp.write("set title \"%s\"\n" % title)
	fp.write("set nokey\n")
	fp.write("set terminal %s\n" % output)
	fp.write("set xzeroaxis\n")
	fp.write("set xlabel \"MD5 values\"\n")
	fp.write("set ylabel \"Blocks covered\"\n")
	fp.write("set xrange [0:]\n")
	fp.write("plot \"-\" using ($0 + 1):1 with linespoints\n")

	items = hashes.items()
	items.sort(byCount)
	cum = 0
	for md5, count in items:
		assert count > 0
		cum += count
		fp.write("%u\n" % cum)
		# print md5, count

	fp.close()

def main():
	commandLine()
	hashes = readHashes(infile);
	plot(hashes, outfile, title)

if __name__ == "__main__": main()
