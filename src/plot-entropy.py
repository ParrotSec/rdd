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
#


import getopt, os, re, string, sys

USAGE = "python plot.py file range"

KBYTE = 1024
MBYTE = KBYTE * KBYTE
GBYTE = KBYTE * MBYTE

DEFAULT_BLOCKSIZE = 256 * KBYTE

infile = None
outfile = None
title = None
debug = 0
blocksize = None
xlo = None
xhi = None
exclude = None

def error(msg):
	sys.stderr.write(msg + "\n")
	sys.exit(1)

def warn(msg):
	sys.stderr.write(msg + "\n")

def usage():
	sys.stderr.write("Usage: plot-entropy.py <options> infile [lo hi]\n"
			+ "\t-o <output file>\n"
			+ "\t-t <title>\n"
			+ "\t-b <block size>\n"
			+ "\t-x <exclude file>\n")
	sys.exit(1)

def commandLine():
	global debug, exclude, infile, outfile, xlo, xhi, blocksize, title

	opts, args = getopt.getopt(sys.argv[1:], "b:do:t:x:")
	for opt, val in opts:
		if opt == "-b":
			blocksize = long(val)
		if opt == "-d":
			debug = 1
		elif opt == "-o":
			outfile = val
		elif opt == "-t":
			title = val
		elif opt == "-x":
			exclude = val

	if len(args) == 1:
		infile, = args
	elif len(args) == 3:
		infile, xlo, xhi = args
		xlo = long(xlo)
		xhi = long(xhi)
	else:
		usage()

def readExcludeFile(path):
	fp = file(path)
	xblocks = []
	for line in fp:
		line = line.strip()
		blocknum, nblock = line.split()
		xblocks.append((long(blocknum), long(nblock)))
	fp.close()
	return xblocks

def getFileInfo(infile):
	bsize = None
	ncol = None
	try:
		fp = file(infile, "r")
		hdrline = fp.readline()
		dataline = fp.readline()
		cols = dataline.split()
		ncol = len(cols)
		fp.close()
		m = re.match("# blocksize (\d+)", hdrline)
		if m != None:
			bsize = long(m.group(1))
		else:
			warn("old-style input file; no block size comment")
	except:
		raise
		pass
	return bsize, ncol

def plotRange(fp, path, lo, hi, mult, col):
	fp.write(" \"%s\"" % path)
	# fp.write(" using ($0 * %f):%u" % (mult, col))
	if hi != None:
		fp.write(" using (($0 >= %lu) && ($0 < %lu) ? $0* %f : 1/0):%u" % (lo, hi, mult, col))
	else:
		fp.write(" using ($0 >= %lu ? $0* %f : 1/0):%u" % (lo, mult, col))
	fp.write(" with points pointtype 2, \\")
	fp.write("\n")

def plot(infile, xlist, outfile, title, xlo, xhi):
	if outfile == None:
		outfile = "/dev/null"
		persist = 1
		output = "x11"
	else:
		persist = 0
		output = "png"

	if title == None:
		title = infile

	bs, ncol = getFileInfo(infile)

	if bs != None and blocksize != None:
		if bs != blocksize:
			error("Block size in file differs " +
				"from command-line block size")
	if bs == None:
		bs = blocksize
	if bs == None:
		warn("Assuming default block size (%u)" % DEFAULT_BLOCKSIZE)
		bs = DEFAULT_BLOCKSIZE
	gbmult = float(bs) / float(GBYTE)

	if ncol == None:
		error("Unknown column count in %s" % infile)
	entropyCol = ncol

	if debug:
		fp = sys.stdout
	elif persist:
		fp = os.popen("gnuplot -persist >%s" % outfile, "w")
	else:
		fp = os.popen("gnuplot >%s" % outfile, "w")
	fp.write("set title \"%s (block size: %u Kbyte)\"\n" \
		% (title, float(bs) / KBYTE))
	fp.write("set nokey\n")
	fp.write("set terminal %s\n" % output)
	fp.write("set xzeroaxis\n")
	fp.write("set xlabel \"Disk Location (GB)\"\n")
	fp.write("set ylabel \"Entropy\"\n")
	if xlo == None:
		fp.write("set xrange [0:]\n")
	else:
		print ("set xrange [%d:%d]\n" % (xlo, xhi))
		fp.write("set xrange [%d:%d]\n" % (xlo, xhi))
	# fp.write("set yrange [0.0:16.1]\n")
	# fp.write("plot \"< awk '{print $1, $6}' %s\"" % infile)

	prevnum = 0L
	fp.write("plot ")
	for blocknum, nblock in xlist:
		plotRange(fp, infile, prevnum, blocknum, gbmult, entropyCol)
		prevnum = blocknum + nblock
	plotRange(fp, infile, prevnum, None, gbmult, entropyCol)
	fp.write("0\n")
	fp.close()

def main():
	commandLine()
	if exclude != None:
		excludeList = readExcludeFile(exclude)
	else:
		excludeList = []
	plot(infile, excludeList, outfile, title, xlo, xhi)

if __name__ == "__main__": main()
