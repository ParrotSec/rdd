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


# A unit test for the rdd message printer.

import sys, os, string

global logfile
global stderr_logfile
global configfile

def usage():
	sys.stderr.write("Usage: python tmsgprinter logfile "  \
		    "stderr-logfile configfile\n")
	sys.exit(1)

def commandLine():
	global logfile, stderr_logfile, configfile

	if len(sys.argv) != 4:
		usage()
	logfile, stderr_logfile, configfile = sys.argv[1:4]	

def readFile(path):
	fp = file(path, 'rb')
	buf = fp.read()
	fp.close()
	return buf

def compareFiles(file1, file2):
	buf1 = readFile(file1)
	buf2 = readFile(file2)

	return buf1 == buf2
	
def fileReadLine(filename):
	'Reads the first line in a file.'

	fp = file(filename, "r")
	line = fp.readline()
	if len(line) == 0:
		sys.stderr.write("The file %s seems to be too short. "
			"Problem with reading error code %i\n" 
			% (filename, seq))
		sys.exit(1)
	fp.close()
	return line

def checkCode(cells):
	global logfile, stderr_logfile, configfile

	# Clean up; logfiles are read only
 	ec = os.system("rm -f %s %s" %(logfile, stderr_logfile))

	# Generate the files with the error messages
	call = ('./tmsgprinter %s "%s" %s 2>%s'
		% (logfile, cells[1], cells[0], stderr_logfile))

	ec = os.system(call)
	if ec:
		sys.stderr.write("Error generating error messages\n")
		sys.exit(1)

	# Both files should be the same.
	# If not, there has been an error.
	# If so, only one file has to be checked.
	if not compareFiles(logfile, stderr_logfile):
		sys.stderr.write("The outputs to the logfile and stderr " 
			"for error code %s do not match\n" %cells[0])
		sys.exit(1)

	# Check the error from RDD
	code = cells[0].lower()
	if code[0] == "r":
		errline = cells[2].strip()		# RDD
	else:
		errline = os.strerror(int(code[1:]))	# Unix

	line = fileReadLine(logfile)

	if line.find(errline) == -1:
		sys.stderr.write('Error string "%s" not found in file %s\n' 
			% (errline, logfile))
		sys.exit(1)

	# Check the error from the unit test
	errmsg = cells[1].strip()
	if (line.find(errmsg) == -1):
		sys.stderr.write('Error string "%s" not found in file %s\n' 
			% (errmsg, stderr_logfile))
		sys.exit(-1)
	
	# Clean up
 	ec = os.system("rm -f %s %s" %(logfile, stderr_logfile))

def checkCodes():
	'Checks all error codes that are listed in our config file.'

	global configfile
	
	fp = file(configfile, "r")
	
	num = 0
	while 1:
		line = fp.readline()
		if len(line) <= 0:
			break		# reached end of file

		line = line.strip()
		if len(line) == 0 or line[0] == '#':
			continue	# skip empty line or comment

		cells = line.split(",")
		code = cells[0].lower()
		if code[0] == "r" or code[0] == "u":
			num += 1
			checkCode(cells)
			print "Error code ", code, " OK"
		else:
			# Unknown error code
			sys.stderr.write("unknown error code: %s\n" % cells[0])
			sys.exit(1)
	fp.close()

def main():
	commandLine()
	checkCodes()

if __name__ == "__main__": main()
