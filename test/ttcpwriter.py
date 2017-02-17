#!/usr/bin/python

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

# Unit test script for the TCP writer module of rdd.
# Copyright Netherlands Forensic Institute, 2004

# This script will fork and run ttcpwriter and netcat (nc) at the same time. ttcpwriter will write data to a TCP port at localhost. nc will read it and save the data to a file. This script will verify the stored data.

import sys, os, struct, md5, time, string

def usage():
	sys.stderr.write('Usage: python ttcpwriter.py\n')
	sys.exit(1)

def conv_net_order(netw_order):
	# Sizes are sent as two 32-bit integers in network byte order.
	# The least significant 32 bits are sent first.

	low = long(struct.unpack('!I', netw_order[:4])[0])
	high = long(struct.unpack('!I', netw_order[4:8])[0])
	return long((pow(2, 32) * high) + low)
	
def error(msg):
	sys.stderr.write(msg + '\n')
	sys.exit(1)

def main():
	ret = os.fork()
	if ret == 0:
		# Child process runs netcat.
		os.system("nc -l -p 1111 > netcat-dump.img")
	else:
		# Parent process runs the ttcpwriter.

		time.sleep(2)	# Wait for child to start up.

		# Run ttcpwriter.
		if (os.system("./ttcpwriter") != 0):
			error('The ttcpwriter program failed. Abort.')

		# Wait until the netcat child exits.
		if (os.waitpid(ret, 0)[1] != 0):
			error('Netcat (nc) exited with an error. Abort')

		# Read the output file produced by netcat.
		fp = file("netcat-dump.img", "rb")
		buf = fp.read()
		fp.close()
		if len(buf) == 0:
			error('no data received by nc. Abort.')

		flen = conv_net_order(buf[:8])
		fsize = conv_net_order(buf[8:16])
		blocksize = conv_net_order(buf[16:24])
		splitsize = conv_net_order(buf[24:32])
		flags = conv_net_order(buf[32:40])

		# Verify the MD5 hash value of the file that was transported.
		m = md5.new()
		m.update(buf[(flen+40):])
		hash = m.hexdigest().lower()

		md = md5.new()
		fp = file('image.img', 'rb')
		while 1:
			buf = fp.read(65536)
			if len(buf) == 0:
				break
			md.update(buf)
		fp.close()

		if (hash != md.hexdigest()):
			print 'Hash of the transported file is not correct. ' \
				'Abort.'
			sys.exit(1)
		else:
			print 'Hash of the transported file is correct.'	
			sys.exit(0)
		
if __name__=="__main__": main()
