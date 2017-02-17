/*
 * Copyright (c) 2002 - 2006, Netherlands Forensic Institute
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.

 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */



#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>

#include "rdd.h"
#include "rdd_internals.h"

static int
copymsg(char *buf, unsigned bufsize, char *msg)
{
	if ((strlen(msg) + 1) > bufsize) {
		return RDD_NOMEM;
	}

	strncpy(buf, msg, bufsize);
	return RDD_OK;
}

static char *
get_message(int rc)
{
	switch (rc) {
	case RDD_OK:
		return "ok";
	case RDD_NOMEM:
		return "out of memory";
	case RDD_BADARG:
		return "bad argument";
	case RDD_ECOMPRESS:
		return "compression error";
	case RDD_EWRITE:
		return "write error";
	case RDD_ECLOSE:
		return "close error";
	case RDD_EEXISTS:
		return "output file already exists";
	case RDD_EOPEN:
		return "cannot open file";
	case RDD_ECONNECT:
		return "cannot connect";
	case RDD_ETELL:
		return "cannot determine current position";
	case RDD_EREAD:
		return "read error";
	case RDD_ESEEK:
		return "seek error";
	case RDD_ESPACE:
		return "insufficient space in buffer or on device";
	case RDD_ESYNTAX:
		return "syntax error";
	case RDD_ERANGE:
		return "number out of range";
	case RDD_EAGAIN:
		return "try again later";
	case RDD_NOTFOUND:
		return "not found";
	case RDD_ABORTED:
		return "operation has been aborted";
	default:
		return 0;
	}
}

int
rdd_strerror(int rc, char *buf, unsigned bufsize)
{
	char *msg;

	if (buf == 0) return RDD_BADARG;

	if ((msg = get_message(rc)) == 0) return RDD_BADARG;

	return copymsg(buf, bufsize, msg);
}
