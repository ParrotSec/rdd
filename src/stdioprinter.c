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
#include "config.h"
#endif

#include <string.h>

#include "rdd.h"
#include "rdd_internals.h"
#include "msgprinter.h"

typedef struct _RDD_STDIO_MSGPRINTER {
	FILE *stream;
} RDD_STDIO_MSGPRINTER;

static void stdio_print(RDD_MSGPRINTER *printer,
		rdd_message_t type, int errcode, const char *msg);
static int  stdio_close(RDD_MSGPRINTER *printer, unsigned flags);

static RDD_MSGPRINTER_OPS stdio_ops = {
	stdio_print,
	stdio_close
};

int
rdd_mp_open_stdio_printer(RDD_MSGPRINTER **printer, FILE *stream)
{	
	RDD_STDIO_MSGPRINTER *stdio = 0;
	RDD_MSGPRINTER *p = 0;
	int rc = RDD_OK;

	rc = rdd_mp_open_printer(&p, &stdio_ops, sizeof(RDD_STDIO_MSGPRINTER));
	if (rc != RDD_OK) {
		return rc;
	}

	stdio = (RDD_STDIO_MSGPRINTER *) p->state;
	stdio->stream = stream;

	*printer = p;
	return RDD_OK;
}

static void
stdio_print(RDD_MSGPRINTER *printer, rdd_message_t type, int errcode,
	const char *msg)
{
	RDD_STDIO_MSGPRINTER *stdio = (RDD_STDIO_MSGPRINTER *) printer->state;

	fprintf(stdio->stream, "%s\n", msg);
}

static int
stdio_close(RDD_MSGPRINTER *printer, unsigned flags)
{
	RDD_STDIO_MSGPRINTER *stdio = (RDD_STDIO_MSGPRINTER *) printer->state;

	memset(stdio, 0, sizeof *stdio);
	return RDD_OK;
}
