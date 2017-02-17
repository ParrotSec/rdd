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

#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif

#include "rdd.h"
#include "rdd_internals.h"
#include "msgprinter.h"

typedef struct _RDD_LOG_MSGPRINTER {
	RDD_MSGPRINTER *next;
} RDD_LOG_MSGPRINTER;

static void log_print(RDD_MSGPRINTER *printer,
		rdd_message_t type, int errcode, const char *msg);
static int  log_close(RDD_MSGPRINTER *printer, unsigned flags);

static RDD_MSGPRINTER_OPS log_ops = {
	log_print,
	log_close
};

int
rdd_mp_open_log_printer(RDD_MSGPRINTER **printer, RDD_MSGPRINTER *next)
{	
	RDD_LOG_MSGPRINTER *log = 0;
	RDD_MSGPRINTER *p = 0;
	int rc = RDD_OK;

	rc = rdd_mp_open_printer(&p, &log_ops, sizeof(RDD_LOG_MSGPRINTER));
	if (rc != RDD_OK) {
		return rc;
	}

	log = (RDD_LOG_MSGPRINTER *) p->state;
	log->next = next;

	*printer = p;
	return RDD_OK;
}

static void
log_print(RDD_MSGPRINTER *printer, rdd_message_t type, int errcode,
	const char *msg)
{
	RDD_LOG_MSGPRINTER *log = (RDD_LOG_MSGPRINTER *) printer->state;
	time_t now_unix;
	char now_buf[64];
	struct tm *now_local;
	size_t n;

	if ((now_unix = time(NULL)) == (time_t) -1)
		goto error;
	if ((now_local = localtime(&now_unix)) == NULL)
		goto error;
	n = strftime(now_buf, sizeof now_buf, "%Y-%m-%d %T %z", now_local);
	if (n == 0 || n >= (sizeof now_buf))
		goto error;
	now_buf[(sizeof now_buf) - 1] = '\000';

	rdd_mp_print(log->next, type, errcode, "%s: %s", now_buf, msg);
	return;

error:
	/* This error condition seems rather unlikely and I
	 * do not want this routine to return an error code
	 * that needs to be tested, especially not since
	 * this routine may well be called if you are already
	 * in trouble.  Instead I settle for a missing timestamp.
	 */
	rdd_mp_print(log->next, type, errcode, "???: %s", msg);
}

static int
log_close(RDD_MSGPRINTER *printer, unsigned flags)
{
	RDD_LOG_MSGPRINTER *log = (RDD_LOG_MSGPRINTER *) printer->state;
	int rc;

	if ((flags & RDD_MP_RECURSE) != 0) {
		if ((rc = rdd_mp_close(log->next, flags)) != RDD_OK) {
			return rc;
		}
	}

	memset(log, 0, sizeof *log);
	return RDD_OK;
}
