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

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "rdd.h"
#include "rdd_internals.h"
#include "msgprinter.h"

typedef struct _RDD_MSGPRINTER_POS {
	char     *msgbuf;
	unsigned  buflen;
} RDD_MSGPRINTER_POS;

int
rdd_mp_open_printer(RDD_MSGPRINTER **printer, RDD_MSGPRINTER_OPS *ops,
	unsigned statesize)
{
	RDD_MSGPRINTER *p = 0;
	void *state = 0;
	int rc = RDD_OK;

	if ((p = calloc(1, sizeof(RDD_MSGPRINTER))) == 0) {
		rc = RDD_NOMEM;
		goto error;
	}
	if ((state = calloc(1, statesize)) == 0) {
		rc = RDD_NOMEM;
		goto error;
	}

	p->ops = ops;
	p->state = state;
	p->mask = RDD_MSG_INFO|RDD_MSG_WARN|RDD_MSG_ERROR|RDD_MSG_DEBUG;

	*printer = p;
	return RDD_OK;

error:
	*printer = 0;
	if (state != 0) free(state);
	if (p != 0) free(p);
	return rc;
}

int
rdd_mp_close(RDD_MSGPRINTER *printer, unsigned flags)
{
	RDD_MSGPRINTER_OPS *ops = printer->ops;

	if (ops->close != 0) {
		return (*ops->close)(printer, flags);
	}
	return RDD_OK;
}

RDD_UINT32
rdd_mp_get_mask(RDD_MSGPRINTER *printer)
{
	return printer->mask;
}

void
rdd_mp_set_mask(RDD_MSGPRINTER *printer, RDD_UINT32 mask)
{
	printer->mask = mask;
}

static int
mp_accept_message(RDD_MSGPRINTER *printer, rdd_message_t type)
{
	if (printer == 0) return 0;

	if (printer->ops->print == 0) return 0;

	if ((printer->mask & type) == 0) return 0;

	return 1;
}

void
rdd_mp_print(RDD_MSGPRINTER *printer,
	rdd_message_t type, int errcode, const char *fmt, ...)
{
	va_list ap;

	if (! mp_accept_message(printer, type)) return;

	va_start(ap, fmt);
	vsnprintf(printer->printbuf, sizeof(printer->printbuf), fmt, ap);
	printer->printbuf[sizeof(printer->printbuf) - 1] = '\000';
	va_end(ap);

	(*printer->ops->print)(printer, type, errcode, printer->printbuf);
}

void
rdd_mp_vmessage(RDD_MSGPRINTER *printer,
	rdd_message_t type, const char *fmt, va_list ap)
{
	if (! mp_accept_message(printer, type)) return;

	vsnprintf(printer->printbuf, sizeof(printer->printbuf), fmt, ap);
	printer->printbuf[sizeof(printer->printbuf) - 1] = '\000';

	(*printer->ops->print)(printer, type, 0, printer->printbuf);
}

void
rdd_mp_message(RDD_MSGPRINTER *printer,
	rdd_message_t type, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	rdd_mp_vmessage(printer, type, fmt, ap);
	va_end(ap);
}

static void
mp_init(RDD_MSGPRINTER_POS *pos, RDD_MSGPRINTER *printer)
{
	printer->printbuf[0] = '\000';
	pos->msgbuf = printer->printbuf;
	pos->buflen = sizeof(printer->printbuf);
}

static void
mp_vprintf(RDD_MSGPRINTER_POS *pos, const char *fmt, va_list ap)
{
	unsigned msglen;

	if (pos->buflen <= 0) return;  /* out of space */

	vsnprintf(pos->msgbuf, pos->buflen, fmt, ap);
	pos->msgbuf[pos->buflen - 1] = '\000';
	msglen = strlen(pos->msgbuf);
	pos->msgbuf += msglen;
	pos->buflen -= msglen;
}

static void
mp_printf(RDD_MSGPRINTER_POS *pos, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	mp_vprintf(pos, fmt, ap);
	va_end(ap);
}

void
rdd_mp_unixmsg(RDD_MSGPRINTER *printer,
	rdd_message_t type, int unix_errno, const char *fmt, ...)
{
	RDD_MSGPRINTER_POS pos;
	va_list ap;

	if (! mp_accept_message(printer, type)) return;

	va_start(ap, fmt);
	mp_init(&pos, printer);
	mp_vprintf(&pos, fmt, ap);
	mp_printf(&pos, ": %s", strerror(unix_errno));
	va_end(ap);

	(*printer->ops->print)(printer, type, unix_errno, printer->printbuf);
}

void
rdd_mp_vrddmsg(RDD_MSGPRINTER *printer,
	rdd_message_t type, int rdd_errno, const char *fmt, va_list ap)
{
	RDD_MSGPRINTER_POS pos;
	char rddbuf[128];

	if (! mp_accept_message(printer, type)) return;

	mp_init(&pos, printer);
	mp_vprintf(&pos, fmt, ap);
	if (rdd_strerror(rdd_errno, rddbuf, sizeof rddbuf) == RDD_OK) {
		rddbuf[(sizeof rddbuf) - 1] = '\000';
		mp_printf(&pos, ": %s", rddbuf);
	}

	(*printer->ops->print)(printer, type, rdd_errno, printer->printbuf);
}

void
rdd_mp_rddmsg(RDD_MSGPRINTER *printer,
	rdd_message_t type, int rdd_errno, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	rdd_mp_vrddmsg(printer, type, rdd_errno, fmt, ap);
	va_end(ap);
}
