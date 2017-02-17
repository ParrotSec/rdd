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

typedef struct _RDD_BCAST_MSGPRINTER {
	unsigned         nprinter;
	RDD_MSGPRINTER **printers;
} RDD_BCAST_MSGPRINTER;

static void bcast_print(RDD_MSGPRINTER *printer,
		rdd_message_t type, int errcode, const char *msg);
static int  bcast_close(RDD_MSGPRINTER *printer, unsigned flags);

static RDD_MSGPRINTER_OPS bcast_ops = {
	bcast_print,
	bcast_close
};

int
rdd_mp_open_bcast_printer(RDD_MSGPRINTER **printer,
	unsigned nprinter, RDD_MSGPRINTER **printers)
{	
	RDD_BCAST_MSGPRINTER *bcast = 0;
	RDD_MSGPRINTER **printertab = 0;
	RDD_MSGPRINTER *p = 0;
	int rc = RDD_OK;
	unsigned i;

	*printer = 0;

	printertab = malloc(nprinter * sizeof(RDD_MSGPRINTER *));
	if (printertab == 0) {
		rc = RDD_NOMEM;
		goto error;
	}
	for (i = 0; i < nprinter; i++) {
		printertab[i] = printers[i];
	}

	rc = rdd_mp_open_printer(&p, &bcast_ops, sizeof(RDD_BCAST_MSGPRINTER));
	if (rc != RDD_OK) {
		goto error;
	}

	bcast = (RDD_BCAST_MSGPRINTER *) p->state;
	bcast->nprinter = nprinter;
	bcast->printers = printertab;

	*printer = p;
	return RDD_OK;

error:
	*printer = 0;
	if (printertab != 0) free(printertab);
	return rc;
}

static void
bcast_print(RDD_MSGPRINTER *printer, rdd_message_t type, int errcode,
	const char *msg)
{
	RDD_BCAST_MSGPRINTER *bcast = (RDD_BCAST_MSGPRINTER *) printer->state;
	unsigned i;

	for (i = 0; i < bcast->nprinter; i++) {
		rdd_mp_message(bcast->printers[i], type, "%s", msg);
	}
}

static int
bcast_close(RDD_MSGPRINTER *printer, unsigned flags)
{
	RDD_BCAST_MSGPRINTER *bcast = (RDD_BCAST_MSGPRINTER *) printer->state;
	unsigned i;
	int rc;

	if ((flags & RDD_MP_RECURSE) != 0) {
		for (i = 0; i < bcast->nprinter; i++) {
			rc = rdd_mp_close(bcast->printers[i], flags);
			if (rc != RDD_OK) {
				return rc;
			}
		}
	}

	free(bcast->printers);
	memset(bcast, 0, sizeof *bcast);
	return RDD_OK;
}
