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



#ifndef lint
static char copyright[] =
"@(#) Copyright (c) 2002-2004\n\
	Netherlands Forensic Institute.  All rights reserved.\n";
#endif /* not lint */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>

#include "rdd.h"
#include "writer.h"

int
rdd_new_writer(RDD_WRITER **self, RDD_WRITE_OPS *ops, unsigned statesize)
{
	RDD_WRITER *w = 0;
	unsigned char *state = 0;
	int rc = RDD_OK;

	if (self == 0 || ops == 0) return RDD_BADARG;

	if ((w = calloc(1, sizeof(RDD_WRITER))) == 0) {
		rc = RDD_NOMEM;
		goto error;
	}

	if ((state = calloc(1, statesize)) == 0) {
		rc = RDD_NOMEM;
		goto error;
	}

	w->state = state;
	w->ops = ops;

	*self = w;
	return RDD_OK;

error:
	*self = 0;
	if (state != 0) free(state);
	if (w != 0) free(w);
	return rc;
}

int
rdd_writer_write(RDD_WRITER *w, const unsigned char *buf, unsigned nbyte)
{
	return (*(w->ops->write))(w, buf, nbyte);
}

int
rdd_writer_close(RDD_WRITER *w)
{
	int rc;

	rc = (*(w->ops->close))(w);
	if (rc != RDD_OK) {
		return rc;
	}

	free(w->state);
	w->state = 0;
	free(w);

	return RDD_OK;
}
