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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rdd.h"
#include "rdd_internals.h"
#include "reader.h"
#include "writer.h"
#include "filter.h"
#include "filterset.h"
#include "copier.h"

/** \brief Size of the read buffer in bytes; a simple copier reads at most
 *  \c SIMPLE_READ_SIZE bytes at a time from its reader.
 */
#define SIMPLE_READ_SIZE  65536	/* bytes */

/** \brief State structure for a simple copier.
 *
 *  At present, a simple reader's state consists only of
 *  a read buffer. The read buffer could also be allocated on the
 *  stack in \c simple_exec(), which would eliminate all state,
 *  but I prefer to keep large data objects off the stack.
 */
typedef struct _RDD_SIMPLE_COPIER {
	unsigned char      readbuf[SIMPLE_READ_SIZE]; /**< read buffer */
	rdd_proghandler_t  progressfun;		/**< progress callback */
	void              *progressenv;		/**< progress environment */
} RDD_SIMPLE_COPIER;

static int simple_exec(RDD_COPIER *c, RDD_READER *r, RDD_FILTERSET *fset,
						     RDD_COPIER_RETURN *ret);

static RDD_COPY_OPS simple_ops = {
	simple_exec,
	0
};

int
rdd_new_simple_copier(RDD_COPIER **self, RDD_SIMPLE_PARAMS *params)
{
	RDD_COPIER *c = 0;
	RDD_SIMPLE_COPIER *state = 0;
	int rc;

	rc = rdd_new_copier(&c, &simple_ops, sizeof(RDD_SIMPLE_COPIER));
	if (rc != RDD_OK) {
		return rc;
	}

	state = (RDD_SIMPLE_COPIER *) c->state;
	memset(state->readbuf, 0, sizeof(state->readbuf));

	if (params) {
		state->progressfun = params->progressfun;
		state->progressenv = params->progressenv;
	} else {
		state->progressfun = 0;
		state->progressenv = 0;
	}

	*self = c;
	return RDD_OK;
}

static int
simple_exec(RDD_COPIER *c, RDD_READER *r, RDD_FILTERSET *fset,
					  RDD_COPIER_RETURN *ret)
{
	RDD_SIMPLE_COPIER *s = (RDD_SIMPLE_COPIER *) c->state;
	rdd_count_t copied = 0;
	int aborted = 0;
	unsigned nread;
	int rc;

	ret->nbyte = 0;
	ret->nlost = 0;
	ret->nread_err = 0;
	ret->nsubst = 0;

	while (1) {
		nread = 0;
		rc = rdd_reader_read(r, s->readbuf, SIMPLE_READ_SIZE,
					&nread);
		if (rc != RDD_OK) return rc;	/* read error */

		if (nread == 0) break;		/* reached end-of-file */

		if ((rc = rdd_fset_push(fset, s->readbuf, nread)) != RDD_OK) {
			return rc;
		}

		copied += nread;

		if (s->progressfun != 0) {
			rc = (*s->progressfun)(copied, s->progressenv);
			if (rc == RDD_ABORTED) {
				aborted = 1;
				break;
			} else if (rc != RDD_OK) {
				return rc;
			}
		}
	}

	if (s->progressfun != 0) {
		rc = (*s->progressfun)(copied, s->progressenv);
		if (rc == RDD_ABORTED) {
			aborted = 1;
		} else if (rc != RDD_OK) {
			return rc;
		}
	}

	if ((rc = rdd_fset_close(fset)) != RDD_OK) {
		return rc;
	}

	ret->nbyte = copied;

	return aborted ? RDD_ABORTED : RDD_OK;
}
