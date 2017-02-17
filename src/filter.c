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
"@(#) Copyright (c) 2002\n\
	Netherlands Forensic Institute.  All rights reserved.\n";
#endif /* not lint */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rdd.h"
#include "writer.h"
#include "filter.h"

#define is_stream_filter(fltr)  ((fltr)->ops->block == 0)
#define is_block_filter(fltr)   ((fltr)->ops->block != 0)

/** This is a convenience routine that can (and should) be used
 *  by filter implementations to initialize the 'base' filter.
 */
int
rdd_new_filter(RDD_FILTER **new, RDD_FILTER_OPS *ops,
		unsigned statesize, unsigned blocksize)
{
	RDD_FILTER *f = 0;
	unsigned char *state = 0;
	int rc = RDD_OK;

	if (new == 0 || ops == 0) return RDD_BADARG;

	if (ops->block != 0 && blocksize == 0) return RDD_BADARG;

	if ((f = calloc(1, sizeof(RDD_FILTER))) == 0) {
		rc = RDD_NOMEM;
		goto error;
	}

	if ((state = calloc(1, statesize)) == 0) {
		rc = RDD_NOMEM;
		goto error;
	}

	f->ops = ops;
	f->state = state;
	f->pos = 0;
	f->blocksize = blocksize;

	*new = f;
	return RDD_OK;

error:
	*new = 0;
	if (state != 0) free(state);
	if (f != 0) free(f);
	return rc;
}

static int
stream_filter_push(RDD_FILTER *f, const unsigned char *buf, unsigned nbyte)
{
	RDD_FILTER_OPS *ops = f->ops;

	return (*ops->input)(f, buf, nbyte);
}

static int
block_filter_push(RDD_FILTER *f, const unsigned char *buf, unsigned nbyte)
{
	RDD_FILTER_OPS *ops = f->ops;
	unsigned todo;
	int rc;

	while (nbyte > 0) {
		if (f->pos + nbyte > f->blocksize) {
			todo = f->blocksize - f->pos;
		} else {
			todo = nbyte;
		}

		rc = (*ops->input)(f, buf, todo);
		if (rc != RDD_OK) {
			return rc;
		}

		buf += todo;
		nbyte -= todo;
		f->pos += todo;
		if (f->pos >= f->blocksize) {
			/* Pushed a full block; notify client.
			 */
			rc = (*ops->block)(f, f->pos);
			if (rc != RDD_OK) {
				return rc;
			}
			f->pos = 0;
		}
	}

	return RDD_OK;
}

/** Passes a buffer of nbyte bytes to a filter.  If the filter is a
 *  stream filter it will simply pass the buffer to the client's
 *  handler.  If the filter is a block filter, it processes the
 *  buffer block by block, calling the client's block handler at
 *  each block boundary.
 */
int 
rdd_filter_push(RDD_FILTER *f, const unsigned char *buf, unsigned nbyte)
{

	if (is_stream_filter(f)) {
		return stream_filter_push(f, buf, nbyte);
	} else {
		return block_filter_push(f, buf, nbyte);
	}
}

int
rdd_filter_close(RDD_FILTER *f)
{
	RDD_FILTER_OPS *ops = f->ops;
	int rc;

	if (is_block_filter(f) && f->pos > 0) {
		rc = (*ops->block)(f, f->pos);	/* final block() call */
		if (rc != RDD_OK) {
			return rc;
		}
		f->pos = 0;
	}

	if (ops->close != 0) {
		return (*ops->close)(f);
	}

	return RDD_OK;
}

int
rdd_filter_get_result(RDD_FILTER *f, unsigned char *buf, unsigned nbyte)
{
	RDD_FILTER_OPS *ops = f->ops;

	if (buf == 0) return RDD_BADARG;

	if (ops->get_result == 0) return RDD_NOTFOUND;

	return (*ops->get_result)(f, buf, nbyte);
}

int
rdd_filter_free(RDD_FILTER *f)
{
	RDD_FILTER_OPS *ops = f->ops;
	int rc;

	if (ops->free != 0) {
		rc = (*ops->free)(f);
		if (rc != RDD_OK) {
			return rc;
		}
	}

	free(f->state);
	f->state = 0;
	free(f);

	return RDD_OK;
}
