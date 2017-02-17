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
#include <config.h>
#endif

#include <assert.h>
#include <stdlib.h>

#if defined(HAVE_LIBZ)
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <zlib.h>
#else
#error: libz not present
#endif

#include "rdd.h"
#include "writer.h"

#define ZBUF_SIZE 32768

#define z_inbuf_empty(z)  ((z)->avail_in <= 0)
#define z_outbuf_full(z)  ((z)->avail_out <= 0)

/* Forward declarations
 */
static int zlib_write(RDD_WRITER *w, const unsigned char *buf, unsigned nbyte);
static int zlib_close(RDD_WRITER *w);

static RDD_WRITE_OPS zlib_write_ops = {
	zlib_write,
	zlib_close
};

typedef struct _RDD_ZLIB_WRITER {
	RDD_WRITER    *parent;
	z_stream       zstate;
	unsigned char *zbuf;
} RDD_ZLIB_WRITER;

int
rdd_open_zlib_writer(RDD_WRITER **self, RDD_WRITER *parent)
{
	RDD_WRITER *w = 0;
	RDD_ZLIB_WRITER *state = 0;
	unsigned char *zbuf = 0;
	int rc = RDD_OK;

	rc = rdd_new_writer(&w, &zlib_write_ops, sizeof(RDD_ZLIB_WRITER));
	if (rc != RDD_OK) {
		goto error;
	}
	state = (RDD_ZLIB_WRITER *) w->state;

	if ((zbuf = malloc(ZBUF_SIZE)) == 0) {
		rc = RDD_NOMEM;
		goto error;
	}
	state->zbuf = zbuf;
	state->parent = parent;

	memset(&state->zstate, 0, sizeof(z_stream));
	state->zstate.zalloc = Z_NULL;
	state->zstate.zfree = Z_NULL;
	state->zstate.opaque = 0;
	state->zstate.next_out = zbuf;
	state->zstate.avail_out = ZBUF_SIZE;

	rc = deflateInit(&state->zstate, Z_DEFAULT_COMPRESSION);
	switch (rc) {
	case Z_OK:
		break;
	case Z_MEM_ERROR:
		rc = RDD_NOMEM;
		goto error;
	default:
		rc = RDD_ECOMPRESS;
		goto error;
	}

	*self = w;
	return RDD_OK;

error:
	*self = 0;
	if (zbuf != 0) free(zbuf);
	if (state != 0) free(state);
	if (w != 0) free(w);
	return rc;
}

/* Flushes the output that the compressor has generated so far
 * to the parent writer.
 */
static int
flush(RDD_ZLIB_WRITER *state)
{
	z_stream *z = &state->zstate;
	unsigned filled;
	int rc;

	filled = ZBUF_SIZE - z->avail_out;

	if ((rc = rdd_writer_write(state->parent, state->zbuf, filled)) != 0) {
		return rc;
	}
	z->next_out = state->zbuf;
	z->avail_out = ZBUF_SIZE;

	return RDD_OK;
}

/* Pushes the entire input buffer into the compressor.
 */
static int
zlib_write(RDD_WRITER *w, const unsigned char *buf, unsigned nbyte)
{
	RDD_ZLIB_WRITER *state = w->state;
	z_stream *z = &state->zstate;
	int rc;

	z->next_in = (unsigned char *) buf;
	z->avail_in = nbyte;

	while (z->avail_in > 0) {
		if (z_outbuf_full(z)) {
			if ((rc = flush(state)) != RDD_OK) {
				return rc;
			}
		}
		assert(! z_outbuf_full(z));
		rc = deflate(z, Z_NO_FLUSH);
		if (rc != Z_OK && rc != Z_STREAM_END) {
			return RDD_ECOMPRESS;
		}
	}

	return RDD_OK;
}

static int
zlib_close(RDD_WRITER *self)
{
	RDD_ZLIB_WRITER *state = self->state;
	z_stream *z = &state->zstate;
	int rc = RDD_OK;

	assert(z_inbuf_empty(z));

	/* Flush any pending output to the parent.
	 */
	while (1) {
		if (z_outbuf_full(z)) {
			if ((rc = flush(state)) != RDD_OK) {
				return rc;
			}
		}
		assert(! z_outbuf_full(z));
		rc = deflate(z, Z_FINISH);
		if (rc == Z_STREAM_END) {
			break;
		} else if (rc != Z_OK) {
			return RDD_ECOMPRESS;
		}
	}
	if ((rc = flush(state)) != RDD_OK) {
		return rc;
	}

	/* Close parent.
	 */
	if ((rc = rdd_writer_close(state->parent)) != RDD_OK) {
		return rc;
	}

	/* Clean up.
	 */
	free(state->zbuf);
	state->zbuf = 0;

	return RDD_OK;
}
