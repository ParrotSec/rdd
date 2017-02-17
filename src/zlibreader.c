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

#include <assert.h>
#include <stdlib.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <zlib.h>

#include "rdd.h"
#include "reader.h"

#define ZBUF_SIZE 32768

#define z_inbuf_empty(z)  ((z)->avail_in <= 0)
#define z_outbuf_full(z)  ((z)->avail_out <= 0)

typedef struct _RDD_ZLIB_READER {
	RDD_READER    *parent;
	unsigned char *zbuf;
	z_stream       zstate;
	rdd_count_t    pos;
} RDD_ZLIB_READER;


/* Forward declarations
 */
static int rdd_zlib_read(RDD_READER *r, unsigned char *buf, unsigned nbyte,
			unsigned *nread);
static int rdd_zlib_tell(RDD_READER *r, rdd_count_t *pos);
static int rdd_zlib_seek(RDD_READER *r, rdd_count_t pos);
static int rdd_zlib_close(RDD_READER *r, int recurse);

static RDD_READ_OPS zlib_read_ops = {
	rdd_zlib_read,
	rdd_zlib_tell,
	rdd_zlib_seek,
	rdd_zlib_close
};

int
rdd_open_zlib_reader(RDD_READER **self, RDD_READER *parent)
{
	RDD_READER *r = 0;
	RDD_ZLIB_READER *state = 0;
	unsigned char *zbuf = 0;
	int rc = RDD_OK;

	rc = rdd_new_reader(&r, &zlib_read_ops, sizeof(RDD_ZLIB_READER));
	if (rc != RDD_OK) {
		goto error;
	}
	state = (RDD_ZLIB_READER *) r->state;

	if ((zbuf = malloc(ZBUF_SIZE)) == 0) {
		rc = RDD_NOMEM;
		goto error;
	}

	state->parent = parent;
	state->zbuf = zbuf;
	state->pos = 0;

	memset(&state->zstate, 0, sizeof(z_stream));
	state->zstate.zalloc = Z_NULL;
	state->zstate.zfree = Z_NULL;
	state->zstate.opaque = 0;
	state->zstate.next_in = Z_NULL;
	state->zstate.avail_in = 0;
	state->zstate.next_out = Z_NULL;
	state->zstate.avail_out = 0;

	rc = inflateInit(&state->zstate);
	if (rc == Z_MEM_ERROR) {
		rc = RDD_NOMEM;
		goto error;
	} else if (rc != Z_OK) {
		rc = RDD_ECOMPRESS;
		goto error;
	}

	*self = r;
	return RDD_OK;

error:
	*self = 0;
	if (zbuf != 0) free(zbuf);
	if (state != 0) free(state);
	if (r != 0) free(r);
	return rc;
}

static int
rdd_zlib_read(RDD_READER *self, unsigned char *buf, unsigned nbyte,
			unsigned *nread)
{
	RDD_ZLIB_READER *state = self->state;
	z_stream *z = &state->zstate;
	int rc;

	*nread = 0;

	z->next_out = buf;
	z->avail_out = nbyte;

	while (z->avail_out > 0) {
		if (z->avail_in == 0) {
			/* Input buffer (zbuf) is empty: refill it with
			 * compressed data that is obtained from the parent
			 * reader.
			 */
			z->next_in = state->zbuf;
			rc = rdd_reader_read(state->parent,
					state->zbuf, ZBUF_SIZE, &z->avail_in);
			if (rc != RDD_OK) {
				return rc;
			}
		}

		rc = inflate(z, Z_NO_FLUSH);
		if (rc == Z_STREAM_END) {
			break;
		} else if (rc != Z_OK) {
			return RDD_ECOMPRESS;
		}
	}

	*nread = z->next_out - buf;
	state->pos += *nread;
	return RDD_OK;
}

static int
rdd_zlib_tell(RDD_READER *self, rdd_count_t *pos)
{
	RDD_ZLIB_READER *state = self->state;

	*pos = state->pos;
	return RDD_OK;
}

static int
rdd_zlib_seek(RDD_READER *self, rdd_count_t pos)
{
	return RDD_ESEEK;	/* not implemented */
}

static int
rdd_zlib_close(RDD_READER *self, int recurse)
{
	RDD_ZLIB_READER *state = self->state;
	int rc;

	if ((rc = inflateEnd(&state->zstate)) != Z_OK) {
		return RDD_ECOMPRESS;
	}

	if (recurse) {
		if ((rc = rdd_reader_close(state->parent, 1)) != RDD_OK) {
			return rc;
		}
	}

	free(state->zbuf);
	state->zbuf = 0;

	return RDD_OK;
}
