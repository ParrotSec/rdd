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
#include <string.h>
#include <sys/types.h>
#include <errno.h>
#include <unistd.h>

#include "rdd.h"
#include "rdd_internals.h"
#include "alignedbuf.h"
#include "reader.h"

#define MOD_ALIGN(r, n)   ((n) % ((r)->align))

typedef struct _RDD_ALIGNED_READER {
	RDD_READER *parent;
	unsigned    align;
} RDD_ALIGNED_READER;


/* Forward declarations
 */
static int rdd_aligned_read(RDD_READER *r, unsigned char *buf, unsigned nbyte,
			unsigned *nread);
static int rdd_aligned_tell(RDD_READER *r, rdd_count_t *pos);
static int rdd_aligned_seek(RDD_READER *r, rdd_count_t pos);
static int rdd_aligned_close(RDD_READER *r, int recurse);

static RDD_READ_OPS aligned_read_ops = {
	rdd_aligned_read,
	rdd_aligned_tell,
	rdd_aligned_seek,
	rdd_aligned_close
};

int
rdd_open_aligned_reader(RDD_READER **self, RDD_READER *parent, unsigned align)
{
	RDD_READER *r = 0;
	RDD_ALIGNED_READER *state = 0;
	int rc = RDD_OK;

	rc = rdd_new_reader(&r, &aligned_read_ops, sizeof(RDD_ALIGNED_READER));
	if (rc != RDD_OK) {
		return rc;
	}

	state = (RDD_ALIGNED_READER *) r->state;
	state->parent = parent;
	state->align = align;

	*self = r;
	return RDD_OK;
}

static int
rdd_aligned_read(RDD_READER *self, unsigned char *buf, unsigned nbyte,
			unsigned *nread)
{
	RDD_ALIGNED_READER *state = self->state;
	unsigned char *p = 0;
	rdd_count_t start_pos = 0;
	rdd_count_t file_pos = 0;
	unsigned sector_offset;
	unsigned sector_extra;
	unsigned done;
	int rc = RDD_OK;
	int all_aligned = 0;
	unsigned nparentread = 0;
	unsigned char *alignedbuf = 0;
	RDD_ALIGNEDBUF abuf;
	int todo;

	/* Record current position.
	 */
	if ((rc = rdd_aligned_tell(self, &start_pos)) != RDD_OK) {
		return rc;
	}
	file_pos = start_pos;

	all_aligned = MOD_ALIGN(state, (unsigned) buf) == 0
		   && MOD_ALIGN(state, nbyte) == 0
		   && MOD_ALIGN(state, start_pos) == 0;
	if (all_aligned) {
		alignedbuf = buf;
	} else {
		rc = rdd_new_alignedbuf(&abuf, nbyte, state->align);
		if (rc != RDD_OK) {
			return rc;
		}
		alignedbuf = abuf.aligned;
		return RDD_BADARG;
	}

	todo = nbyte;

	/* Move the file pointer back to the nearest sector boundary.
	 */
	if ((sector_offset = MOD_ALIGN(state, file_pos)) > 0) {
		file_pos -= sector_offset;
		todo += sector_offset;
		if (rdd_aligned_seek(self, file_pos) != RDD_OK) {
			return RDD_ESEEK;
		}
	}

	/* Round up the read size, so that we will read a
	 * multiple of the sector size.
	 */
	if ((sector_extra = MOD_ALIGN(state, todo)) > 0) {
		todo += RDD_SECTOR_SIZE - sector_extra;
	}
	assert(todo >= (signed) sector_offset);

	/* Read all sectors necessary to satisfy the user's request.
	 */
	done = 0;
	p = buf;
	while (todo > 0) {
		assert(MOD_ALIGN(state, todo) == 0);
		assert(MOD_ALIGN(state, (unsigned) (p)) == 0);

		rc = rdd_reader_read(state->parent, p, todo, &nparentread);
		if (rc == RDD_EAGAIN) {
			continue;
		} else if (rc != RDD_OK) {
			return rc;
		}

		if (nparentread == 0) {
			break;	/* EOF */
		}

		if (MOD_ALIGN(state, nparentread) != 0) {
#if 0
			error("raw device returned an incomplete sector");
#endif
			return RDD_EREAD;  /* read error */
		}

		done += nparentread;
		todo -= nparentread;
		p += nparentread;
	}


	/* We got data or we reached EOF.  We should at least be able
	 * to read up to the point where we were when we entered this
	 * routine (start_pos).
	 */
	file_pos += done;
	if (file_pos < start_pos) {
#if 0
		bug("fd %d: raw device does not supply enough data", state->fd);
#endif
		return RDD_EREAD;
	}

	if (file_pos > start_pos + nbyte) {
		/* We read beyond the point requested by the caller.
		 * Return only the bytes that the caller asked for and
		 * move back the file pointer.
		 */
		file_pos = start_pos + nbyte;
		if ((rc = rdd_aligned_seek(self, file_pos)) != RDD_OK) {
			return rc;
		}
	}

	*nread = file_pos - start_pos;

	if (alignedbuf != buf) {
		memcpy(buf, alignedbuf, *nread);
		rdd_free_alignedbuf(&abuf);
	}

	return RDD_OK;
}

static int
rdd_aligned_tell(RDD_READER *self, rdd_count_t *pos)
{
	RDD_ALIGNED_READER *state = self->state;

	return rdd_reader_tell(state->parent, pos);
}

static int
rdd_aligned_seek(RDD_READER *self, rdd_count_t pos)
{
	RDD_ALIGNED_READER *state = self->state;

	return rdd_reader_seek(state->parent, pos);
}

static int
rdd_aligned_close(RDD_READER *self, int recurse)
{
	RDD_ALIGNED_READER *state = self->state;
	int rc = RDD_OK;

	if (recurse) {
		rc = rdd_reader_close(state->parent, recurse);
		if (rc != RDD_OK) {
			return rc;
		}
	}

	return RDD_OK;
}
