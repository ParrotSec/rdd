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

#include <stdlib.h>
#include <sys/types.h>
#include <errno.h>
#include <unistd.h>

#include "rdd.h"
#include "reader.h"

/** \brief Atomic reader state.
 *
 *  An atomic reader forwards all operations to its parent
 *  in the reader stack, so it only needs to keep track of
 *  that parent.
 */
typedef struct _RDD_ATOMIC_READER {
	RDD_READER *parent;
} RDD_ATOMIC_READER;


/* Forward declarations
 */
static int rdd_atomic_read(RDD_READER *r, unsigned char *buf, unsigned nbyte,
			unsigned *nread);
static int rdd_atomic_tell(RDD_READER *r, rdd_count_t *pos);
static int rdd_atomic_seek(RDD_READER *r, rdd_count_t pos);
static int rdd_atomic_close(RDD_READER *r, int recurse);

static RDD_READ_OPS atomic_read_ops = {
	rdd_atomic_read,
	rdd_atomic_tell,
	rdd_atomic_seek,
	rdd_atomic_close
};

int
rdd_open_atomic_reader(RDD_READER **self, RDD_READER *p)
{
	RDD_READER *r = 0;
	RDD_ATOMIC_READER *state = 0;
	int rc;

	rc = rdd_new_reader(&r, &atomic_read_ops, sizeof(RDD_ATOMIC_READER));
	if (rc != RDD_OK) {
		*self = 0;
		return rc;
	}
	state = (RDD_ATOMIC_READER *) r->state;
	state->parent = p;

	*self = r;
	return RDD_OK;
}

static int
rdd_atomic_read(RDD_READER *self, unsigned char *buf, unsigned nbyte,
			unsigned *nread)
{
	RDD_ATOMIC_READER *state = self->state;
	rdd_count_t pos;
	int rc1;
	int rc2;

	/* Save current position.
	 */
	if ((rc1 = rdd_reader_tell(state->parent, &pos)) != RDD_OK) {
		return rc1;
	}

	rc2 = rdd_reader_read(state->parent, buf, nbyte, nread);
	if (rc2 == RDD_OK) {
		return RDD_OK;
	}

	/* Error occurred: restore current position.
	 */
	if ((rc1 = rdd_reader_seek(state->parent, pos)) != RDD_OK) {
		return rc1;
	}

	return rc2;
}

static int
rdd_atomic_tell(RDD_READER *self, rdd_count_t *pos)
{
	RDD_ATOMIC_READER *state = self->state;

	return rdd_reader_tell(state->parent, pos);
}

static int
rdd_atomic_seek(RDD_READER *self, rdd_count_t pos)
{
	RDD_ATOMIC_READER *state = self->state;

	return rdd_reader_seek(state->parent, pos);
}

static int
rdd_atomic_close(RDD_READER *self, int recurse)
{
	RDD_ATOMIC_READER *state = self->state;

	if (recurse) {
		return rdd_reader_close(state->parent, 1 /* recurse */);
	} else {
		return RDD_OK;
	}
}
