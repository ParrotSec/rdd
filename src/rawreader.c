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
#include <unistd.h>

#include "rdd.h"
#include "rdd_internals.h"
#include "reader.h"

#define MOD_SECTOR(n)   ((n) & (RDD_SECTOR_SIZE - 1))

typedef struct _RDD_RAW_READER {
	int fd;
} RDD_RAW_READER;


/* Forward declarations
 */
static int rdd_raw_read(RDD_READER *r, unsigned char *buf, unsigned nbyte,
			unsigned *nread);
static int rdd_raw_tell(RDD_READER *r, rdd_count_t *pos);
static int rdd_raw_seek(RDD_READER *r, rdd_count_t pos);
static int rdd_raw_close(RDD_READER *r, int recurse);

static RDD_READ_OPS raw_read_ops = {
	rdd_raw_read,
	rdd_raw_tell,
	rdd_raw_seek,
	rdd_raw_close
};

int
rdd_open_raw_reader(RDD_READER **self, int fd)
{
	RDD_READER *r = 0;
	RDD_RAW_READER *state = 0;
	int rc = RDD_OK;

	rc = rdd_new_reader(&r, &raw_read_ops, sizeof(RDD_RAW_READER));
	if (rc != RDD_OK) {
		return rc;
	}

	state = (RDD_RAW_READER *) r->state;
	state->fd = fd;

	*self = r;
	return RDD_OK;
}

static int
rdd_raw_read(RDD_READER *self, unsigned char *buf, unsigned nbyte,
			unsigned *nread)
{
	RDD_RAW_READER *state = self->state;
	unsigned char *p = 0;
	rdd_count_t start_pos = 0;
	unsigned done;
	int rc = RDD_OK;
	int all_aligned = 0;

	/* Record current position.
	 */
	if ((rc = rdd_raw_tell(self, &start_pos)) != RDD_OK) {
		return rc;
	}

	/* Check whether the alignment constraints are met.
	 */
	all_aligned = MOD_SECTOR((unsigned) buf) == 0
		   && MOD_SECTOR(nbyte) == 0
		   && MOD_SECTOR(start_pos) == 0;
	if (! all_aligned) {
		return RDD_BADARG;
	}

	/* Read all sectors necessary to satisfy the user's request.
	 */
	done = 0;
	p = buf;
	while (nbyte > 0) {
		assert(MOD_SECTOR(nbyte) == 0);
		assert(MOD_SECTOR((unsigned) (p)) == 0);

		rc = read(state->fd, p, nbyte);
		if (rc < 0) {
#if defined(__linux)
			if (errno == ENXIO) {
				rc = 0;   /* assume EOF on raw device */
				break;
			}
#endif
#if defined(RDD_SIGNALS)
			if (errno == EINTR) {
				continue;
			}
#endif
#if 0
			fprintf(stderr, "offset %llu, buf %p, %u bytes:"
				" raw device read error [errno %d]:"
				" %s\n",
				file_pos, p, nbyte, errno, strerror(errno));
#endif
			return RDD_EREAD;  /* read error */
		} else if (rc == 0) {
			break; /* EOF */
		} else if (MOD_SECTOR(rc) != 0) {
#if 0
			error("raw device returned an incomplete sector");
#endif
			return RDD_EREAD;  /* read error */
		}

		done += rc;
		nbyte -= rc;
		p += rc;
	}

	*nread = done;
	return RDD_OK;
}

static int
rdd_raw_tell(RDD_READER *self, rdd_count_t *pos)
{
	RDD_RAW_READER *state = self->state;
	off_t offset;

	if ((offset = lseek(state->fd, (off_t) 0, SEEK_CUR)) == (off_t) -1) {
		return RDD_ETELL;
	}

	*pos = (rdd_count_t) offset;
	return RDD_OK;
}

static int
rdd_raw_seek(RDD_READER *self, rdd_count_t pos)
{
	RDD_RAW_READER *state = self->state;

	if ((lseek(state->fd, (off_t) pos, SEEK_SET)) == (off_t) -1) {
		return RDD_ESEEK;
	}
	return RDD_OK;
}

static int
rdd_raw_close(RDD_READER *self, int recurse /* ignored */)
{
	RDD_RAW_READER *state = self->state;

	if (close(state->fd) < 0) {
		return RDD_ECLOSE;
	}

	return RDD_OK;
}
