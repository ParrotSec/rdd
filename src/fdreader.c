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
#include <sys/types.h>
#include <errno.h>
#include <unistd.h>

#include "rdd.h"
#include "reader.h"

typedef struct _RDD_FD_READER {
	int fd;
} RDD_FD_READER;


/* Forward declarations
 */
static int rdd_fd_read(RDD_READER *r, unsigned char *buf, unsigned nbyte,
			unsigned *nread);
static int rdd_fd_tell(RDD_READER *r, rdd_count_t *pos);
static int rdd_fd_seek(RDD_READER *r, rdd_count_t pos);
static int rdd_fd_close(RDD_READER *r, int recurse);

static RDD_READ_OPS fd_read_ops = {
	rdd_fd_read,
	rdd_fd_tell,
	rdd_fd_seek,
	rdd_fd_close
};

int
rdd_open_fd_reader(RDD_READER **self, int fd)
{
	RDD_READER *r = 0;
	RDD_FD_READER *state = 0;
	int rc = RDD_OK;

	rc = rdd_new_reader(&r, &fd_read_ops, sizeof(RDD_FD_READER));
	if (rc != RDD_OK) {
		return rc;
	}

	state = (RDD_FD_READER *) r->state;
	state->fd = fd;

	*self = r;
	return RDD_OK;
}

static int
rdd_fd_read(RDD_READER *self, unsigned char *buf, unsigned nbyte,
			unsigned *nread)
{
	RDD_FD_READER *state = self->state;
	unsigned char *next = buf;
	int n;

	while (nbyte > 0) {
		n = read(state->fd, next, nbyte);
		if (n < 0) {
#if defined(RDD_SIGNALS)
			if (errno == EINTR) continue;
#endif
			return RDD_EREAD;
		} else if (n == 0) {
			break;	/* reached EOF */
		}
		nbyte -= n;
		next += n;
	}

	*nread = next - buf;
	return RDD_OK;
}

static int
rdd_fd_tell(RDD_READER *self, rdd_count_t *pos)
{
	RDD_FD_READER *state = self->state;
	off_t offset;

	if ((offset = lseek(state->fd, (off_t) 0, SEEK_CUR)) == (off_t) -1) {
		return RDD_ETELL;
	}

	*pos = (rdd_count_t) offset;
	return RDD_OK;
}

static int
rdd_fd_seek(RDD_READER *self, rdd_count_t pos)
{
	RDD_FD_READER *state = self->state;

	if ((lseek(state->fd, (off_t) pos, SEEK_SET)) == (off_t) -1) {
		return RDD_ESEEK;
	}
	return RDD_OK;
}

static int
rdd_fd_close(RDD_READER *self, int recurse /* ignored */)
{
	RDD_FD_READER *state = self->state;

	if (close(state->fd) < 0) {
		return RDD_ECLOSE;
	}

	return RDD_OK;
}
