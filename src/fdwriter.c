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
#include <config.h>
#endif

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include "rdd.h"
#include "writer.h"

/* Forward declarations
 */
static int fd_write(RDD_WRITER *w, const unsigned char *buf, unsigned nbyte);
static int fd_close(RDD_WRITER *w);

static RDD_WRITE_OPS fd_write_ops = {
	fd_write,
	fd_close
};

typedef struct _RDD_FD_WRITER {
	int fd;
} RDD_FD_WRITER;

int
rdd_open_fd_writer(RDD_WRITER **self, int fd)
{
	RDD_WRITER *w = 0;
	RDD_FD_WRITER *state = 0;
	int rc = RDD_OK;

	rc = rdd_new_writer(&w, &fd_write_ops, sizeof(RDD_FD_WRITER));
	if (rc != RDD_OK) {
		return rc;
	}
	state = (RDD_FD_WRITER *) w->state;
	state->fd = fd;

	*self = w;
	return RDD_OK;
}

/* Writes the entire input buffer to the output file descriptor.
 */
static int
fd_write(RDD_WRITER *w, const unsigned char *buf, unsigned nbyte)
{
	RDD_FD_WRITER *state = w->state;
	int n;

	while (nbyte > 0) {
		if ((n = write(state->fd, buf, nbyte)) < 0) {
#if defined(RDD_SIGNALS)
			if (errno == EINTR) continue;
#endif
			if (errno == ENOSPC) {
				return RDD_ESPACE;
			} else {
				return RDD_EWRITE;
			}
		}
		buf += n;
		nbyte -= n;
	}

	return RDD_OK;
}

static int
fd_close(RDD_WRITER *self)
{
	RDD_FD_WRITER *state = self->state;
	int rc;

	if ((rc = close(state->fd)) < 0) {
		return RDD_ECLOSE;
	}

	return RDD_OK;
}
