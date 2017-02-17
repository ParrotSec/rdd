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
#include <string.h>
#include <sys/types.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include "rdd.h"
#include "reader.h"

typedef struct _RDD_CDROM_READER {
	char        *path;
	rdd_count_t  pos;
} RDD_CDROM_READER;


/* Forward declarations
 */
static int rdd_cdrom_read(RDD_READER *r, unsigned char *buf, unsigned nbyte,
			unsigned *nread);
static int rdd_cdrom_tell(RDD_READER *r, rdd_count_t *pos);
static int rdd_cdrom_seek(RDD_READER *r, rdd_count_t pos);
static int rdd_cdrom_close(RDD_READER *r, int recurse);

static RDD_READ_OPS fd_read_ops = {
	rdd_cdrom_read,
	rdd_cdrom_tell,
	rdd_cdrom_seek,
	rdd_cdrom_close
};

int
rdd_open_cdrom_reader(RDD_READER **self, const char *path)
{
	RDD_READER *r = 0;
	RDD_CDROM_READER *state = 0;
	char *devpath = 0;
	int rc = RDD_OK;

	rc = rdd_new_reader(&r, &fd_read_ops, sizeof(RDD_CDROM_READER));
	if (rc != RDD_OK) {
		return rc;
	}

	if ((devpath = malloc(strlen(path) + 1)) == 0) {
		rc = RDD_NOMEM;
		goto error;
	}
	strcpy(devpath, path);

	state = (RDD_CDROM_READER *) r->state;
	state->path = devpath;
	state->pos = 0;

	*self = r;
	return RDD_OK;
error:
	*self = 0;
	if (devpath != 0) free(devpath);
	return rc;
}

static int
rdd_cdrom_read(RDD_READER *self, unsigned char *buf, unsigned nbyte,
			unsigned *nread)
{
	RDD_CDROM_READER *state = self->state;
	unsigned char *next = buf;
	off_t offset;
	int fd = -1;
	int rc = RDD_OK;
	int n;

	if ((fd = open(state->path, O_RDONLY)) < 0) {
		rc = RDD_EOPEN;
		goto error;
	}

	if ((offset = lseek(fd, (off_t) state->pos, SEEK_SET)) == (off_t) -1) {
		rc = RDD_ESEEK;
		goto error;
	}

	while (nbyte > 0) {
		n = read(fd, next, nbyte);
		if (n < 0) {
#if defined(RDD_SIGNALS)
			if (errno == EINTR) continue;
#endif
			rc = RDD_EREAD;
			goto error;
		} else if (n == 0) {
			break;	/* reached EOF */
		}
		nbyte -= n;
		next += n;
	}

	(void) close(fd);

	*nread = next - buf;
	return RDD_OK;

error:
	if (fd >= 0) (void) close(fd);
	return rc;
}

static int
rdd_cdrom_tell(RDD_READER *self, rdd_count_t *pos)
{
	RDD_CDROM_READER *state = self->state;

	*pos = (rdd_count_t) state->pos;
	return RDD_OK;
}

static int
rdd_cdrom_seek(RDD_READER *self, rdd_count_t pos)
{
	RDD_CDROM_READER *state = self->state;

	state->pos = pos;

	return RDD_OK;
}

static int
rdd_cdrom_close(RDD_READER *self, int recurse /* ignored */)
{
	return RDD_OK;
}
