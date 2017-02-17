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

/*
 * Implements the generic writer interface (see writer.h)
 *
 * A partwriter distributes its input data over multiple
 * files, each of which has a maximum size that is specified
 * at construction time.  When one file has been filled, the
 * partwriter closes it and opens a new file.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "rdd.h"
#include "writer.h"

#define GIGABYTE (1024*1024*1024)

/* Forward declarations
 */
static int part_write(RDD_WRITER *w, const unsigned char *buf, unsigned nbyte);
static int part_close(RDD_WRITER *w);

static RDD_WRITE_OPS part_write_ops = {
	part_write,
	part_close
};

typedef struct _RDD_PART_WRITER {
	char        *path;
	char        *pathbuf;
	unsigned     maxpathlen;
	rdd_count_t  splitlen;
	unsigned     next_partnum;	/* next part number */
	rdd_write_mode_t writemode;
	unsigned     ndigit;		/* #decimal digits in sequence no. */
	rdd_count_t  written;		/* #bytes in current part */
	RDD_WRITER *parent;
} RDD_PART_WRITER;


/* Counts the number of decimal digits required to represent
 * the sequence number of the last part of a split file.
 * For example: splitting a 1 MB (maxlen) file into 2 Kbyte
 * (splitlen) parts yields 512 parts.  It takes three digits
 * to represents the number 512.
 */
static unsigned
count_digits(rdd_count_t maxlen, rdd_count_t splitlen)
{
	rdd_count_t npart;
	unsigned ndigit;

	if (maxlen == RDD_WHOLE_FILE) {
		/* File size unknown.  Pick some big number.
		 */
		maxlen = ((rdd_count_t) 1000) * ((rdd_count_t) GIGABYTE);
	}

	npart = (maxlen + splitlen - 1) / splitlen;
	for (ndigit = 0; npart != 0; ndigit++, npart /= 10) {
	}

	return ndigit;
}

/* Opens a new file. Each file's name includes a sequence number
 * that is prepended to the basename of the template file name
 * specified at construction time (stored in state->path).
 */
static int
open_next_part(RDD_PART_WRITER *state)
{
	char *sep;
	int rc;

	assert(state->path != 0);

	sep = strrchr(state->path, '/');
	if (sep == 0) {
		/* Simple path, no '/' separators.
		 * Example: foo.img -> 002-foo.img.
		 */
		snprintf(state->pathbuf, state->maxpathlen, "%0*d-%s",
			state->ndigit, state->next_partnum, state->path);
		state->pathbuf[state->maxpathlen-1] = '\000';
	} else {
		/* Multipart path, path components separated by '/' chars.
		 * Example: /tmp/foo.img -> /tmp/002-foo.img.
		 */
		char *dir = state->path;
		char *file = sep + 1;
		*sep = '\000';	/* overwrites last '/' in state->path */
		snprintf(state->pathbuf, state->maxpathlen, "%s/%0*d-%s",
				dir, state->ndigit, state->next_partnum, file);
		state->pathbuf[state->maxpathlen-1] = '\000';
		*sep = '/';	/* restores last '/' in state->path */
	}

	rc = rdd_open_safe_writer(&state->parent, state->pathbuf,
					state->writemode);
	if (rc != RDD_OK) {
		return rc;
	}

	state->next_partnum++;

	return RDD_OK;
}

int
rdd_open_part_writer(RDD_WRITER **self,
	const char *path, rdd_count_t maxlen, rdd_count_t splitlen,
	rdd_write_mode_t wrmode)
{
	RDD_WRITER *w = 0;
	RDD_PART_WRITER *state = 0;
	char *pathcopy = 0;
	char *pathbuf = 0;
	int rc = RDD_OK;

	if (splitlen <= 0) return RDD_BADARG;
	if (maxlen <= 0) return RDD_BADARG;

	rc = rdd_new_writer(&w, &part_write_ops, sizeof(RDD_PART_WRITER));
	if (rc != RDD_OK) {
		goto error;
	}
	state = (RDD_PART_WRITER *) w->state;

	state->ndigit = count_digits(maxlen, splitlen);
	state->next_partnum = 0;
	state->splitlen = splitlen;
	state->written = 0;
	state->writemode = wrmode;

	if ((pathcopy = malloc(strlen(path) + 1)) == 0) {
		rc = RDD_NOMEM;
		goto error;
	}
	strcpy(pathcopy, path);
	state->path = pathcopy;
	state->maxpathlen = strlen(state->path) + 128;

	if ((pathbuf = malloc(state->maxpathlen)) == 0) {
		goto error;
	}
	memset(pathbuf, 0, state->maxpathlen);
	state->pathbuf = pathbuf;

	if ((rc = open_next_part(state)) != RDD_OK) {
		goto error;
	}

	*self = w;
	return RDD_OK;

error:
	*self = 0;
	if (pathbuf != 0) free(pathbuf);
	if (pathcopy != 0) free(pathcopy);
	if (state != 0) free(state);
	if (w != 0) free(w);
	return rc;
}

static int
part_write(RDD_WRITER *w, const unsigned char *buf, unsigned nbyte)
{
	RDD_PART_WRITER *state = w->state;
	unsigned to_write;
	int rc;

	while (nbyte > 0) {
		if (state->written >= state->splitlen) {
			/* Current part is full; close, then open next part.
			 */
			if ((rc = rdd_writer_close(state->parent)) != RDD_OK) {
				return rc;
			}
			state->parent = 0;
			if ((rc = open_next_part(state)) != RDD_OK) {
				return rc;
			}
			state->written = 0;
		}

		/* Figure out how much space is left in the current
		 * output file.
		 */
		if (state->written + nbyte > state->splitlen) {
			to_write = state->splitlen - state->written;
		} else {
			to_write = nbyte;
		}

		rc = rdd_writer_write(state->parent, buf, to_write);
		if (rc != RDD_OK) {
			return rc;
		}
		buf += to_write;
		nbyte -= to_write;
		state->written += to_write;
	}

	return RDD_OK;
}

static int
part_close(RDD_WRITER *self)
{
	RDD_PART_WRITER *state = self->state;
	int rc;

	assert(state->parent != 0);

	if ((rc = rdd_writer_close(state->parent)) != RDD_OK) {
		return rc;
	}

	free(state->pathbuf);
	state->pathbuf = 0;
	free(state->path);
	state->path = 0;

	return RDD_OK;
}
