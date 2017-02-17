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

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "rdd.h"
#include "writer.h"

/* Forward declarations
 */
static int safe_write(RDD_WRITER *w, const unsigned char *buf, unsigned nbyte);
static int safe_close(RDD_WRITER *w);

static RDD_WRITE_OPS safe_write_ops = {
	safe_write,
	safe_close
};

typedef struct _RDD_SAFE_WRITER {
	char *path;
	RDD_WRITER *parent;
} RDD_SAFE_WRITER;


/* Check whether path is a valid path name in the file system.
 */
static int
path_exists(const char *path, struct stat *info)
{
	return stat(path, info) != -1 || errno != ENOENT;
}

int
rdd_open_safe_writer(RDD_WRITER **self, const char *path,
			rdd_write_mode_t wmode)
{
	RDD_WRITER *w = 0;
	RDD_SAFE_WRITER *state = 0;
	struct stat statinfo;
	int rc = RDD_OK;
	char *pathcopy = 0;

	if (wmode == RDD_NO_OVERWRITE && path_exists(path, &statinfo)) {
		rc = RDD_EEXISTS;
		goto error;
	}

	rc = rdd_new_writer(&w, &safe_write_ops, sizeof(RDD_SAFE_WRITER));
	if (rc != RDD_OK) {
		goto error;
	}
	state = (RDD_SAFE_WRITER *) w->state;

	if ((pathcopy = malloc(strlen(path) + 1)) == 0) {
		rc = RDD_NOMEM;
		goto error;
	}
	strcpy(pathcopy, path);
	state->path = pathcopy;

	rc = rdd_open_file_writer(&state->parent, path);
	if (rc != RDD_OK) {
		goto error;
	}

	*self = w;
	return RDD_OK;

error:
	*self = 0;
	if (pathcopy != 0) free(pathcopy);
	if (state != 0) free(state);
	if (w != 0) free(w);
	return rc;
}

static int
safe_write(RDD_WRITER *w, const unsigned char *buf, unsigned nbyte)
{
	RDD_SAFE_WRITER *state = w->state;

	return rdd_writer_write(state->parent, buf, nbyte);
}

static int
safe_close(RDD_WRITER *self)
{
	RDD_SAFE_WRITER *state = self->state;
	struct stat statinfo;
	int rc;

	if ((rc = rdd_writer_close(state->parent)) != RDD_OK) {
		return rc;
	}

	if (stat(state->path, &statinfo) < 0) {
		return RDD_ECLOSE;
	}

	if (S_ISREG(statinfo.st_mode)
	&&  chmod(state->path, S_IRUSR|S_IRGRP|S_IROTH) < 0) {
		/* This need not be an error; we may not own
		 * the output file.
		 */
	}

	free(state->path);
	state->path = 0;

	return RDD_OK;
}
