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
"@(#) Copyright (c) 2002\n\
	Netherlands Forensic Institute.  All rights reserved.\n";
#endif /* not lint */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <assert.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#include "rdd.h"
#include "rdd_internals.h"
#include "error.h"
#include "outfile.h"

/* Check whether path is a valid path name in the file system.
 */
static int
path_exists(const char *path, struct stat *info)
{
	return stat(path, info) != -1 || errno != ENOENT;
}


/* Opens a new output file, but refuses to overwrite
 * an existing file, unless the user specified -f.
 */
int
outfile_open(int *fdp, const char *path, int force_overwrite)
{
	struct stat statinfo;
	int open_flags;
	int fd = -1;

	open_flags = O_CREAT|O_WRONLY;
	if (path_exists(path, &statinfo)) {
		if (S_ISDIR(statinfo.st_mode)) {
			unix_error("%s is a directory", path);
		}
		if (! force_overwrite) {
			error("refusing to overwrite %s; use -f", path);
		}
		if (S_ISREG(statinfo.st_mode)) {
			open_flags |= O_TRUNC;
		}
	}

	if ((fd = open(path, open_flags, S_IRUSR|S_IWUSR)) < 0) {
		unix_error("cannot open output file %s", path);
	}

	*fdp = fd;
	return RDD_OK;
}

int
outfile_fopen(FILE **fpp, const char *path, int force_overwrite)
{
	FILE *fp;
	int fd = -1;
	int rc = RDD_OK;

	if ((rc = outfile_open(&fd, path, force_overwrite)) != RDD_OK) {
		return rc;
	}

	if ((fp = fdopen(fd, "wb")) == NULL) {
		return RDD_EOPEN;
	}

	*fpp = fp;
	return RDD_OK;
}

/* Try to make the current output file read-only, then close it.
 */
void
outfile_close(int fd, char *path)
{
	struct stat statinfo;

	if (fd < 0) return;	/* nothing open */

	if (fstat(fd, &statinfo) < 0) {
		unix_error("cannot fstat current output file");
	}
	if (close(fd) < 0) {
		unix_error("cannot close %s", path);
	}
	if (S_ISREG(statinfo.st_mode)
	&&  chmod(path, S_IRUSR|S_IRGRP|S_IROTH) < 0) {
		/* This need not be an error; we may not own
		 * the output file.
		 */
		errlognl("cannot make %s read-only", path);
	}
}

void
outfile_fclose(FILE *fp, char *path)
{
	int fd, fd2;

	fflush(fp);
	if ((fd = fileno(fp)) < 0) {
		unix_error("no file descriptor for stream (%s)", path);
	}
	if ((fd2 = dup(fd)) < 0) {
		unix_error("cannot copy file descriptor (%s)", path);
	}
	if (fclose(fp) < 0) { /* This also closes fd! */
		unix_error("cannot close stream (%s)", path);
	}
	outfile_close(fd2, path);
}
