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

#include <string.h>
#include <sys/stat.h>

#include "rdd.h"
#include "rdd_internals.h"
#include "msgprinter.h"

typedef struct _RDD_FILE_MSGPRINTER {
	char *path;
	FILE *stream;
} RDD_FILE_MSGPRINTER;

static void file_print(RDD_MSGPRINTER *printer,
		rdd_message_t type, int errcode, const char *msg);
static int  file_close(RDD_MSGPRINTER *printer, unsigned flags);

static RDD_MSGPRINTER_OPS file_ops = {
	file_print,
	file_close
};

int
rdd_mp_open_file_printer(RDD_MSGPRINTER **printer, const char *path)
{	
	RDD_FILE_MSGPRINTER *file = 0;
	RDD_MSGPRINTER *p = 0;
	char *path_copy = 0;
	int rc = RDD_OK;
	FILE *fp = NULL;

	rc = rdd_mp_open_printer(&p, &file_ops, sizeof(RDD_FILE_MSGPRINTER));
	if (rc != RDD_OK) {
		goto error;
	}

	if ((path_copy = malloc(strlen(path) + 1)) == 0) {
		rc = RDD_NOMEM;
		goto error;
	}
	strcpy(path_copy, path);

	file = (RDD_FILE_MSGPRINTER *) p->state;

	if ((fp = fopen(path, "rb")) != NULL) {     /* File exists */
		rc = RDD_EEXISTS;
		goto error;
	}
	if ((fp = fopen(path, "w")) == NULL) {
		rc = RDD_EOPEN;
		goto error;
	}

	file->stream = fp;
	file->path = path_copy;

	*printer = p;
	return RDD_OK;

error:
	*printer = 0;
	if (fp != NULL) (void) fclose(fp);
	if (path_copy != 0) free(path_copy);
	if (file != 0) free(file);
	return rc;
}

static void
file_print(RDD_MSGPRINTER *printer, rdd_message_t type, int errcode,
	const char *msg)
{
	RDD_FILE_MSGPRINTER *file = (RDD_FILE_MSGPRINTER *) printer->state;

	fprintf(file->stream, "%s\n", msg);
}

static int
file_close(RDD_MSGPRINTER *printer, unsigned flags)
{
	RDD_FILE_MSGPRINTER *file = (RDD_FILE_MSGPRINTER *) printer->state;
	struct stat fileinfo;
	mode_t ro_mode;

	if (file->stream != NULL) (void) fclose(file->stream);

	if (file->path != 0) {
		if ((flags & RDD_MP_READONLY) != 0) {
			/* Make the file read-only.
			 */
			memset(&fileinfo, 0, sizeof fileinfo);
			if (stat(file->path, &fileinfo) < 0) {
				return RDD_ECLOSE;
			}

			/* fileinfo.st_mode holds the permission bits _and_
			 * the file-type bits.  Get rid of the file-type bits
			 * and switch off the write-permission bits.
			 */
			ro_mode = fileinfo.st_mode;
			ro_mode &= ~(S_IFMT|S_IWUSR|S_IWGRP|S_IWOTH);

			if (chmod(file->path, ro_mode) < 0) {
				return RDD_ECLOSE;
			}
		}

		free(file->path);
	}

	memset(file, 0, sizeof *file);
	return RDD_OK;
}
