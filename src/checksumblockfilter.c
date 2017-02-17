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
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <zlib.h>

#include "rdd.h"
#include "rdd_internals.h"
#include "error.h"
#include "writer.h"
#include "filter.h"
#include "filterset.h"
#include "outfile.h"


/* State maintained by a checksum filter.
 */
typedef struct _RDD_CHECKSUM_BLOCKFILTER {
	char                    *path;          /* output file */
	FILE                    *fp;		/* output stream */
	rdd_checksum_t           checksum;	/* running checksum */
	rdd_checksum_algorithm_t algorithm;	/* checksum algorithm */
} RDD_CHECKSUM_BLOCKFILTER;

/* Forward declarations.
 */
static int checksum_input(RDD_FILTER *f,
			const unsigned char *buf, unsigned nbyte);
static int checksum_block(RDD_FILTER *f, unsigned nbyte);
static int checksum_close(RDD_FILTER *f);
static int checksum_free(RDD_FILTER *f);

static RDD_FILTER_OPS checksum_ops = {
	checksum_input,
	checksum_block,
	checksum_close,
	0,
	checksum_free
};

static void
reset_checksum(RDD_CHECKSUM_BLOCKFILTER *state)
{
	switch (state->algorithm) {
	case RDD_ADLER32:
		state->checksum = adler32(0, NULL, 0);
		break;
	case RDD_CRC32:
		state->checksum = crc32(0, NULL, 0);
		break;
	}
}

static void
init_header(RDD_CHECKSUM_FILE_HEADER* rec,
	    int type, size_t blocksize,
	    off_t offset, off_t imgsize)
{
	memset(rec, '\000', sizeof(RDD_CHECKSUM_FILE_HEADER));
	rec->magic = RDD_CHECKSUM_MAGIC;
	rec->version = RDD_CHECKSUM_VERSION;
	rec->flags |= type;
	rec->blocksize = blocksize;
	rec->offset = offset;
	rec->reserved = 0x0000;
	rec->imagesize = imgsize;
}

static int
checksum_input(RDD_FILTER *f, const unsigned char *buf, unsigned nbyte)
{
	RDD_CHECKSUM_BLOCKFILTER *state = (RDD_CHECKSUM_BLOCKFILTER *) f->state;

	switch (state->algorithm) {
	case RDD_ADLER32:
		state->checksum = adler32(state->checksum, buf, nbyte);
		break;
	case RDD_CRC32:
		state->checksum = crc32(state->checksum, buf, nbyte);
		break;
	}

	return RDD_OK;
}

static int
checksum_block(RDD_FILTER *f, unsigned pos)
{
	RDD_CHECKSUM_BLOCKFILTER *state = (RDD_CHECKSUM_BLOCKFILTER *) f->state;
	rdd_checksum_t checksum = state->checksum;

	if (fwrite(&checksum, sizeof checksum, 1, state->fp) < 1) {
		return RDD_EWRITE;
	}
	reset_checksum(state);

	return RDD_OK;
}

static int
checksum_close(RDD_FILTER *f)
{
	RDD_CHECKSUM_BLOCKFILTER *state = (RDD_CHECKSUM_BLOCKFILTER *) f->state;

	outfile_fclose(state->fp, state->path);
	state->fp = NULL;

	return RDD_OK;
}

static int
checksum_free(RDD_FILTER *f)
{
	RDD_CHECKSUM_BLOCKFILTER *state = (RDD_CHECKSUM_BLOCKFILTER *) f->state;

	free(state->path);
	state->path = 0;

	return RDD_OK;
}

static int
new_checksum_blockfilter(RDD_FILTER **self, rdd_checksum_algorithm_t alg,
		unsigned blocksize, const char *outpath, int overwrite)
{
	RDD_FILTER *f = 0;
	RDD_CHECKSUM_BLOCKFILTER *state = 0;
	RDD_CHECKSUM_FILE_HEADER header;
	char *path = 0;
	FILE *fp = NULL;
	int rc = RDD_OK;

	if (blocksize <= 0) return RDD_BADARG;
	if (alg != RDD_ADLER32 && alg != RDD_CRC32) return RDD_BADARG;

	rc = rdd_new_filter(&f, &checksum_ops, sizeof(RDD_CHECKSUM_BLOCKFILTER),
			blocksize);
	if (rc != RDD_OK) {
		goto error;
	}
	state = (RDD_CHECKSUM_BLOCKFILTER *)f->state;

	if ((path = malloc(strlen(outpath) + 1)) == 0) {
		rc = RDD_NOMEM;
		goto error;
	}
	strcpy(path, outpath);

	if ((rc = outfile_fopen(&fp, outpath, overwrite)) != RDD_OK) {
		goto error;
	}

	state->path = path;
	state->fp = fp;
	state->algorithm = alg;
	reset_checksum(state);

	init_header(&header, alg, blocksize, 0, 0);
	if (fwrite((const void *) &header, sizeof(header), 1, state->fp) < 1) {
		rc = RDD_EWRITE;
		goto error;
	}

	*self = f;
	return RDD_OK;

error:
	*self = 0;
	if (fp != NULL) fclose(fp);
	if (path != 0) free(path);
	if (state != 0) free(state);
	if (f != 0) free(f);
	return rc;
}

int
rdd_new_adler32_blockfilter(RDD_FILTER **f,
		unsigned blocksize, const char *outpath, int overwrite)
{
	return new_checksum_blockfilter(f, RDD_ADLER32,
					blocksize, outpath, overwrite);
}

int
rdd_new_crc32_blockfilter(RDD_FILTER **f,
		unsigned blocksize, const char *outpath, int overwrite)
{
	return new_checksum_blockfilter(f, RDD_CRC32,
					blocksize, outpath, overwrite);
}
