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


/* State maintained by a checksum filter.
 */
typedef struct _RDD_VERIFY_BLOCKFILTER {
	FILE                    *fp;		/* stream with checksums */
	rdd_checksum_t           checksum;	/* running checksum */
	rdd_checksum_algorithm_t algorithm;	/* checksum algorithm */
	int                      swap;
	rdd_count_t              blocknum;
	unsigned                 blocksize;
	rdd_count_t              num_error;	/* error count */
	rdd_fltr_error_fun       error_fun;	/* callback function */
	void                    *error_env;	/* callback environment */
} RDD_VERIFY_BLOCKFILTER;

/* Forward declarations.
 */
static int verify_input(RDD_FILTER *f,
			const unsigned char *buf, unsigned nbyte);
static int verify_block(RDD_FILTER *f, unsigned nbyte);
static int verify_get_result(RDD_FILTER *f, unsigned char *buf, unsigned nbyte);

static RDD_FILTER_OPS verify_ops = {
	verify_input,
	verify_block,
	0,	/* close */
	verify_get_result,
	0	/* free */
};

static void
reset_checksum(RDD_VERIFY_BLOCKFILTER *state)
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

static int
verify_input(RDD_FILTER *f, const unsigned char *buf, unsigned nbyte)
{
	RDD_VERIFY_BLOCKFILTER *state = (RDD_VERIFY_BLOCKFILTER *) f->state;

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

static u_int32_t
swap32(u_int32_t n)
{
	return
	  ((n << 24) & 0xff000000)
	| ((n <<  8) & 0x00ff0000)
	| ((n >>  8) & 0x0000ff00)
	| ((n >> 24) & 0x000000ff)
	;
}

static int
read_chksum(RDD_VERIFY_BLOCKFILTER *state, rdd_checksum_t *result)
{
	rdd_checksum_t chksum;

	if (fread(&chksum, sizeof chksum, 1, state->fp) != 1) {
		return RDD_EREAD;
	}
	if (state->swap) {
		chksum = swap32(chksum);
	}
	*result = chksum;
	return RDD_OK;
}

static void
verify_checksum(RDD_VERIFY_BLOCKFILTER *state, u_int32_t stored_checksum)
{
	rdd_count_t offset;

	if (state->checksum == stored_checksum) {
		return;	/* checksum ok */
	}

	state->num_error++;

	if (state->error_fun != 0) {
		offset = state->blocknum * state->blocksize;
		(*state->error_fun)(offset,
				    stored_checksum, state->checksum,
				    state->error_env);
	}
}

static int
verify_block(RDD_FILTER *f, unsigned pos)
{
	RDD_VERIFY_BLOCKFILTER *state = (RDD_VERIFY_BLOCKFILTER *) f->state;
	rdd_checksum_t stored_checksum;
	int rc;

	if ((rc = read_chksum(state, &stored_checksum)) != RDD_OK) {
		return rc;
	}

	verify_checksum(state, stored_checksum);

	reset_checksum(state);

	state->blocknum++;

	return RDD_OK;
}

static int
verify_get_result(RDD_FILTER *f, unsigned char *buf, unsigned nbyte)
{
	RDD_VERIFY_BLOCKFILTER *state = (RDD_VERIFY_BLOCKFILTER *) f->state;

	if (nbyte < sizeof(unsigned)) {
		return RDD_NOMEM;
	}

	memcpy(buf, &state->num_error, sizeof(state->num_error));

	return RDD_OK;
}

static int
new_verify_checksum_blockfilter(RDD_FILTER **self,
	rdd_checksum_algorithm_t alg, FILE *fp, unsigned blocksize, int swap,
	rdd_fltr_error_fun error_fun, void *error_env)
{
	RDD_FILTER *f = 0;
	RDD_VERIFY_BLOCKFILTER *state = 0;
	int rc = RDD_OK;

	if (blocksize <= 0) return RDD_BADARG;
	if (alg != RDD_ADLER32 && alg != RDD_CRC32) return RDD_BADARG;

	rc = rdd_new_filter(&f, &verify_ops,
			sizeof(RDD_VERIFY_BLOCKFILTER), blocksize);
	if (rc != RDD_OK) {
		goto error;
	}
	state = (RDD_VERIFY_BLOCKFILTER *)f->state;

	state->fp = fp;
	state->algorithm = alg;
	state->swap = swap;
	state->blocknum = 0;
	state->blocksize = blocksize;
	state->num_error = 0;
	state->error_fun = error_fun;
	state->error_env = error_env;
	reset_checksum(state);

	*self = f;
	return RDD_OK;

error:
	*self = 0;
	if (fp != NULL) fclose(fp);
	if (state != 0) free(state);
	if (f != 0) free(f);
	return rc;
}

int
rdd_new_verify_adler32_blockfilter(RDD_FILTER **f, FILE *fp,
	unsigned blocksize, int swap, rdd_fltr_error_fun err, void *env)
{
	return new_verify_checksum_blockfilter(f, RDD_ADLER32,
						fp, blocksize, swap,
						err, env);
}

int
rdd_new_verify_crc32_blockfilter(RDD_FILTER **f, FILE *fp,
	unsigned blocksize, int swap, rdd_fltr_error_fun err, void *env)
{
	return new_verify_checksum_blockfilter(f, RDD_CRC32,
						fp, blocksize, swap,
						err, env);
}
