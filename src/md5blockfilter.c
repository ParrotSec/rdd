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

#include "rdd.h"
#include "rdd_internals.h"

#include <math.h>
#include <string.h>
#include <stdio.h>

#if defined(HAVE_LIBCRYPTO) && defined(HAVE_OPENSSL_MD5_H) && defined(HAVE_OPENSSL_SHA_H)
#include <openssl/md5.h>
#include <openssl/sha.h>
#else
/* Use local versions to allow stand-alone compilation.
 */
#include "md5.h"
#include "sha1.h"
#endif /* HAVE_LIBCRYPTO */

#include "error.h"
#include "writer.h"
#include "filter.h"
#include "msgprinter.h"

typedef struct _RDD_BLOCKHASH_FILTER {
	rdd_count_t     blocknum;
	MD5_CTX         md5_state;
	char           *path;
	RDD_MSGPRINTER *printer;
} RDD_BLOCKHASH_FILTER;

static int blockhash_input(RDD_FILTER *f,
			const unsigned char *buf, unsigned nbyte);
static int blockhash_block(RDD_FILTER *f, unsigned nbyte);
static int blockhash_close(RDD_FILTER *f);
static int blockhash_free(RDD_FILTER *f);

static RDD_FILTER_OPS blockhash_ops = {
	blockhash_input,
	blockhash_block,
	blockhash_close,
	0,
	blockhash_free
};

int
rdd_new_md5_blockfilter(RDD_FILTER **self, unsigned blocksize,
			const char *outpath, int force_overwrite)
{
	RDD_FILTER *f = 0;
	RDD_BLOCKHASH_FILTER *state = 0;
	RDD_MSGPRINTER *prn = 0;
	char *path = 0;
	int rc;

	rc = rdd_new_filter(&f, &blockhash_ops, sizeof(RDD_BLOCKHASH_FILTER),
			blocksize);
	if (rc != RDD_OK) {
		goto error;
	}
	state = (RDD_BLOCKHASH_FILTER *)f->state;

	if ((path = malloc(strlen(outpath) + 1)) == 0) {
		rc = RDD_NOMEM;
		goto error;
	}
	strcpy(path, outpath);

	if ((rc = rdd_mp_open_file_printer(&prn, outpath)) != RDD_OK) {
		goto error;
	}

	state->path = path;
	state->printer = prn;
	MD5_Init(&state->md5_state);

	*self = f;
	return RDD_OK;

error:
	*self = 0;
	if (path != 0) free(path);
	if (state != 0) free(state);
	if (f != 0) free(f);
	return rc;
}

/** Updates the running MD5 hash value for the current block.
 */
static int
blockhash_input(RDD_FILTER *self, const unsigned char *buf, unsigned nbyte)
{
	RDD_BLOCKHASH_FILTER *state = (RDD_BLOCKHASH_FILTER *) self->state;

	MD5_Update(&state->md5_state, buf, nbyte);

	return RDD_OK;
}

/** Outputs the MD5 hash value of the block that has just been
 *  completed.
 */
static int
blockhash_block(RDD_FILTER *self, unsigned block_size)
{
	RDD_BLOCKHASH_FILTER *state = (RDD_BLOCKHASH_FILTER *) self->state;
	unsigned char md5bytes[MD5_DIGEST_LENGTH];
	char digest[2*MD5_DIGEST_LENGTH + 1];
	int rc;

	MD5_Final(md5bytes, &state->md5_state);

	rc = rdd_buf2hex(md5bytes, sizeof md5bytes, digest, sizeof digest);
	if (rc != RDD_OK) {
		return rc;
	}
	rdd_mp_message(state->printer, RDD_MSG_INFO, "%llu\t%s",
			state->blocknum, digest);

	state->blocknum++;
	MD5_Init(&state->md5_state);

	return RDD_OK;
}

static int
blockhash_close(RDD_FILTER *self)
{
	RDD_BLOCKHASH_FILTER *state = (RDD_BLOCKHASH_FILTER *) self->state;
	unsigned char md5bytes[MD5_DIGEST_LENGTH];
	int rc;

	MD5_Final(md5bytes, &state->md5_state);

	rc = rdd_mp_close(state->printer, RDD_MP_RECURSE|RDD_MP_READONLY);
	if (rc != RDD_OK) {
		return rc;
	}

	return RDD_OK;
}

static int
blockhash_free(RDD_FILTER *self)
{
	RDD_BLOCKHASH_FILTER *state = (RDD_BLOCKHASH_FILTER *) self->state;

	free(state->path);

	return RDD_OK;
}
