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

#include <stdio.h>
#include <string.h>

#include "rdd.h"
#include "rdd_internals.h"

#if defined(HAVE_LIBCRYPTO) && defined(HAVE_OPENSSL_SHA1_H) && defined(HAVE_OPENSSL_SHA_H)
#include <openssl/sha1.h>
#else
/* Use local versions to allow stand-alone compilation.
 */
#include "sha1.h"
#endif /* HAVE_LIBCRYPTO */

#include "writer.h"
#include "filter.h"

typedef struct _RDD_SHA1_STREAM_FILTER {
	SHA_CTX   sha1_state;
	unsigned char result[SHA_DIGEST_LENGTH];
} RDD_SHA1_STREAM_FILTER;

static int sha1_input(RDD_FILTER *f, const unsigned char *buf, unsigned nbyte);
static int sha1_close(RDD_FILTER *f);
static int sha1_get_result(RDD_FILTER *f, unsigned char *buf, unsigned nbyte);

static RDD_FILTER_OPS sha1_ops = {
	sha1_input,
	0,
	sha1_close,
	sha1_get_result,
	0
};

int
rdd_new_sha1_streamfilter(RDD_FILTER **self)
{
	RDD_FILTER *f;
	RDD_SHA1_STREAM_FILTER *state;
	int rc;

	rc = rdd_new_filter(&f, &sha1_ops, sizeof(RDD_SHA1_STREAM_FILTER), 0);
	if (rc != RDD_OK) {
		return rc;
	}
	state = (RDD_SHA1_STREAM_FILTER *) f->state;

	SHA1_Init(&state->sha1_state);

	*self = f;
	return RDD_OK;
}

static int
sha1_input(RDD_FILTER *f, const unsigned char *buf, unsigned nbyte)
{
	RDD_SHA1_STREAM_FILTER *state = (RDD_SHA1_STREAM_FILTER *) f->state;

	SHA1_Update(&state->sha1_state, (unsigned char *) buf, nbyte);

	return RDD_OK;
}

static int
sha1_close(RDD_FILTER *f)
{
	RDD_SHA1_STREAM_FILTER *state = (RDD_SHA1_STREAM_FILTER *) f->state;

	SHA1_Final(state->result, &state->sha1_state);

	return RDD_OK;
}

static int
sha1_get_result(RDD_FILTER *f, unsigned char *buf, unsigned nbyte)
{
	RDD_SHA1_STREAM_FILTER *state = (RDD_SHA1_STREAM_FILTER *) f->state;

	if (nbyte < SHA_DIGEST_LENGTH) return RDD_ESPACE;

	memcpy(buf, state->result, SHA_DIGEST_LENGTH);

	return RDD_OK;
}
