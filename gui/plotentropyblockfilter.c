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

#include <math.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include "rdd.h"
#include "rdd_internals.h"
#include "rddgui.h"
#include "error.h"
#include "writer.h"
#include "filter.h"
#include "msgprinter.h"

#define NUM_BYTE_VAL   256

#define RDD_LN2        0.69314718055994530942

typedef struct _RDD_PLOTENTROPY_BLOCKFILTER {
	rdd_count_t     blocknum;
	unsigned        histogram[NUM_BYTE_VAL];
	void          (*handler)(unsigned blocknum, double entropy, void *env);
	void           *env;
} RDD_PLOTENTROPY_BLOCKFILTER;

static int plotentropy_input(RDD_FILTER *f,
			const unsigned char *buf, unsigned nbyte);
static int plotentropy_block(RDD_FILTER *f, unsigned nbyte);
static int plotentropy_close(RDD_FILTER *f);
static int plotentropy_free(RDD_FILTER *f);

static RDD_FILTER_OPS plotentropy_ops = {
	plotentropy_input,
	plotentropy_block,
	plotentropy_close,
	0,
	plotentropy_free
};


int
rddgui_new_plotentropy_blockfilter(RDD_FILTER **self, unsigned blocksize,
	void (*entropy_handler)(unsigned blocknum, double entropy, void *env),
	void *env)
{
	RDD_FILTER *f = 0;
	RDD_PLOTENTROPY_BLOCKFILTER *state = 0;
	int rc;

	rc = rdd_new_filter(&f, &plotentropy_ops, sizeof(RDD_PLOTENTROPY_BLOCKFILTER),
			blocksize);
	if (rc != RDD_OK) {
		goto error;
	}
	state = (RDD_PLOTENTROPY_BLOCKFILTER *) f->state;

	state->handler = entropy_handler;
	state->env = env;
	state->blocknum = 0;
	memset(state->histogram, 0, sizeof(state->histogram));

	*self = f;
	return RDD_OK;

error:
	*self = 0;
	if (state != 0) free(state);
	if (f != 0) free(f);
	return rc;
}

/** Computes block statistics based on the byte-value histogram.
 *  The modus is the byte value that occurs most in the block.
 *  Entropy measures randomness in a block.  It is computed as
 *  sum(-Pi * (log2(Pi))), where Pi is the occurrence frequency of
 *  byte value i and where i ranges over all byte values with positive Pi.
 */
static void
compute_histogram_stats(RDD_PLOTENTROPY_BLOCKFILTER *state, unsigned block_size,
	double *entropy)
{
	unsigned byte, count;
	double p, ent;

	ent = 0.0;
	for (byte = 0; byte < NUM_BYTE_VAL; byte++) {
		count = state->histogram[byte];
		if (count > 0) {
			p = ((double) count) / ((double) block_size);
			ent += -p * (log(p) / RDD_LN2);
		}
	}

	*entropy = ent;
}

/** Uses the byte values in buf to update the histogramming
 *  statistics for the current block.
 */
static int
plotentropy_input(RDD_FILTER *f, const unsigned char *buf, unsigned nbyte)
{
	RDD_PLOTENTROPY_BLOCKFILTER *state = (RDD_PLOTENTROPY_BLOCKFILTER *) f->state;
	unsigned byte;
	unsigned i;

	for (i = 0; i < nbyte; i++) {
		byte = buf[i];
		state->histogram[byte]++;
	}

	return RDD_OK;
}

/** Computes and outputs the per-block histogramming statistics:
 *  entropy, mininum byte value, maximum byte value, and modus.
 */
static int
plotentropy_block(RDD_FILTER *f, unsigned nbyte)
{
	RDD_PLOTENTROPY_BLOCKFILTER *state = (RDD_PLOTENTROPY_BLOCKFILTER *) f->state;
	double entropy;

	compute_histogram_stats(state, nbyte, &entropy);

	(*state->handler)(state->blocknum, entropy, state->env);

	state->blocknum++;
	memset(state->histogram, 0, sizeof(state->histogram));

	return RDD_OK;
}

static int
plotentropy_close(RDD_FILTER *f)
{
	return RDD_OK;
}

static int
plotentropy_free(RDD_FILTER *f)
{
	return RDD_OK;
}
