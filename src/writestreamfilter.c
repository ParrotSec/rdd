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


/* The writefilter module implements a filter that writes
 * a data stream to one or more output files.
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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#include "rdd.h"
#include "rdd_internals.h"
#include "error.h"
#include "writer.h"
#include "filter.h"
#include "writer.h"

typedef struct _RDD_WRITE_STREAM_FILTER {
	RDD_WRITER *writer;
} RDD_WRITE_STREAM_FILTER;

static int write_input(RDD_FILTER *f, const unsigned char *buf, unsigned nbyte);
static int write_close(RDD_FILTER *f);

static RDD_FILTER_OPS write_ops = {
	write_input,
	0,
	write_close,
	0,
	0
};

int
rdd_new_write_streamfilter(RDD_FILTER **self, RDD_WRITER *writer)
{
	RDD_FILTER *f;
	RDD_WRITE_STREAM_FILTER *state;
	int rc;

	rc = rdd_new_filter(&f, &write_ops, sizeof(RDD_WRITE_STREAM_FILTER), 0);
	if (rc != RDD_OK) {
		return rc;
	}
	state = (RDD_WRITE_STREAM_FILTER *) f->state;

	state->writer = writer;

	*self = f;
	return RDD_OK;
}

static int
write_input(RDD_FILTER *f, const unsigned char *buf, unsigned nbyte)
{
	RDD_WRITE_STREAM_FILTER *state = (RDD_WRITE_STREAM_FILTER *) f->state;

	return rdd_writer_write(state->writer, buf, nbyte);
}

static int
write_close(RDD_FILTER *f)
{
	return RDD_OK;
}
