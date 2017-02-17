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


/** @file
 * \brief Unit test program for the \c alignedbuf module.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>

#include "rdd.h"
#include "alignedbuf.h"

typedef struct _RDD_ALIGNEDBUF_TESTCASE {
	unsigned size;		/**< buffer size */
	unsigned alignment;	/**< alignment */
	int      errcode;	/**< expected errcode for rdd_new_alignedbuf */
} RDD_ALIGNEDBUF_TESTCASE;

static RDD_ALIGNEDBUF_TESTCASE testcases[] = {
	{0, 0, RDD_BADARG},
	{1, 0, RDD_BADARG},
#if 0
	/* This test case does not always produce RDD_NOMEM
	 * on machines with a lot of memory.
	 */
	{~0, ~0, RDD_NOMEM},
#endif
	{1024, 0, RDD_BADARG},
	{1024, 1, RDD_OK},
	{256*1024, 512, RDD_OK},
	{8*1024*1024, 512, RDD_OK},
	{1024, 13, RDD_OK},
	{2, 13, RDD_OK},
	{0, 1, RDD_OK}
};

static void
test(RDD_ALIGNEDBUF_TESTCASE *tc) 
{
	RDD_ALIGNEDBUF buf;
	ptrdiff_t diff;
	int rc;

	printf("%u %u %d\n", tc->size, tc->alignment, tc->errcode);

	rc = rdd_new_alignedbuf(&buf, tc->size, tc->alignment);
	if (rc != tc->errcode) {
		printf("unexpected return code [%d]\n", rc);
		exit(EXIT_FAILURE);
	}

	if (rc != RDD_OK && rc != RDD_NOMEM && rc != RDD_BADARG) {
		printf("bad return code [%d]\n", rc);
		exit(EXIT_FAILURE);
	}

	if (rc != RDD_OK) return;

	if ((buf.aligned - (unsigned char *)0) % tc->alignment != 0) {
		printf("buffer not aligned\n");
		exit(EXIT_FAILURE);
	}

	diff = buf.aligned - buf.unaligned;
	if (diff < 0 || diff >= (signed) tc->alignment) {
		printf("aligned, but at wrong position\n");
		exit(EXIT_FAILURE);
	}

	rc = rdd_free_alignedbuf(&buf);
	if (rc != RDD_OK) {
		printf("cannot free aligned buf\n");
		exit(EXIT_FAILURE);
	}
}

int
main(int argc, char **argv)
{
	unsigned i;

	for (i = 0; i < (sizeof testcases) / (sizeof testcases[0]); i++) {
		test(&testcases[i]);
	}

	return 0;
}
