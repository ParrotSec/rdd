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

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>

#include "rdd.h"
#include "writer.h"

static char *progname;

static int test_write(RDD_WRITER *w, const unsigned char *buf, unsigned nbyte);
static int test_close(RDD_WRITER *w);

static RDD_WRITE_OPS test_writer = {
	test_write,
	test_close
};

static struct _RDD_WRITER_TEST {
	RDD_WRITE_OPS *ops;
	unsigned statesize;
	int result;
} testcases[] = {
	{&test_writer, 0, RDD_OK},
	{0, 0, RDD_BADARG},
#if 0
	/* This test case does not always produce RDD_NOMEM
	 * on machines with a lot of memory.
	 */
	{&test_writer, ~0, RDD_NOMEM}
#endif
};


static int
test_write(RDD_WRITER *w, const unsigned char *buf, unsigned nbyte)
{
	return RDD_OK;
}

static int
test_close(RDD_WRITER *w)
{
	return RDD_OK;
}

static void
command_line(int argc, char **argv)
{
	if (argc != 1) {
		fprintf(stderr, "Usage: %s\n", progname);
		exit(EXIT_FAILURE);
	}
}

static void
run_tests(void)
{
	struct _RDD_WRITER_TEST *wt;
	RDD_WRITER *writer = 0;
	unsigned i;
	unsigned n;
	int rc;

	n = (sizeof testcases) / sizeof(testcases[0]);

	for (i = 0; i < n; i++) {
		wt = &testcases[i];
		writer = 0;

		rc = rdd_new_writer(&writer, wt->ops, wt->statesize);
		if (rc != wt->result) {
			printf("test %u: bad return value; "
				"got %d, expected %d\n", i+1, rc, wt->result);
			exit(EXIT_FAILURE);
		}

		if (rc != RDD_OK) {
			continue;
		}

		rc = rdd_writer_close(writer);
		if (rc != RDD_OK) {
			printf("test %u: close failed\n", i+1);
			exit(EXIT_FAILURE);
		}
	}
}

int
main(int argc, char **argv)
{
	progname = argv[0];

	command_line(argc, argv);

	run_tests();

	return 0;
}
