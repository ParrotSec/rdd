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


/* A unit-test for the sha1 stream filter.
 */

#ifdef HAVE_CONFIG_H
#include"config.h"
#endif

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "rdd.h"
#include "writer.h"
#include "filter.h"
#include "filterset.h"
#include "rdd_internals.h"
#include "sha1.h"
#include "error.h"
#include "rddtest.h"

/*
 * Command-line arguments:
 * 1: file to calculate the SHA-1 hash of
 * 2: SHA-1 of the file to match with the calculated SHA-1
 * 
 * Output to command line:
 * PASSED
 * STRING FAILED
 * FILE FAILED
 * 
 * Error messages go to stderr.
 */

typedef struct _TESTCASE {
	const char *input;
	unsigned    size;
	const char *sha1;
} TESTCASE;

static TESTCASE test_cases[] = {
	{
		"aa", 
		2,
		"e0c9035898dd52fc65c41454cec9c4d2611bfb37"
	},
	{
		"Listen very carefully, I will say this only once!", 
		49,
		"99e149e89b3c39d39371b18468ec6bd1374aeaf0"
	}
};

static void
filter_error(char *fmt, ...)
{
	va_list ap;

	fprintf(stderr, "[tsha1filter] ");
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");

	exit(EXIT_FAILURE);
}

#if 0
static void
usage(void)
{
	fprintf(stderr, "Usage: tsha1stream <file> <SHA-1>\n");
	exit(EXIT_FAILURE);
}

static void
verifyFile(int argc, char **argv)
{
	RDD_FILTER *f = 0;
	int rc;

	/* XXX TODO calculate the SHA-1 hash value.
	 */

	rc = rdd_new_sha1_streamfilter(&f);
	
	/* Read the contents of the file and push all bytes into
	 * the filter.
	 */

	if (argc != 3) {
		usage();	
	}
}
#endif

/* Calculates the SHA-1 hash of a predefined string and checks
 * the hash.
 */
static void
verifyStrings(unsigned i, TESTCASE *testcase)
{
	RDD_FILTER *sha1_filter = 0;
	RDD_FILTERSET fset;
	char *copy = 0;
	int rc;
	unsigned char sha1_digest[SHA_DIGEST_LENGTH];
	char sha1string[2*SHA_DIGEST_LENGTH+1];

	printf("testing string %u......", i);

	if ((copy = malloc(testcase->size + 1)) == 0) {
		filter_error("out of memory");
	}

	/* Set up filter and filter set
	 */ 

	rc = rdd_fset_init(&fset);
	if (rc != RDD_OK) {
		filter_error("rdd_fset_init() returned %d instead of RDD_OK", rc);
	}

	/* Set up new SHA1 digest stream filter.
	 */
	rc = rdd_new_sha1_streamfilter(&sha1_filter);
	if (rc != RDD_OK) {
		filter_error("rdd_new_sha1_streamfilter() returned %d "
				" instead of RDD_OK", rc);
	}
	
	/* Install the filter in the filterset.
	 */
	rc = rdd_fset_add(&fset, "SHA-1-filter", sha1_filter);
	if (rc != RDD_OK) {
		filter_error("rdd_fset_add() returned %d instead of RDD_OK", rc);
	}
	
	/* Make a copy of the test input so that we can check whether
	 * the input string is modified (it should not be modified).
	 */
	strcpy(copy, testcase->input);

	/* Push the teststring into the filterset.
	 */
	rc = rdd_fset_push(&fset, (unsigned char *) copy, testcase->size);
	if (rc != RDD_OK) {
		filter_error("rdd_fset_push() returned %d instead of RDD_OK", rc);
	}

	/* Close all filters in the filterset; the final SHA-1 digest is
	 * saved.
	 */
	if ((rc = rdd_fset_close(&fset)) != RDD_OK) {
		filter_error("rdd_fset_close() returned %d instead of RDD_OK", rc);
	}

	/* Get the SHA-1 digest filter.
	 */
	if ((rc = rdd_fset_get(&fset, "SHA-1-filter", &sha1_filter)) != RDD_OK) {
		filter_error("rdd_fset_get() returned %d instead of RDD_OK", rc);
	}
	
	/* Get the SHA-1 hash from the filter.
	 */
	rc = rdd_filter_get_result(sha1_filter, sha1_digest, SHA_DIGEST_LENGTH);
	if (rc != RDD_OK) {
		filter_error("rdd_filter_get_result() returned %d instead of RDD_OK", rc);
	}
	
	/* Convert the binary digest buffer to a human-readable hex string.
	 */
	rc = rdd_buf2hex(sha1_digest, SHA_DIGEST_LENGTH,
			 sha1string, sizeof sha1string);	
	if (rc != RDD_OK) {
		filter_error("cannot convert SHA-1 digest");
	}
	
	if (strcmp(sha1string, testcase->sha1) != 0) {
		filter_error("incorrect SHA-1 hash value");	
	}

	/* Check whether the input buffer has been modified.
	 */
	if (strcmp(copy, testcase->input) != 0) {
		filter_error("someone modified the input buffer");
	}
	
	if (copy != 0) {
		free(copy);
	}

	printf("OK\n");
}
	
static void 
testFilters(void)
{
	unsigned char sha1_digest[20];
	RDD_FILTER *f = 0;
	RDD_FILTER *g = 0;
	RDD_FILTERSET fset;
	int rc;

	printf("Testing functions on bad behaviour.\n");

	rc = rdd_fset_init(&fset);

	rc = rdd_fset_get(&fset, "xx", &f);
	if (rc != RDD_NOTFOUND) {
		filter_error("rdd_fset_get() should return RDD_NOTFOUND when there are no filters in the filterset");
	}
 
	rc = rdd_new_sha1_streamfilter(&f);

	rc = rdd_fset_add(&fset, "", f);
	if (rc != RDD_BADARG) {
		filter_error("rdd_fset_add() returned %d instead of RDD_BAD_ARG", rc);
	}
	
	/*forget everything, start with a new filterset*/
	rc = rdd_fset_clear(&fset);
	if (rc != RDD_OK) {
		filter_error("rdd_fset_clear() returned %d instead of RDD_OK", rc);
	}
	
	rc = rdd_fset_init(&fset);
	if (rc != RDD_OK) {
		filter_error("rdd_fset_init() returned %d instead of RDD_OK", rc);
	}
	
	/*build a couple of filters and add them to the filter set*/
	rc = rdd_new_sha1_streamfilter(&f);
	if (rc != RDD_OK) {
		filter_error("rdd_sha1_stream_filter() returned %d, should return RDD_OK", rc);
	}
	
	rc = rdd_new_sha1_streamfilter(&g);
	if (rc != RDD_OK) {
		filter_error("rdd_sha1_stream_filter() returned %d, should return RDD_OK", rc);
	}
	
	rc = rdd_fset_add(&fset, "SHA-1 filter", f);
	if (rc != RDD_OK) {
		filter_error("rdd_fset_add() returned %d instead of RDD_OK", rc);
	}
	
	rc = rdd_fset_add(&fset, "SHA-1 filter", g);
	if (rc != RDD_EEXISTS) {
		filter_error("rdd_fset_add() accepted an existing filter name");
	}

	rc = rdd_fset_add(&fset, "SHA-1 filter-2", g);

	f = g = 0;

	rc = rdd_fset_get(&fset, "xx", &f);
	if (rc != RDD_NOTFOUND) {
		filter_error("rdd_fset_get() found non-existing filter.");
	}

	/* Get buffers from filters.
	 */
	rc = rdd_fset_push(&fset, (unsigned char *) "olla vogala", 12);
	if (rc != RDD_OK) {
		filter_error("rdd_fset_push() returned %d instead of RDD_OK", rc); 
	}

	rc = rdd_fset_close(&fset);
	if (rc != RDD_OK) {
		filter_error("rdd_fset_close() returned %d instead of RDD_OK", rc); 
	}

	rc = rdd_fset_get(&fset, "SHA-1 filter", &f);
	if (rc != RDD_OK) {
		filter_error("rdd_fset_get() returned %d instead of RDD_OK", rc); 
	}

	
	rc = rdd_filter_get_result(f, sha1_digest, sizeof sha1_digest);
	if (rc != RDD_OK) {
		filter_error("rdd_filter_get_result() failed to get SHA-1 result"); 
	}

	rc = rdd_filter_get_result(f, sha1_digest, 0);
	if (rc != RDD_ESPACE) {
		filter_error("undersized (0) SHA-1 buffer was not detected");
	}

	rc = rdd_filter_get_result(f, sha1_digest, 19);
	if (rc != RDD_ESPACE) {
		filter_error("undersized (19) SHA-1 buffer was not detected");
	}

	rc = rdd_filter_get_result(f, sha1_digest, 100);
	if (rc != RDD_OK) {
		filter_error("rdd_filter_get_result() failed to get SHA-1 result"); 
	}
}

int
main(int argc, char **argv)
{
	unsigned i;

	printf("------------------Testing SHA-1 routines\n");

	for (i = 0; i < (sizeof test_cases) / sizeof(test_cases[0]); i++) {
		verifyStrings(i+1, &test_cases[i]);
	}

	testFilters();

#if 0
	verifyFile(argc, argv);
#endif

	printf("------------------Finished testing SHA-1 routines\n");
	
	return 0;
}
