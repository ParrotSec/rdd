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
 *  \brief Unit test program for the \c numparser module.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <stdio.h>

#include "rdd.h"
#include "numparser.h"

typedef struct _RDD_TEST_BIGNUM {
	const char *testnum;	/**< test string */
	unsigned    flags;	/**< flags to pass to rdd_parse_bignum() */
	int         errcode;	/**< expected return code */
	rdd_count_t result;	/**< expected return value (number parsed) */
} RDD_TEST_BIGNUM;

RDD_TEST_BIGNUM bignums[] = {
	{"abc",
		0, RDD_ESYNTAX, 0},
	{" 1",
		0, RDD_ESYNTAX, 0},
	{"-1",
		0, RDD_ESYNTAX, 0},
	{"8T",
		0, RDD_ESYNTAX, 0},
	{"-1",
		0, RDD_ESYNTAX, 0},
	{"-3k",
		0, RDD_ESYNTAX, 0},
	{"3.4",
		0, RDD_ESYNTAX, 0},
	{"11111111111111111111111111111111111111111111111111",
		0, RDD_ERANGE, 0},
	{"11111111111111111111111111111111111111111111111111G",
		0, RDD_ERANGE, 0},
	{"0",
		RDD_POSITIVE, RDD_ERANGE, 0},
	{"-10",
		RDD_POSITIVE, RDD_ESYNTAX, 0},
	{"129",
		RDD_POWER2, RDD_ERANGE, 0},
	{"0K",
		0, RDD_OK, 0},
	{"1024K",
		0, RDD_OK, 1048576},
	{"0",
		0, RDD_OK, 0},
	{"1",
		0, RDD_OK, 1},
	{"1",
		RDD_POWER2, RDD_OK, 1},
	{"1",
		RDD_POSITIVE|RDD_POWER2, RDD_OK, 1},
	{"9c",
		0, RDD_OK, 9},
	{"18w",
		0, RDD_OK, 36},
	{"18b",
		0, RDD_OK, 18*512},
	{"8k",
		0, RDD_OK, 8192},
	{"1m",
		0, RDD_OK, 1048576},
	{"0M",
		0, RDD_OK, 0},
	{"120G",
		0, RDD_OK, 120ULL * (1 << 30)},
	{"128g",
		RDD_POWER2, RDD_OK, 128ULL * (1<<30)},
	{0, 
		0, RDD_OK, 0}
};

static void
run_testcase(RDD_TEST_BIGNUM *testcase)
{
	rdd_count_t num = 0;
	int rc;

	printf("running test: %s\n", testcase->testnum);

	rc = rdd_parse_bignum(testcase->testnum, testcase->flags, &num);

	if (rc != testcase->errcode) {
		printf("tnumparser: test failed [%s]: bad error code[%d]\n",
			testcase->testnum, rc);
		exit(EXIT_FAILURE);
	}

	if (rc == RDD_OK && num != testcase->result) {
		printf("tnumparser: test failed [%s]: bad result [%llu]\n",
			testcase->testnum, num);
		exit(EXIT_FAILURE);
	}
}

static void
test_bignums(void)
{
	RDD_TEST_BIGNUM *testcase;
	int i;

	for (i = 0; ; i++) {
		testcase = &bignums[i];
		if (testcase->testnum == 0) {
			break;
		}

		run_testcase(testcase);
	}
}

int
main(int argc, char **argv)
{
	test_bignums();
	return 0;
}
