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
"@(#) Copyright (c) 2002-2004\n\
	Netherlands Forensic Institute.  All rights reserved.\n";
#endif /* not lint */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <ctype.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "rdd.h"
#include "rdd_internals.h"
#include "numparser.h"

#define flags_set(flags, bit)  (((flags) & (bit)) == (bit))

static struct _RDD_MULTIPLIER {
	char mchar;
	unsigned factor;
} multtab[] = {
	{'c', 1<<0},	/* single byte/character */
	{'w', 1<<1},	/* two-byte word */
	{'b', 1<<9},	/* sector/block */
	{'k', 1<<10},	/* kilobyte (2^10 bytes) */
	{'m', 1<<20},	/* megabyte (2^20 bytes) */
	{'g', 1<<30},	/* gigabyte (2^30 bytes) */
	{'\000', 0}	/* sentinel */
};


/* Parse size specifications of the form 32k, 4M, etc.  Don't
 * use atoi(), because we have to be able to process numbers
 * that won't fit in a 32-bit integer.
 */
int
rdd_parse_bignum(const char *str, rdd_num_flags_t flags, rdd_count_t *result)
{
	rdd_count_t sz;
	rdd_count_t multiplier;
	unsigned d, i, j;
	unsigned n;

	*result = 0;
	n = (unsigned) strlen(str);
	sz = 0;
	for (i = 0; i < n && isdigit(str[i]); i++) {
		d = str[i] - '0';

		if (sz > (RDD_COUNT_MAX - d) / 10) {
			return RDD_ERANGE;	/* overflow */
		}
		sz = 10 * sz + d;
	}
	if ((i == 0) || (i < n - 1)) {
		return RDD_ESYNTAX;	/* no digits or too many nondigits */
	}

	/* i==n-1 or i==n */

	if (i == n - 1) {
		/* Search for multiplier.
		 */
		multiplier = 0;
		for (j = 0; multtab[j].mchar != '\0'; j++) {
			if (tolower(str[i]) == multtab[j].mchar) {
				multiplier = multtab[j].factor;
				break;
			}
		}
		if (multiplier == 0) {
			return RDD_ESYNTAX;	/* bad multiplier */
		}
		if (sz > (RDD_COUNT_MAX / multiplier)) {
			return RDD_ERANGE;	/* overflow */
		}
		sz *= multiplier;
	}

	if (flags_set(flags, RDD_POSITIVE) && sz <= 0) return RDD_ERANGE;

	if (flags_set(flags, RDD_POWER2)) { /* sz should be a power of 2.  */
		rdd_count_t x;

		for (x = sz; x != 0 && (x & 1) == 0; x /= 2) {
		}
		if (x != 1) return RDD_ERANGE;
	}

	*result = sz;
	return RDD_OK;
}

/* Parse a nonnegative number.  Standard library call atoi(3) cannot
 * handle 64-bit numbers.
 */
int
rdd_parse_uint(const char *str, unsigned *result)
{
	unsigned n;
	const char *p;

	*result = 0;
	n = 0;
	for (p = str; *p != '\0'; p++) {
		n *= 10;
		if (! isdigit(*p)) return RDD_ESYNTAX;
		n += *p - '0';
	}

	*result = n;
	return RDD_OK;
}

int
rdd_parse_tcp_port(const char *str, unsigned *result)
{
	unsigned n;
	int rc;

	if ((rc = rdd_parse_uint(str, &n)) != RDD_OK) {
		return rc;
	}

	if (n > 65535) return RDD_ERANGE;

	*result = n;
	return RDD_OK;
}
