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


/* 
 * This is a unit test for the block MD5 handling of rdd.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>

#include "rdd.h"
#include "rdd_internals.h"
#include "writer.h"
#include "filter.h"
#include "filterset.h"

#define INPUT_FILE  "image.img"

static void
build_filters(RDD_FILTERSET *fset, rdd_count_t blocklen, char *outfile)
{
	RDD_FILTER *f = 0;
	int rc;

	rc = rdd_new_md5_blockfilter(&f, blocklen, outfile, RDD_OVERWRITE);
	if (rc != RDD_OK) {
		fprintf(stderr, "could not create new MD5 block filter. "
			"Returnvalue: %i\n", rc);
		exit(EXIT_FAILURE);
	}

	if ((rc = rdd_fset_init(fset)) != RDD_OK) {
		fprintf(stderr, "could not create a filter set. Returnvalue: "
			"%i\n", rc);
		exit(EXIT_FAILURE);
	}

	if ((rc = rdd_fset_add(fset, "MD5-blockfilter", f)) != RDD_OK) {
		fprintf(stderr, "could not add the MD5 blockfilter to the "
			"filterset. Returnvalue: %i\n", rc);
		exit(EXIT_FAILURE);
	}
}

static void
fill_filters(RDD_FILTERSET *fset, rdd_count_t chunklen)
{
	FILE *infile;
	unsigned char *buf;
	size_t nread;
	int rc;

	if ((buf = malloc(chunklen)) == 0) {
		fprintf(stderr, "out of memory\n");
		exit(EXIT_FAILURE);
	}

	if ((infile = fopen(INPUT_FILE, "rb")) == NULL) {
		fprintf(stderr, "cannot open input file.\n");
		exit(EXIT_FAILURE);
	}

	while ((nread = fread(buf, 1, chunklen, infile)) > 0) {
		rdd_fset_push(fset, buf, nread);
	}

	if (feof(infile) == 0) {
		fprintf(stderr, "An error occurred reading the input file."
			"Errornumber: %i.\n", ferror(infile));
		exit(EXIT_FAILURE);
	}

	if ((rc = rdd_fset_close(fset)) != RDD_OK) {
		fprintf(stderr, "Could not close the filterset. "
			"Returnvalue: %i.\n", rc);
		exit(EXIT_FAILURE);
	}

	if (fclose(infile) == EOF) {
		fprintf(stderr, "Cannot close input file.\n");
		exit(EXIT_FAILURE);
	}

	free(buf);
}

static void
clear_filters(RDD_FILTERSET *fset)
{
	int rc;

	if ((rc = rdd_fset_clear(fset)) != RDD_OK) {
		fprintf(stderr, "Cannot clear filter set [%d]\n", rc);
		exit(EXIT_FAILURE);
	}
}

int
main(void)
{
	RDD_FILTERSET fset;
	char outfile[100];
	rdd_count_t blocklen[] = {1024, 1048576, 13373, 3382912};
	rdd_count_t chunklen[] = {1024, 1048576, 13373, 3382912};
	int i, j;

	/* Read the complete testfile in one chunk and push it 
	 * in one chunk into the filter. The filter's block size equals 
	 * the file size.
	 */
	build_filters(&fset, 1572864, "block-md5-bs1572864-chunk1572864.txt");
	fill_filters(&fset, 1572864);
	clear_filters(&fset);

	/* Read the testfile in various chunk sizes and use various
	 * block sizes.
	 */
	for (i = 0; i < 4; i++) {
		for (j = 0; j < 4; j++) {	
			sprintf(outfile, "block-md5-bs%llu-chunk%llu.txt", 
				blocklen[i], chunklen[j]);
	
			build_filters(&fset, blocklen[i], outfile);
			fill_filters(&fset, chunklen[j]);
			clear_filters(&fset);
		}
	}

	return 0;
}
