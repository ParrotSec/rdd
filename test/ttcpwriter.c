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


/* A unit test for the TCP writer module. This module is used when rdd is put 
 * in client mode. The module reads a file and writes it to a TCP port.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>

#include "rdd.h"
#include "writer.h"
#include "filter.h"
#include "filterset.h"
#include "rdd_internals.h"
#include "reader.h"
#include "netio.h"

#define INPUT_FILE  "image.img"
#define OUTPUT_FILE "image-net.img"
#define SERVER "localhost"
#define PORT 1111

static void
build_filterset(RDD_FILTERSET *fset)
{
	int rc;
	unsigned flags = 0;
	rdd_count_t size;
	RDD_WRITER *w = 0;
	RDD_FILTER *f = 0;

	rc = rdd_open_tcp_writer(&w, SERVER, 1111);
	if (rc != RDD_OK){
		fprintf(stderr, "could not connect to %s:%u.\n"
			"Returnvalue: %i\n", SERVER, PORT, rc);
		exit(-1);
	}

	rc = rdd_device_size(INPUT_FILE, &size);
	if (size == 0){
		fprintf(stderr, "Size of input file is 0. Abort\n");
		exit(-1);
	}

	rc = rdd_send_info(w, OUTPUT_FILE, size,
			262144, 12345678901, flags);
	if (rc != RDD_OK) {
		fprintf(stderr, "cannot send header to %s:%u", SERVER, PORT);
		exit(-1);
	}

	if ((rc = rdd_fset_init(fset)) != RDD_OK){
		fprintf(stderr, "could not create a filter set. Returnvalue: "
			"%i\n", rc);
		exit(-1);
	}

	if ((rc = rdd_new_write_streamfilter(&f, w)) != RDD_OK){
		fprintf(stderr, "cannot build write-stream filter");
		exit(-1);
	}
	
	if ((rc = rdd_fset_add(fset, "tcp-writer", f)) != RDD_OK){
		fprintf(stderr, "could not add the tcp writer to the "
			"filterset. Returnvalue: %i\n", rc);
		exit(-1);
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
		exit(-1);
	}

	infile = fopen(INPUT_FILE, "rb");
	if (infile == NULL){
		fprintf(stderr, "could not open input file.\n");
		exit(-1);
	}

	while ((nread = fread(buf, 1, chunklen, infile)) > 0) {
		rdd_fset_push(fset, buf, nread);
	}

	if (feof(infile) == 0){
		fprintf(stderr, "An error occurred reading the input file."
			"Errornumber: %i.\n", ferror(infile));
		exit(-1);
	}

	if ((rc = rdd_fset_close(fset)) != RDD_OK){
		fprintf(stderr, "Could not close the filterset. "
			"Returnvalue: %i.\n", rc);
		exit(-1);
	}

	if (fclose(infile) == EOF) {
		fprintf(stderr, "Cannot close input file.\n");
		exit(-1);
	}

	free(buf);
}




int 
main (int argc, char **argv)
{

	RDD_FILTERSET fset;

	build_filterset(&fset);	
	fill_filters(&fset, 1048576);

	return 0;

}


