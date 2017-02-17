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


/* A unit test for the reader code of rdd
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <string.h>

#include "rdd.h"
#include "error.h"
#include "writer.h"
#include "reader.h"
#include "filter.h"
#include "filterset.h"
#include "rdd_internals.h"
#include "copier.h"

#include "rddtest.h"

static char *progname;
static char *input_file;
static char *output_file;
static char *sim_file;

static void
usage(void)
{
	fprintf(stderr, "Usage: %s <input file> <output file> <sim file>\n",
		progname);
	exit(EXIT_FAILURE);
}

static void
command_line(int argc, char **argv)
{
	unsigned i = 1;

	if (argc - i == 0) {
		/* Just one argument. Set some default values.
		 */
		input_file = argv[0];	/* copy this program's binary */
		output_file = "output.img";
		sim_file = "simfile.txt";
	} else if (argc - i != 3) {
		input_file = argv[i++];
		output_file = argv[i++];
		sim_file = argv[i++];
	} else {
		usage();
	}
}

static void
handle_subst(rdd_count_t offset, unsigned nbyte, void *env){

	fprintf(stderr, "input dropped: offset = %llu bytes, "
		"count = %u bytes\n", offset, nbyte);		

	
}

static void
handle_read_error(rdd_count_t offset, unsigned nbyte, void *env){

	fprintf(stderr, "read error: offset = %llu bytes, "
		"count = %u bytes\n", offset, nbyte);		

}

/* build readers to simulate faults.
 */
static RDD_READER *
build_reader(void)
{
	RDD_READER *reader= 0;
	RDD_READER *faulty_reader= 0;
	int rc;
	rdd_count_t size;

	rc = rdd_open_file_reader(&reader, input_file, 0);
	if (rc != RDD_OK) {
		rdd_error(rc, "cannot open file reader");
	}
	
	if ((rc = rdd_reader_seek(reader, 0)) != RDD_OK){
		rdd_error(rc, "cannot seek to offset 0");
	}
	
	size = RDD_WHOLE_FILE;
	if ((rc = rdd_device_size(input_file, &size)) != RDD_OK){
		rdd_error(rc, "cannot determine file size of %s", input_file);
	}

	printf("file size is %llu\n", size);

	/* Stack the faulty reader onto the file reader
	 */
	if ((rc = rdd_open_faulty_reader(&faulty_reader, 
		reader, sim_file)) != RDD_OK)
	{
		rdd_error(rc, "cannot initialize faulty reader");
	}
	
	return faulty_reader;
}

/* Build a filter set and put a writer in it.
 */
static void
build_fset(RDD_FILTERSET *fset)
{
	RDD_FILTER *f = 0;
	RDD_WRITER *writer = 0;
	int rc;

	if ((rc = rdd_fset_init(fset)) != RDD_OK){
		rdd_error(rc, "cannot initialize filter set");
	}

	if ((rc = rdd_open_safe_writer(&writer, output_file, RDD_OVERWRITE)) 
		!= RDD_OK){
		rdd_error(rc, "cannot open output file %s", output_file);
	}
	
	if ((rc = rdd_new_write_streamfilter(&f, writer)) != RDD_OK){
		rdd_error(rc, "cannot build write-stream filter");
	}
	
	if ((rc = rdd_fset_add(fset, "writer", f)) != RDD_OK){
		rdd_error(rc, "cannot add write filter to filter set");
	}	
}

/* Build the robust copier.
 */
static void
copy(RDD_READER *reader, RDD_FILTERSET *fset)
{
	RDD_COPIER *copier = 0;
	RDD_ROBUST_PARAMS p;
	RDD_COPIER_RETURN ret;
	int rc;

	memset(&p, 0, sizeof(p));

	p.minblocklen = 512;
	p.maxblocklen = 1048576;
	p.nretry = 4;
	p.maxsubst = 10000;
	p.readerrfun = handle_read_error;
	p.substfun = handle_subst;
		
	if ((rc = rdd_new_robust_copier(&copier, 0, RDD_WHOLE_FILE, &p) 
		!= RDD_OK)){
		rdd_error(rc, "cannot create robust copier");
	}
	
	if ((rc = rdd_copy_exec(copier, reader, fset, &ret)) != RDD_OK){
		rdd_error(rc, "copy error");
	}	

	if ((rc = rdd_copy_free(copier)) != RDD_OK) {
		rdd_error(rc, "cannot free copier");
	}
}

/* Calls some functions with bad arguments.
 */
static int
call_tests(void)
{
	RDD_READER *reader;
	RDD_READER *faulty_reader= 0;
	int rc;
	int errors = 0;


	printf("Trying to open a file. The path is an empty string.\n");
	if ((rc = rdd_open_file_reader(&reader, "", 0)) == RDD_OK){
		fprintf(stderr, "COULD OPEN THE FILE. TEST FAILED.\n");
		errors++;
	}
		
	printf("Trying to open a non-existing file.\n");
	if ((rc = rdd_open_file_reader(&reader, "fajhdgahd", 0)) == RDD_OK){
		fprintf(stderr, "COULD OPEN THE FILE. TEST FAILED.\n");
		errors++;
	}
		
	if ((rc = rdd_open_file_reader(&reader, input_file, 0)) != RDD_OK){
		printf("Could not open input file when it should be no "
			"problem.\nTEST FAILED");
		exit(EXIT_FAILURE);
	}

	if ((rc = rdd_reader_seek(reader, 0)) != RDD_OK){
		printf("could not seek to location 0.\nTEST FAILED.\n");
		errors++;
	}

	printf("Trying to seek illegal locations in the reader.\n");
	if ((rc = rdd_reader_seek(reader, -1)) == RDD_OK){
		printf("COULD SEEK TO LOCATION -1. TEST FAILED.\n");
		errors++;
	}
	if ((rc = rdd_reader_seek(reader, 22223343)) == RDD_OK){
		printf("COULD SEEK TO LOCATION TOO FAR AWAY. TEST FAILED.\n");
		errors++;
	}
	
	printf("Trying to open a faulty reader. The path to the simfile "
		"is an empty string.\n");
	if ((rc = rdd_open_faulty_reader(&faulty_reader, reader, ""))
		== RDD_OK){
		printf("COULD OPEN SIMFILE. TEST FAILED.\n");
		errors++;
	}

	printf("Trying to open a faulty reader. The simfile "
		"is a non-existing file.\n");
	if ((rc = rdd_open_faulty_reader(&faulty_reader, reader, "fasdgfadgj"))
		== RDD_OK){
		printf("COULD OPEN SIMFILE. TEST FAILEd.\n");
		errors++;
	}

	if ((rc = rdd_open_faulty_reader(&faulty_reader, reader, sim_file))
		!= RDD_OK){
		rdd_error(rc, "cannot open simulation file when it "
				"should not be a problem\nTEST FAILED");
	}

	return errors;		
	

}

static int
call_robust_copier(void)
{
	/* Some parameters for the robust copier. None of these
	 * sets of parameters should be accepted.
	 */
	struct TESTCASE {
		rdd_count_t offset;
		rdd_count_t count;
		unsigned    minblocklen;
		unsigned    maxblocklen;
		unsigned    retries;
		unsigned    maxsubst;
	} testcases[] = {
#if 0
		{-10, 1024,  512, 512,        4,  10}, /* legal */
		{  0,  -10,  512, 512,        4,  10}, /* legal */
#endif
		{  0, 1024,  -10, 512,        4,  10}, /* illegal */
#if 0
		{  0, 1024,  512, -10,      -10,  10}, /* legal */
		{  0, 1024,  512, 512,        4,  10}, /* legal */
		{  0, 1024,  512, 512,        4, -10}, /* legal */
#endif
		{  0, 1024, 1024, 512,        4,  10}, /* illegal */
#if 0
		{  0, 1024, 1048576, 1048576, 4,  10}, /* legal */
		{1048579,   1024, 512, 512,   4,  10}, /* legal */
		{  0,1048579, 512, 512,       4,  10}, /* legal */
		{  0, 1024,  512, 512,        4,  10}, /* legal */
#endif
	};

	RDD_COPIER *copier = 0;
	struct TESTCASE *tc;
	RDD_ROBUST_PARAMS p;
	int rc;
	int errors = 0;
	unsigned i;

	printf("Trying to make a robust copier with invalid parameters.\n");
	for (i = 0; i < sizeof(testcases)/sizeof(testcases[0]); i++){
		tc = &testcases[i];

		memset(&p, 0, sizeof p);
		p.minblocklen = tc->minblocklen;
		p.maxblocklen = tc->maxblocklen;
		p.nretry = tc->retries;
		p.maxsubst = tc->maxsubst;

		rc = rdd_new_robust_copier(&copier, tc->offset, tc->count, &p);
		if (rc == RDD_OK) {
			fprintf(stderr, "Could build a copier in run %u.\n"
				"TEST FAILED.\n", i);
			errors++;
		} else {
			fprintf(stderr, "OK: cannot build illegal copier\n");
		}
	}

	return errors;
}

static void
close_reader(RDD_READER *reader)
{
	int rc;

	if ((rc = rdd_reader_close(reader, 1 /* recurse */)) != RDD_OK) {
		rdd_error(rc, "cannot close reader");
	}
}

int
main(int argc, char **argv)
{
	
	RDD_READER *reader;
	RDD_FILTERSET fset;

	progname = argv[0];
	set_progname(progname);
	command_line(argc, argv);

	printf("input file = %s\n", input_file);
	printf("output file = %s\n", output_file);
	printf("sim file = %s\n", sim_file);
	
	reader = build_reader();

	build_fset(&fset);

	copy(reader, &fset);

	close_reader(reader);
	
#if 0
	if (call_tests() > 0){
		exit(EXIT_FAILURE);
	}
#endif
	if (call_robust_copier() > 0){
		exit(EXIT_FAILURE);
	}
	
	return 0;
}
