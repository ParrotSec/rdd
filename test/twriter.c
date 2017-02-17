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
#include "rdd_internals.h"
#include "writer.h"

#include "rddtest.h"

#define ERR_BUFSIZE   256
#define MAX_BUFSIZE 65536

static char *progname;
static char *input_file;

static unsigned char buf[MAX_BUFSIZE];

static unsigned blocksize = MAX_BUFSIZE;

static void
command_line(int *argcp, char ***argvp)
{
	int argc = *argcp;
	char **argv = *argvp;
	unsigned i = 1;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s file ...\n", progname);
		exit(EXIT_FAILURE);
	}

	input_file = argv[i++];

	argc -= i;
	*argcp = argc;
	argv += i;
	*argvp = argv;
}

static void
copy_file(char *path, int argc, char **argv)
{
	char errmsg[ERR_BUFSIZE];
	size_t n;
	FILE *fp;
	RDD_WRITER *writer;
	int rc;

       	writer = rdd_test_get_writer(argc, argv);
	if (writer == 0) {
		fprintf(stderr, "%s: cannot build writer stack\n", progname);
		exit(EXIT_FAILURE);
	}

	if ((fp = fopen(path, "rb")) == NULL) {
		fprintf(stderr, "%s: cannot open %s\n", progname, path);
		exit(EXIT_FAILURE);
	}

	while (1) {
		n = fread(buf, sizeof(char), blocksize, fp);
		if (n == 0) {
			break;
		}

		if ((rc = rdd_writer_write(writer, buf, n)) != RDD_OK) {
			(void) rdd_strerror(rc, errmsg, sizeof errmsg);
			fprintf(stderr, "write error: %s\n", errmsg);
			exit(EXIT_FAILURE);
		}
	}

	(void) fclose(fp);

	if ((rc = rdd_writer_close(writer)) != RDD_OK) {
		fprintf(stderr, "%s: cannot close writer\n", progname);
		exit(EXIT_FAILURE);
	}
}

int
main(int argc, char **argv)
{
	progname = argv[0];
	command_line(&argc, &argv);

	copy_file(input_file, argc, argv);

	return 0;
}
