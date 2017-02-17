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


/* A unit-test for the message printer.
 */

#ifdef HAVE_CONFIG_H
#include"config.h"
#endif

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "rdd.h"
#include "rdd_internals.h"
#include "error.h"
#include "msgprinter.h"

/*
 * Command-line arguments:
 * 1: logfile to print the messages in
 * 2: formatted string to print
 * 3: a list of errorcodes. Unix errors start with a 'U', rdd errors start 
 *      with an 'A'
 * 
 * Error messages go to stderr.
 */

static RDD_MSGPRINTER *the_printer;

static void
printer_error(char *fmt, ...)
{
	va_list ap;

	fprintf(stderr, "[tmsgprinter] ");
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");

	exit(EXIT_FAILURE);
}

static void
open_printers(char *logfile)
{
	RDD_MSGPRINTER *file_log_printer = 0;
	RDD_MSGPRINTER *stdio_log_printer = 0;
	RDD_MSGPRINTER *bcast_printer = 0;
	RDD_MSGPRINTER *printers[2];
	unsigned nprinter = 0;
	int rc = RDD_OK;
	
	/* Build a stdio printer to stderr and stack a log printer
	 * as its child.
	*/

	rc = rdd_mp_open_stdio_printer(&stdio_log_printer, stderr);
	if (rc != RDD_OK) {
		printer_error("cannot open stdio printer to stderr");
	}

	rc = rdd_mp_open_log_printer(&stdio_log_printer, stdio_log_printer);
	if (rc != RDD_OK) {
		printer_error("cannot stack log printer on stdio printer");
	}

	printers[nprinter++] = stdio_log_printer;
	

	/* Build a file printer and stack a log printer as its child.
	*/

	rc = rdd_mp_open_file_printer(&file_log_printer, logfile);
	if (rc != RDD_OK) {
		printer_error("cannot open log file (%s)",
				logfile);
	}

	rc = rdd_mp_open_log_printer(&file_log_printer, file_log_printer);
	if (rc != RDD_OK) {
		printer_error("cannot stack log printer");
	}

	printers[nprinter++] = file_log_printer;

	/* Create a broadcast printer and make it the current printer.
	 */
	rc = rdd_mp_open_bcast_printer(&bcast_printer, nprinter, printers);
	if (rc != RDD_OK) {
		printer_error("cannot open bcast printer");
	}
	the_printer = bcast_printer;
}

static void
close_printer(void)
{
	int rc;

	if (the_printer == 0) return;

	rc = rdd_mp_close(the_printer, RDD_MP_RECURSE|RDD_MP_READONLY);
	if (rc != RDD_OK) {
		/* Cannot trust the_printer any more...
		 */
		fprintf(stderr, "cannot close message printer\n");
		exit(EXIT_FAILURE);
	}

	the_printer = 0;
}

static void
report_rdd_error(int rdd_errno, char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	rdd_mp_vrddmsg(the_printer, RDD_MSG_ERROR, rdd_errno, fmt, ap);
	va_end(ap);
}

static void
report_unix_error(int rdd_errno, char *fmt, ...)
{
	rdd_mp_unixmsg(the_printer, RDD_MSG_ERROR, rdd_errno, fmt);
}

static void
report_error(char *errno, char *fmt, ...)
{
	int n;

	n = atoi(errno + 1);

	if (errno[0] == 'U' || errno[0] == 'u') {
		report_unix_error(n, fmt);
	} else if (errno[0] == 'R' || errno[0] == 'r') {
		report_rdd_error(n, fmt);
	} else {
		fprintf(stderr, "Unknown errorcode: %s\n" , errno);
	}
}

int
main(int argc, char **argv)
{
	int i;

	if (argc < 4){
		fprintf(stderr, "missing argument(s)\n");
		fprintf(stderr, "usage: tmsgprinter logfile error-message "
			"error-code [error-code2, ......]\n");
		exit(EXIT_FAILURE);
	}
	
	open_printers(argv[1]);

	for (i = 3; i < argc; i++) {
		report_error(argv[i], argv[2]);
	}

	close_printer();
	
	return 0;
}
