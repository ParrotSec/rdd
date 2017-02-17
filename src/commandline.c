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
"@(#) Copyright (c) 2002\n\
	Netherlands Forensic Institute.  All rights reserved.\n";
#endif /* not lint */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "rdd.h"
#include "rdd_internals.h"
#include "error.h"
#include "commandline.h"

static RDD_OPTION *opttab;
static const char *usage_message;

void
rdd_opt_init(RDD_OPTION *tab, const char *usage_msg)
{
	opttab = tab;
	usage_message = usage_msg;
}

/* Verify whether argv[*i] is an option name (short or long) and
 * whether its argument, if any, is present.
 */
RDD_OPTION *
rdd_get_opt_with_arg(char **argv, int argc, unsigned *i, char **opt, char **arg)
{
	RDD_OPTION *od;
	char *optname;

	optname = argv[*i];
	for (od = &opttab[0]; od->short_name != 0; od++) {
		if (! streq(od->short_name, optname)
		&&  (od->long_name == 0 || !streq(od->long_name, optname))) {
			continue;
		}

		if (++od->count > 1) {
			error("option %s specified multiple times", optname);
		}

		*opt = optname;
		if (od->arg_descr == 0) {	/* no argument */
			*arg = 0;
		} else {
			(*i)++;
			if ((*i) >= (unsigned) argc) {
				error("option %s requires an argument", optname);
			}
			od->arg_value = *arg = argv[*i];
		}

		return od;
	}
	return 0;
}

int
rdd_opt_set_arg(char *longname, char **argp)
{
	RDD_OPTION *od;

	for (od = &opttab[0]; od->short_name != 0; od++) {
		if (streq(od->long_name+2, longname)) {
		       	if (od->count == 0) {
				return 0;	/* option not set */
			}
			if (argp != 0) {
				*argp = od->arg_value;
			}
			return 1;
		}
	}
	bug("opt_set_arg: %s is not a known option", longname);
	return 0; /* NOTREACHED */
}

int
rdd_opt_set(char *longname)
{
	return rdd_opt_set_arg(longname, 0);
}

void
rdd_opt_usage(void)
{
	RDD_OPTION *od;
	char optnames[80];

	fprintf(stderr, "Usage: %s", usage_message);
	fprintf(stderr, "Options:\n");
	for (od = &opttab[0]; od->short_name != 0; od++) {
		if (od->long_name != 0) {
			snprintf(optnames, sizeof optnames, "%s, %s %s", 
				od->short_name, od->long_name,
				od->arg_descr == 0 ? "" : od->arg_descr);
		} else {
			snprintf(optnames, sizeof optnames, "%s %s", od->short_name,
				od->arg_descr == 0 ? "" : od->arg_descr);
		}
		optnames[(sizeof optnames)-1] = '\000';

		if (strlen(optnames) <= 32) {
			fprintf(stderr, "%-32.32s %s\n",
					optnames, od->description);
		} else {
			fprintf(stderr, "%s\n", optnames);
			fprintf(stderr, "%-32.32s %s\n", "", od->description);
		}
	}
	exit(EXIT_FAILURE);
}
