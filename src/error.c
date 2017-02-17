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

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "rdd.h"
#include "rdd_internals.h"
#include "rdd.h"
#include "error.h"

#define NO_CONSOLE 0
#define CONSOLE    1

static char *progname = "<unknown program>";
static char *email_addr = PACKAGE_BUGREPORT;

static char *bug_message_fmt =
"Rdd has crashed.  Please do the following:\n"
"  1. Write down the time of day reported by your computer.\n"
"  2. If rdd dumped core, save a copy of the core file.\n"
"  3. Save a copy of /var/log/messages.\n"
"  4. Save a copy of your rdd binary.\n"
"  4. Report this problem to %s.\n";

static FILE *logfp = NULL;
static int new_line = 1;

#if defined(RDD_CONSOLE)
#define LOGFP (logfp)
#else
#define LOGFP ((logfp) == NULL ? stderr : (logfp))
#endif

/** \brief Sends a formatted message to a log file and optionally
 *   to the console.
 */
static void
log_vprintf(int console, char *fmt, va_list ap)
{
	if (console) {
#if defined(RDD_CONSOLE)
		rdd_cons_vprintf(fmt, ap);
#else
		/* No true console access. Use stderr instead.
		 */
		vfprintf(stderr, fmt, ap);
#endif
	}

	if (logfp != NULL) {
		/* There is a log file. Write the message to the
		 * log file.
		 */
		vfprintf(logfp, fmt, ap);
	} else if (! console) {
		/* There is no log file and this message was not
		 * explicitly sent to the console. Since we do not
		 * want messages to get lost we will send it to the
		 * console anyway.
		 */
#if defined(RDD_CONSOLE)
		rdd_cons_vprintf(fmt, ap);
#else
		/* No true console access. Use stderr instead.
		 */
		vfprintf(stderr, fmt, ap);
#endif
	}
}

static void
log_printf(int console, char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	log_vprintf(console, fmt, ap);
	va_end(ap);
}

static void
log_flush(void)
{
	if (logfp != NULL) fflush(logfp);
}

void
set_progname(char *name)
{
	progname = name;
}

void
set_logfile(FILE *fp)
{
	if (logfp != NULL) {
		fflush(logfp);
	}
	logfp = fp;
}

void
bug(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	log_printf(CONSOLE, "%s: bug: ", progname);
	log_vprintf(CONSOLE, fmt, ap);
	log_printf(CONSOLE, "\n\n");
	log_printf(CONSOLE, bug_message_fmt, email_addr);
	log_flush();
	va_end(ap);
	abort();
}

void
error(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	log_printf(CONSOLE, "%s: ", progname);
	log_vprintf(CONSOLE, fmt, ap);
	log_printf(CONSOLE, "\n");
	log_flush();
	va_end(ap);
	exit(EXIT_FAILURE);
}

void
warn(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	log_printf(CONSOLE, "(warning) %s: ", progname);
	log_vprintf(CONSOLE, fmt, ap);
	log_printf(CONSOLE, "\n");
	log_flush();
	va_end(ap);
}

void
unix_warn(char *fmt, ...)
{
	va_list ap;
	int err = errno;

	va_start(ap, fmt);
	log_printf(CONSOLE, "%s: ", progname);
	log_vprintf(CONSOLE, fmt, ap);
	log_printf(CONSOLE, ": %s\n", strerror(err));
	log_flush();
	va_end(ap);
}

void
unix_error(char *fmt, ...)
{
	va_list ap;
	int err = errno;

	va_start(ap, fmt);
	log_printf(CONSOLE, "%s: ", progname);
	log_vprintf(CONSOLE, fmt, ap);
	log_printf(CONSOLE, ": %s\n", strerror(err));
	log_flush();
	va_end(ap);
	exit(EXIT_FAILURE);
}

void
errlog(char *fmt, ...)
{
	va_list ap;

	if (new_line) log_printf(CONSOLE, "%s: ", rdd_ctime());

	va_start(ap, fmt);
	log_vprintf(CONSOLE, fmt, ap);
	va_end(ap);

	new_line = 0;
}

void
errlognl(char *fmt, ...)
{
	va_list ap;

	if (new_line) log_printf(CONSOLE, "%s: ", rdd_ctime());

	va_start(ap, fmt);
	log_vprintf(CONSOLE, fmt, ap);
	log_printf(CONSOLE, "\n");
	log_flush();
	va_end(ap);

	new_line = 1;
}

void
rdd_error(int errcode, char *fmt, ...)
{
	char msg[1024];
	va_list ap;
	int rc;

	va_start(ap, fmt);
	log_printf(CONSOLE, "%s: ", progname);
	log_vprintf(CONSOLE, fmt, ap);
	va_end(ap);

	log_printf(CONSOLE, ": ");
	rc = rdd_strerror(errcode, msg, sizeof msg);
	if (rc == RDD_NOMEM) {
		log_printf(CONSOLE, "<error message too long>");
	} else if (rc == RDD_OK) {
		log_printf(CONSOLE, msg);
	} else {
		log_printf(CONSOLE, "internal error: "
				"unknown error code [%d]\n", errcode);
		abort();
	}

	log_printf(CONSOLE, "\n");

	log_flush();
	exit(EXIT_FAILURE);
}
