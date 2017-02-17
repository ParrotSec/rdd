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



#if defined(HAVE_CONFIG_H)
#include <config.h>
#endif

#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>

#include "rdd.h"
#include "rdd_internals.h"
#include "error.h"

#define MAX_WRITEBUF    256
#define MAX_LINE         80

static int console_fd = -1;
static int quiet = 0;

void
rdd_set_quiet(int q)
{
	quiet = q;
}


static void
cons_write(char *buf, unsigned buf_size)
{
#if defined(RDD_CONSOLE)
	int n;

	if (console_fd < 0) return;

	while (buf_size > 0) {
		if ((n = write(console_fd, buf, buf_size)) < 0) {
			(void) close(console_fd);
			console_fd = -1;  /* prevents recursion */
			unix_error("cannot write to tty");
		}
		buf += n;
		buf_size -= n;
	}
#endif
}

void
rdd_cons_open(void)
{
#if defined(RDD_CONSOLE)
	if ((console_fd = open("/dev/tty", O_RDWR)) < 0) {
		unix_error("cannot open terminal");
	}
#endif
}

void
rdd_cons_close(void)
{
#if defined(RDD_CONSOLE)
	if (console_fd < 0) return;

	(void) close(console_fd);
	console_fd = -1;
#endif
}

/* Interactive routine that poses a question and that takes
 * only 'yes' or 'no' for an answer.
 */
static int
rdd_vask(char *fmt, va_list ap)
{
	char line[MAX_LINE];
	int answer = RDD_NO;
	ssize_t n;

	while (1) {
		rdd_cons_vprintf(fmt, ap);
		rdd_cons_printf("  ");

		n = read(console_fd, line, sizeof line);
		if (n < 0) {
			unix_error("cannot read from terminal");
		} else if (n == 0) {
			error("terminal closed?");
		}

		if (line[n-1] != '\n') {
			error("line too long");
		}
		line[n-1] = '\000';  /* strip newline character */

		if (strcmp(line, "yes") == 0 || strcmp(line, "YES") == 0) {
			answer = RDD_YES;
			break;
		}
		if (strcmp(line, "no") == 0 || strcmp(line, "NO") == 0) {
			answer = RDD_NO;
			break;
		}
		rdd_cons_printf("Please answer yes or no.\n");
	}

	return answer;
}

int
rdd_ask(char *fmt, ...)
{
	va_list ap;
	int rc;

	va_start(ap, fmt);
	rc = rdd_vask(fmt, ap);
	va_end(ap);
	return rc;
}

void
rdd_quit_if(int quit_answer, char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (!quiet && rdd_vask(fmt, ap) == quit_answer) {
		exit(EXIT_FAILURE);
	}
	va_end(ap);
}

/** Writes a formatted message to the console if the console is open.
 *  Be careful: do not (recursively) invoke any error routines here.
 */
void
rdd_cons_vprintf(char *fmt, va_list ap)
{
#if defined(RDD_CONSOLE)
	char promptbuf[MAX_WRITEBUF+1];
	
	if (console_fd < 0) {
		return;
	}

	vsnprintf(promptbuf, MAX_WRITEBUF, fmt, ap);
	promptbuf[MAX_WRITEBUF] = '\000';   /* truncate if too long */
	cons_write(promptbuf, strlen(promptbuf));
#endif
}

void
rdd_cons_printf(char *fmt, ...)
{
#if defined(RDD_CONSOLE)
	va_list ap;

	va_start(ap, fmt);
	rdd_cons_vprintf(fmt, ap);
	va_end(ap);
#endif
}
