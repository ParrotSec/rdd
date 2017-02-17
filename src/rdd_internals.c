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

#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>

#include "rdd.h"
#include "rdd_internals.h"
#include "error.h"

#define MAX_SIZE_BUF_LEN 64
#define TIME_BUF_SIZE    64
#define TIME_FORMAT      "%Y-%m-%d %H:%M:%S %Z"

#define bitcount(t) (sizeof(t) * CHAR_BIT)

/* Performs size checks on critical integer types.
 */
static void
check_type_sizes(void)
{
	if (bitcount(off_t) < 64) {
		error("configuration problem: off_t not wide enough");
	}
	if (bitcount(rdd_count_t) < 64) {
		error("configuration problem: rdd_count_t not wide enough");
	}
	if (bitcount(RDD_UINT32) < 32) {
		error("configuration problem: RDD_UINT32 is not 32 bits wide");
	}
	if (bitcount(RDD_UINT64) < 64) {
		error("configuration problem: RDD_UINT64 is not 64 bits wide");
	}
	if (bitcount(unsigned char) != 8) {
		error("configuration problem: unsigned char is not 8 bits wide");
	}
	if (bitcount(rdd_checksum_t) != 32) {
		error("configuration problem: rdd_checksum_t is not 32 bits wide");
	}
}

void
rdd_init(void)
{
	check_type_sizes();
}

/** Allocates memory and clears it.
 */
void *
rdd_malloc(size_t nbyte)
{
	void *p;

	if ((p = malloc(nbyte)) == 0) {
		error("out of memory (%u bytes requested)", nbyte);
	}
	memset(p, 0, nbyte);  /* expensive but safer */
	return p;
}

void
rdd_free(void *p)
{
	free(p);
}

int
rdd_buf2hex(const unsigned char *buf, unsigned bufsize,
	    char *hexbuf, unsigned hexbuflen)
{
	static char *hexdigits = "0123456789abcdef";
	unsigned d, k, i;

	if (2*bufsize + 1 > hexbuflen) {
		return RDD_ESPACE;
	}

	for (i = k = 0; i < bufsize; i++) {
		d = (buf[i] >> 4) & 0xf;
		hexbuf[k++] = hexdigits[d];

		d = buf[i] & 0xf;
		hexbuf[k++] = hexdigits[d];
	}
	hexbuf[k] = '\000';

	return RDD_OK;
}

char *
rdd_ctime(void)
{
	static char timebuf[TIME_BUF_SIZE];
	time_t now;
	struct tm *now_local;

	now = time(NULL);
	if (now == (time_t) -1) {
		unix_error("cannot retrieve current time");
	}

	if ((now_local = localtime(&now)) == NULL) {
		error("cannot convert Unix ticks to local time");
	}

	if (strftime(timebuf, TIME_BUF_SIZE, TIME_FORMAT, now_local) == 0) {
		error("cannot convert local time to a string");
	}

	return timebuf;
}

double
rdd_gettime(void)
{
	struct timeval now;

	if (gettimeofday(&now, 0) < 0) {
		unix_error("cannot read time-of-day");
	}

	return ((double) now.tv_sec) + (1e-6 * now.tv_usec); 
}

char *
rdd_strsize(rdd_count_t size)
{
	static char sizestr[MAX_SIZE_BUF_LEN];

	if (size == RDD_WHOLE_FILE) {
		snprintf(sizestr, MAX_SIZE_BUF_LEN - 1, "unknown size");
	} else {
		snprintf(sizestr, MAX_SIZE_BUF_LEN - 1, "%llu", size);
	}
	sizestr[MAX_SIZE_BUF_LEN-1] = '\000';   /* always null-terminate */

	if (strlen(sizestr) >= MAX_SIZE_BUF_LEN - 1) {
		bug("rdd_strsize: size too large for string conversion?");
	}

	return sizestr;
}

static void
signal_exit(int signum)
{
	char buf[128];

	/* This is a signal handler.  Use write(2), not printf.
	 */
	sprintf(buf, "rdd received signal %d and exits\n", signum);
	write(2, buf, strlen(buf));
	_exit(EXIT_FAILURE);   /* exit _now_ */
}

static void
set_signal_handler(int signum, void (*handler)(int sig))
{
	struct sigaction siginfo;

	siginfo.sa_handler = handler;
	sigemptyset(&siginfo.sa_mask);
	siginfo.sa_flags = 0;

	if (sigaction(signum, &siginfo, 0) < 0) {
		unix_error("cannot install signal handler for signal %d", signum);
	}
}

void
rdd_catch_signals(void)
{
	/* The following signals may be generated during
	 * a write(2) system call.  We ignore them, so
	 * that the write will set errno and return -1.
	 */
#if defined(SIGPIPE)
	set_signal_handler(SIGPIPE, SIG_IGN);
#endif
#if defined(SIGXFSZ)
	set_signal_handler(SIGXFSZ, SIG_IGN);
#endif

	/* These signals are received when rdd is terminated
	 * externally.  In this case we exit gracefully.
	 */
#if defined(SIGINT)
	set_signal_handler(SIGINT,  signal_exit);
#endif
#if defined(SIGTERM)
	set_signal_handler(SIGTERM, signal_exit);
#endif
}

int
rdd_device_size(const char *path, rdd_count_t *size)
{
	off_t offset;
	int fd;

#if 0
	/* Use stat to determine the file type.  Use the size stored
	 * in the stat buffer if we are dealing with a regular file.
	 * Use platform-specific magic to deal with devices.
	 */

	if (stat(&pathinfo, path) < 0) {
	}

	if ((pathinfo.st_mode & S_ISREG) != 0) {
		*size = pathinfo.st_size;
		return RDD_OK;
	}

	/* Platform-specific code.
	 */
#if defined(0)

#else
	*size = RDD_WHOLE_FILE;
	return RDD_OK;
#endif
#endif

	if ((fd = open(path, O_RDONLY)) < 0) {
		return RDD_EOPEN;
	}
	if ((offset = lseek(fd, 0, SEEK_END)) == (off_t) -1) {
		return RDD_ESEEK;
	}

	*size = offset;
	return RDD_OK;
}
