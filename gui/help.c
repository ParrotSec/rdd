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

#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "rdd.h"
#include "rddgui.h"

static char *browsers[] = {
	"firefox",
	"konqueror",
	"mozilla",
	"mozilla-gtk2",
	"netscape",
	"galeon",
	"opera",
	0
};

/* Checks whether browser exists in a directory on the user's PATH.
 * If there is no PATH, a default path is searched (/bin:/usr/bin).
 */
static int
find_executable(const char *browser)
{
	char *origpath = getenv("PATH");
	char *path = 0;
	char *dir;
	unsigned bpathlen;
	char *bpath = 0;
	char *save = 0;
	int rc = RDD_NOTFOUND;

	if (origpath == NULL) {
		origpath = "/bin:/usr/bin";	/* default path */
	}

	/* Strtok (used below) will modify the path, so we
	 * copy the path.
	 */
	if ((path = malloc(strlen(origpath) + 1)) == 0) {
		rc = RDD_NOMEM;
		goto done;
	}
	strcpy(path, origpath);

	/* Try all directories.
	 */
	for (dir = strtok_r(path, ":", &save);
	     dir;
	     dir = strtok_r(NULL, ":", &save) )
	{
		bpathlen = strlen(dir) + 1 + strlen(browser) + 1;
		if ((bpath = malloc(bpathlen)) == 0) {
			rc = RDD_NOMEM;
			goto done;
		}
		snprintf(bpath, bpathlen, "%s/%s", dir, browser);

		if (access(bpath, R_OK|X_OK) == 0) {
			rc = RDD_OK;
			goto done;
		}
		free(bpath);
		bpath = 0;
	}

done:
	if (path != 0) free(path);
	if (bpath != 0) free(bpath);
	return rc;
}

/** \brief Starts a browser in a new process.
 */
static void
start_browser(char *browser, char *url)
{
	pid_t pid;
	char *newargv[3];

	pid = fork();
	if (pid < 0) {
		return; /* Fork failed. */
	} else if (pid == 0) {
		/* This is the level-1 child process. We will fork again
		 * to prevent the creation of a zombie process. (The
		 * browser may exit before our parent process. Since
		 * the parent will not wait() for the browser process,
		 * the browser would become a zombie.) See [W.R. Stevens,
		 * Advanced Programming in the Unix Environment, pp. 201-202,
		 * Addison-Wesley, 1992].
		 */
		pid = fork();
		if (pid < 0) {
			return; /* Fork failed. */
		} else if (pid > 0) {
			/* This is the level-2 parent process. It will exit
			 * immediately; the root process will wait
			 * for this process.
			 */
			exit(EXIT_SUCCESS);
		}

		/* This is the level-2 child process. This process
		 * will run the browser.
		 */
		newargv[0] = browser;
		newargv[1] = url;
		newargv[2] = NULL;
		execvp(browser, newargv);
		_exit(EXIT_FAILURE); /* See the Unix programming FAQ */
	}

	/* This is the level-1 parent process. It waits for the
	 * level-2 parent process and then resumes GUI execution.
	 */
	if (waitpid(pid, NULL, 0) != pid) {
		/* XXX FIXME Error.
		 */
	}
}

/** Appends string s to buffer *p which has room for *len bytes.
 *  Returns RDD_OK on success and RDD_ESPACE if there is insufficient
 *  space in the buffer.  Updates *p and *len.
 */
static int
append(char **p, unsigned *len, const char *s)
{
	unsigned slen = strlen(s);

	if ((slen + 1) > *len) {
		return RDD_ESPACE;
	}

	strcpy(*p, s);
	*p += slen;
	*len -= slen;

	return RDD_OK;
}

int
rddgui_showhtml(const char *htmlfile)
{
	char urlbuf[1024];
	int buflen = sizeof urlbuf;
	char *p = urlbuf;
	unsigned i;
	int rc;

	/* Create a suitable URL.
	 */
	*p = '\000';
	if ((rc = append(&p, &buflen, "file://")) != RDD_OK) {
		return rc;
	}
	if (htmlfile[0] != '/') {
		/* Relative path: prepend shared dir
		 */
		if ((rc = append(&p, &buflen, RDDGUI_DATADIR)) != RDD_OK) {
			return rc;
		}
		if ((rc = append(&p, &buflen, "/")) != RDD_OK) {
			return rc;
		}
	}
	if ((rc = append(&p, &buflen, htmlfile)) != RDD_OK) {
		return rc;
	}

	/* Find a browser.
	 */
	for (i = 0; browsers[i] != 0; i++) {
		rc = find_executable(browsers[i]);
		if (rc == RDD_OK) {
			start_browser(browsers[i], urlbuf);
			return RDD_OK;
		} else if (rc != RDD_NOTFOUND) {
			return rc;
		}
	}

	return RDD_NOTFOUND;
}
