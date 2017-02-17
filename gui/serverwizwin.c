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
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "rdd.h"
#include "rddgui.h"

static void
server_init(RDD_WIZWIN *ww)
{
	ww->help = "rddgui.html#server";
	ww->advanced = rddgui_serveradv_win;
}

/* REFACTOR Duplicate code 
 * Code copied from outputwizwin.c. Code in outputwizwin has been changed.
 * Changes should be applied here too. Better is to move this function 
 * to utils.c.*/
static int
validate_output_file(RDD_WIZWIN *ww, const char *guiname, const char *path)
{
	struct stat fileinfo;

	/* Did the user specify an output file at all?
	 */
	if (path == 0 || strlen(path) == 0) {
		rddgui_error(GTK_WINDOW(ww->window),
				"No %s specified", guiname);
		return 0;
	}

	if (ww->opts->split_output) {
		/* If the output is to be split, we are not dealing with
		 * a single output path, but with a set of output paths 
		 * and we cannot always know the number of output paths
		 * in that set.  All checks below assume a single output
		 * path and do not apply to the case that the output is
		 * split.
		 */
		return 1;
	}

	/* Get file status and deal with it.
	 */
	memset(&fileinfo, 0, sizeof fileinfo);
	if (stat(path, &fileinfo) >= 0) {          /* path exists. */
		int remove;

		/* Is it a regular file?
		 */
		if (! S_ISREG(fileinfo.st_mode)) {
			rddgui_error(GTK_WINDOW(ww->window),
				"%s is not a regular file", path);
			return 0;
		}

		/* Should we really overwrite this existing file?
		 */
		remove = rddgui_yesno_dialog(GTK_WINDOW(ww->window),
				"Output file %s exists.\nRemove %s?",
				path, path);
		if (! remove) {
			return 0;
		}

		if (unlink(path) < 0) {
			rddgui_error(GTK_WINDOW(ww->window),
				"Cannot remove %s", path);
			return 0;
		}
	} else if (errno != ENOENT) {
		/* Some unexpected error.
		*/
		rddgui_error(GTK_WINDOW(ww->window),
				"File status error for %s", path);
			return 0;
	}

#if 0
	/* Do we have write access to the output file's directory?
	 */
	if ((fd = open(path, O_RDONLY)) < 0) {
		rddgui_error(GTK_WINDOW(ww->window), "cannot open %s", path);
		return 0;
	}
	(void) close(fd);
#endif

	return 1;
}

static int
server_next(RDD_WIZWIN *ww)
{
	RDDGUI_OPTS *opts = ww->opts;

	if (opts->log_path != 0) {
		free(opts->log_path);
		opts->log_path = 0;
	}
	ww->next = 0;

	opts->log_path = rddgui_get_text(ww, "entLogfile", 1);
	if (! validate_output_file(ww, "server log file", opts->log_path)) {
		return 0;
	}
	
#if 0
	ww->next = rddgui_server_waiting_win;
#else
	ww->next = 0;
#endif
	return 1;
}

RDD_WIZWIN_OPS rddgui_server_ops = {
	server_init,
	server_next,
	0
};

static void
serveradv_init(RDD_WIZWIN *ww)
{
	/* set standard port? */
}

static int
serveradv_next(RDD_WIZWIN *ww)
{
	unsigned port;

	if (! rddgui_get_uint(ww, "server port", "name", &port)) {
		return 0;
	}

	if (port >= 65536) {
		rddgui_error(GTK_WINDOW(ww->window),
			"Port number too large.\n\n"
			"Choose a port number smaller than 65536.");
		return 0;
	}
	
	ww->opts->server_port = port;
	return 1;
}

RDD_WIZWIN_OPS rddgui_serveradv_ops = {
	serveradv_init,
	serveradv_next,
	0
};
