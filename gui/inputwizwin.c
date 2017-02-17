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
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "rdd.h"
#include "rdd_internals.h"
#include "rddgui.h"

static void
input_init(RDD_WIZWIN *ww)
{
	ww->help = "rddgui.html#input";
	ww->advanced = rddgui_inputadv_win;
}

static int
input_next(RDD_WIZWIN *ww)
{
	RDDGUI_OPTS *opts = ww->opts;
	struct stat pathinfo;
	rdd_count_t devsize;
	char *path = 0;
	int rc = RDD_OK;
	int fd = -1;

	if (opts->input_path != 0) {
		free(opts->input_path);
		opts->input_path = 0;
	}

	ww->next = 0;
       	opts->input_path = path = rddgui_get_text(ww, "entDevice", 1);
	
	/* Did the user select an input file at all?
	 */
	if (path == 0 || strlen(path) == 0) {
		rddgui_error(GTK_WINDOW(ww->window), "No input file specified");
		return 0;
	}

	if (stat(path, &pathinfo) < 0) {
		rddgui_error(GTK_WINDOW(ww->window), "Bad input path %s", path);
		return 0;
	}

	if (S_ISDIR(pathinfo.st_mode)) {
		rddgui_error(GTK_WINDOW(ww->window), "%s is a directory", path);
		return 0;
	}

	/* Can we open the path for reading?
	 */
	if ((fd = open(path, O_RDONLY)) < 0) {
		rddgui_error(GTK_WINDOW(ww->window), "Cannot open %s", path);
		return 0;
	}
	(void) close(fd);

	/* Obtain the file/device size.
	 */
	rc = rdd_device_size(path, &devsize);
	if (rc != RDD_OK) {
		rddgui_error(GTK_WINDOW(ww->window),
			"Cannot compute size of %s", path);
		return 0;
	}
	opts->input_size = devsize;

	/* Process the data in the advanced window. RDD-GUI can be run twice
	 * without the user opening and closing the advanced window.
	 */
	(ww->advanced->ops->next)(ww->advanced);

	/* Process the offset option.  If the user did not set
	 * this option explicitly then its value should be 0.
	 */
	if (opts->offset > devsize) {
		rddgui_error(GTK_WINDOW(ww->window),
			"Offset %llu exceeds input size ( %s )",
			opts->offset, rdd_strsize(devsize));
		return 0;
	}

	/* Process the count option.  If the user did not set
	 * this option explicitly then its value should be RDD_WHOLE_FILE.
	 */
	if ( (opts->count != RDD_WHOLE_FILE)
	&&  ((opts->offset + opts->count) > devsize)) {
		rdd_count_t total = opts->offset + opts->count;
		rddgui_error(GTK_WINDOW(ww->window),
			"Illegal offset/byte-count ( %llu and %llu ) "
			"combination. The offset and the bytes to read " 
			"together exceed the input size ( %llu to %s )", 
			opts->offset, opts->count, total, rdd_strsize(devsize));
		return 0;
	}

	/* Update the count option to reflect our knowledge of the
	 * size of the input file/device.
	 */
	if (devsize != RDD_WHOLE_FILE
	&&  opts->count == RDD_WHOLE_FILE)
	{
		opts->count = devsize - opts->offset;
	}

	ww->next = rddgui_output_win;
	return 1;
}

static void
input_advanced(RDD_WIZWIN *ww)
{
	ww->advanced = rddgui_inputadv_win;
}

RDD_WIZWIN_OPS rddgui_input_ops = {
	input_init,
	input_next,
	input_advanced
};
