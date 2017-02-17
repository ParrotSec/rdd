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

#include "rdd.h"
#include "rddgui.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_OUTFILE 8

typedef struct _RDDGUI_OUTFILE {
	const char *label;
	char *path;
} RDDGUI_OUTFILE;

static RDDGUI_OUTFILE outfiles[MAX_OUTFILE];
static unsigned num_outfile;

int
rddgui_add_output_file(RDD_WIZWIN *ww, const char *label, const char *path)
{
	RDDGUI_OUTFILE *outfile = 0;
	RDDGUI_OUTFILE *replace = 0;
	char *copy = 0;
	struct stat pathinfo;
	unsigned i;
	int rc;
	int fd;

	/* Do not allow empty paths.
	 */
	if (path == 0 || strlen(path) == 0) {
		rddgui_error(GTK_WINDOW(ww->window), "Empty %s field", label);
		return 0;
	}

	/* Find out where to insert the path. If label matches an
	 * existing label, then we will overwrite the entry for that
	 * existing label.
	 */
	for (i = 0; i < num_outfile; i++) {
		outfile = &outfiles[i];

		if (outfile->label == 0 || outfile->path == 0) {
			continue;
		}

		if (strcmp(outfile->label, label) == 0) {
			replace = outfile;
			continue;
		}

		if (strcmp(outfile->path, path) == 0) {
			rddgui_error(GTK_WINDOW(ww->window),
				"%s %s already specified as %s",
				label, path, outfile->label);
#if 1
			rddgui_dump_output_files();
#endif
			return 0;
		}
	}

	rc = stat(path, &pathinfo);

	if (rc < 0 && errno != ENOENT) { 
		rddgui_error(GTK_WINDOW(ww->window),
			"Cannot get information on %s ", path);
		return 0;
	}
			
	if (rc == 0) {

		/* File or directory exists.
		 */
		if (S_ISDIR(pathinfo.st_mode)) {
			rddgui_error(GTK_WINDOW(ww->window),
				"%s is a directory", path);
			return 0;
		}

		/* File exists.  Ask user whether we can remove it.
		 */
		int remove = rddgui_yesno_dialog(GTK_WINDOW(ww->window),
				"%s exists.\nRemove %s?\n\nCheck the "
				"regular screen and the advanced screen "
				"for this file entry.", path, path);
		if (! remove) return 0;

		rc = unlink(path);
		if (rc < 0) {
			rddgui_error(GTK_WINDOW(ww->window),
				"Cannot remove %s", path);
			return 0;
		}
	}

	/* Make sure we can create the output file.
	 */
	if ((fd = open(path, O_WRONLY|O_CREAT)) < 0) {
		rddgui_error(GTK_WINDOW(ww->window), "Cannot create %s", path);
		return 0;
	}
	(void) close(fd);
	(void) unlink(path);

	if (!replace && num_outfile >= MAX_OUTFILE) {
		rddgui_error(GTK_WINDOW(ww->window), "Too many output files");
		return 0;
	}

	copy = malloc(strlen(path) + 1);
	if (copy == 0) {
		rddgui_fatal(GTK_WINDOW(ww->window), "Out of memory");
	}
	strcpy(copy, path);

	if (replace) {
		if (replace->path != 0) {
			free(replace->path);
		}
		replace->path = copy;
	} else {
		outfile = &outfiles[num_outfile++];
		outfile->label = label;
		outfile->path = copy;
	}

	return 1;
}

void
rddgui_clear_output_files(void)
{
	RDDGUI_OUTFILE *outfile = 0;
	unsigned i;

	for (i = 0; i < (sizeof outfiles)/(sizeof outfiles[0]); i++) {
		outfile = &outfiles[i];
		if (outfile->path != 0) {
			free(outfile->path);
		}
		outfiles->label = 0;
		outfiles->path = 0;
	}

	num_outfile = 0;
}

void
rddgui_dump_output_files(void)
{
	RDDGUI_OUTFILE *outfile = 0;
	int i;

	for (i = 0; i < MAX_OUTFILE; i++) {
		outfile = &outfiles[i];

		printf("Entry: %u\n", i);
		printf("Label: %s\n",
			outfile->label ? outfile->label : "(empty)");
		printf("Path: %s\n",
			outfile->path ? outfile->path : "(empty)");
		printf("\n");
	}
}
