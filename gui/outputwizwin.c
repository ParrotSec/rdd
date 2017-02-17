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
#include <fcntl.h>

#include "rdd.h"
#include "rddgui.h"

static void
output_init(RDD_WIZWIN *ww)
{
	ww->help = "rddgui.html#output";
	ww->advanced = rddgui_outputadv_win;
}

/*
 * Much of this checking is done in add_output_file() in outputfile.c.
 */
static int
validate_output_file(RDD_WIZWIN *ww, const char *guiname, 
			const char *label, const char *path)
{
	struct stat fileinfo;
	int fd;
	int remove = 0;

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

	/* Add file to the list of output files
	 */ 
	if (! rddgui_add_output_file(ww, label, path)) {
		return 0;
	}

	return 1;
}

static int
output_next(RDD_WIZWIN *ww)
{
	RDDGUI_OPTS *opts = ww->opts;

	if (opts->output_path != 0) {
		free(opts->output_path);
		opts->output_path = 0;
	}
	if (opts->log_path != 0) {
		free(opts->log_path);
		opts->log_path = 0;
	}
	ww->next = 0;

	opts->output_path = rddgui_get_text(ww, "entOutput", 1);
	if (strcmp(opts->output_path, opts->input_path) == 0) {
		rddgui_error(GTK_WINDOW(ww->window),
				"The output file has the same name as the "
				" input file");
		return 0;
	}
	if (! validate_output_file(ww, "output file", "output image file", 
							opts->output_path)) {
		return 0;
	}
	
	opts->log_path = rddgui_get_text(ww, "entLogfile", 1);
	if (strcmp(opts->log_path, opts->input_path) == 0) {
		rddgui_error(GTK_WINDOW(ww->window),
				"The log file has the same name as the "
				" input file");
		return 0;
	}
	if (! validate_output_file(ww, "log file", "log file", 
							opts->log_path)) {
		return 0;
	}
	
	if (strcmp(opts->output_path, opts->log_path) == 0) {
		rddgui_error(GTK_WINDOW(ww->window),
				"The output file and the log file have "
				"the same name");
		return 0;
	}

	/* Process the data in the advanced window. RDD-GUI can be run twice
	 * without the user opening and closing the advanced window.
	 */
	ww->advanced->ops->next(ww->advanced);

	ww->next = rddgui_integrity_win;
	return 1;
}

RDD_WIZWIN_OPS rddgui_output_ops = {
	output_init,
	output_next,
	0
};

/** \brief Disables the split size input widgets when the user
 *  indicates that he wants his output in a single file.
 */
static gboolean
single_toggled(GtkWidget *wdgt, gpointer data)
{
	RDD_WIZWIN *ww = (RDD_WIZWIN *) data;
	static const char *names[] = {"entSplit", "cboSplit"};

	rddgui_widgets_set_sensitive(ww, names, (sizeof names)/sizeof(char*),
					FALSE);
	return TRUE;
}

/** \brief Enables the split size input widgets when the user
 *  indicates that he wants to split his output.
 */
static gboolean
split_toggled(GtkWidget *wdgt, gpointer data)
{
	RDD_WIZWIN *ww = (RDD_WIZWIN *) data;
	static const char *names[] = {"entSplit", "cboSplit"};

	rddgui_widgets_set_sensitive(ww, names, (sizeof names)/sizeof(char*),
					TRUE);
	return TRUE;
}

static void
outputadv_init(RDD_WIZWIN *ww)
{
	ww->help = "rddgui.html#output-advanced";

	glade_xml_signal_connect_data(ww->xml, "on_radSingle_toggled",
			G_CALLBACK(single_toggled), ww);
	glade_xml_signal_connect_data(ww->xml, "on_radSplit_toggled",
			G_CALLBACK(split_toggled), ww);

	rddgui_radio_select(ww, "radSingle");
}

static int
outputadv_next(RDD_WIZWIN *ww)
{
	RDDGUI_OPTS *opts = ww->opts;
	int rc = RDD_OK;

	if (rddgui_radio_selected(ww, "radSingle")) {
		opts->split_output = 0;
		opts->split_size = 0;
		return 1;
	} else if (rddgui_radio_selected(ww, "radSplit")) {
		opts->split_output = 1;
		rc = rddgui_get_multnum(ww, "split size",
				"entSplit", "cboSplit", &opts->split_size);
		return rc == RDD_OK ? 1 : 0;
	} else {
		rddgui_fatal(GTK_WINDOW(ww->window), "No radio button selected");
		return 0; /* NOT REACHED */
	}
}

RDD_WIZWIN_OPS rddgui_outputadv_ops = {
	outputadv_init,
	outputadv_next,
	0
};
