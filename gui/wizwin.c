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

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "rdd.h"
#include "rddgui.h"

static void
next_clicked(GtkWidget *widget, gpointer data)
{
	RDD_WIZWIN *ww = (RDD_WIZWIN *) data;

	if (rdd_wizwin_next(ww)) {
		ww->result = RDDGUI_NEXT;
	} else {
		ww->result = RDDGUI_NONE;
	}
}

static void
back_clicked(GtkWidget *widget, gpointer data)
{
	RDD_WIZWIN *ww = (RDD_WIZWIN *) data;
	ww->result = RDDGUI_BACK;
}

static void
finish_clicked(GtkWidget *widget, gpointer data)
{
	RDD_WIZWIN *ww = (RDD_WIZWIN *) data;

	if (rdd_wizwin_next(ww)) {
		assert(ww->next == 0);
		ww->result = RDDGUI_FINISH;
	} else {
		ww->result = RDDGUI_NONE;
	}
}

static void
advanced_clicked(GtkWidget *widget, gpointer data)
{
	RDD_WIZWIN *ww = (RDD_WIZWIN *) data;

	ww->result = RDDGUI_ADVANCED;

#if 0
	rdd_wizwin_advanced(ww);
#endif
	if (ww->advanced == 0) {
		rddgui_fatal(GTK_WINDOW(ww->window),
				"no advanced options (not implemented?)");
	}
	(void) rdd_wizwin_run(ww->advanced);
}

static void
ok_clicked(GtkWidget *widget, gpointer data)
{
	RDD_WIZWIN *ww = (RDD_WIZWIN *) data;

	if (rdd_wizwin_next(ww)) {
		ww->result = RDDGUI_FINISH;
	} else {
		ww->result = RDDGUI_NONE;
	}
}

static void
help_clicked(GtkWidget *widget, gpointer data)
{
	RDD_WIZWIN *ww = (RDD_WIZWIN *) data;
	int rc;

	if (ww->help) {
		rc = rddgui_showhtml(ww->help);
		if (rc == RDD_NOTFOUND) {
			rddgui_error(GTK_WINDOW(ww->window),
					"No browser found");
		}
	}

	ww->result = RDDGUI_NONE;
}

static void
set_start_path(GtkFileSelection *filesel, const char *path)
{
	struct stat pathinfo;
	size_t pathlen;
	char *dirpath;

	if (path == 0				/* no path given */
	|| (pathlen = strlen(path)) == 0	/* empty path */
	|| stat(path, &pathinfo) < 0)		/* invalid path */
	{	
		return; /* do not set path; use current dir */
	}

	if (! S_ISDIR(pathinfo.st_mode)) {
		/* The path refers to some sort of (special) file.
		 */
		gtk_file_selection_set_filename(filesel, path);
		return;
	}

	/* The path refers to a directory. Make sure the path ends
	 * with a '/' character.
	 */
	if (path[pathlen-1] == '/') {
		gtk_file_selection_set_filename(filesel, path);
		return;
	}
	if ((dirpath = malloc(pathlen + 2)) == 0) {
		return;   /* out of memory (ignored) */
	}
	sprintf(dirpath, "%s/", path);
	gtk_file_selection_set_filename(filesel, dirpath);
	free(dirpath);
}

#if 0
static void
path_entered(GtkFileSelection *filesel)
{
	struct stat pathinfo;
	const char *path;

	path = gtk_entry_get_text(GTK_ENTRY(entry));

	if (stat(path, &pathinfo) == 0) {
		/* Valid path.
		 */
		if (! S_ISDIR(pathinfo.st_mode)) return;

		set_start_path(filesel, path);
	} else { 
		/* Bad path: assume it is a prefix of a valid path.
		 */
		char *pattern;

		if ((pattern = malloc(strlen(path) + 2)) == 0) {
			return;   /* out of memory (ignored) */
		}
		sprintf(pattern, "%s*", path);
		gtk_file_selection_complete(filesel, pattern);
		free(pattern);
	}

	browse_path(filesel);
}
#endif

static void
file_dialog(GtkWidget *widget, GtkEntry *entry, int save)
{
	GtkWidget *filedialog;
	const char *title;
	gint result;
	char path[RDDGUI_MAX_FILENAME_SIZE];
	
	title = save ? "Select output file" : "Select input file";

	/* Use a GtkFileSelection. GtkFileChooser may be nicer, but
	 * it requires a higher version of GTK.
	 */
	filedialog = gtk_file_selection_new(title);
	if (! save) {
		gtk_file_selection_hide_fileop_buttons(
				GTK_FILE_SELECTION(filedialog));
	}
	
	if (rddgui_get_dir(gtk_entry_get_text(GTK_ENTRY(entry)), 
						(char *)&path)) {

		set_start_path(GTK_FILE_SELECTION(filedialog), path);
	} else {
		set_start_path(GTK_FILE_SELECTION(filedialog), "");
	}

	result = gtk_dialog_run(GTK_DIALOG(filedialog));

	if (result == GTK_RESPONSE_OK) {
		const char *path = gtk_file_selection_get_filename(
					GTK_FILE_SELECTION(filedialog));
		gtk_entry_set_text(entry, path);
		
		/* Bug fix: path must _not_ be freed!
		 */
	}

	gtk_widget_destroy(filedialog);
}

static void
open_file_dialog(GtkWidget *widget, GtkEntry *entry)
{
	file_dialog(widget, (GtkEntry *) entry, 0);
}

static void
save_file_dialog(GtkWidget *widget, gpointer *entry)
{
	file_dialog(widget, (GtkEntry *) entry, 1);
}

int
rdd_new_wizwin(RDD_WIZWIN **self, const char *path, const char *name,
#if 0
	const char *help,
#endif
	RDDGUI_OPTS *opts, RDD_WIZWIN_OPS *ops, unsigned statesize)
{
	GladeXML *xml = 0;
	GtkWidget *widget = 0;
	RDD_WIZWIN *ww = 0;
	int rc = RDD_OK;
	void *state = 0;

	if ((ww = calloc(1, sizeof(RDD_WIZWIN))) == 0) {
		rc = RDD_NOMEM;
		goto error;
	}

	if ((state = calloc(1, statesize)) == 0) {
		rc = RDD_NOMEM;
		goto error;
	}

	/* How to release this stuff */
	xml = glade_xml_new(path, name, NULL);
	widget = glade_xml_get_widget(xml, name);
	gtk_widget_hide_all(widget);

	if (strlen(name) > (RDD_MAX_WIDGET_NAME_LEN - 1)){
		rc = RDD_ERANGE;
		goto error;
	} else {
		strcpy(ww->name, name);
	}

	ww->xml = xml;
	ww->window = widget;
	ww->opts = opts;
	ww->ops = ops;
	ww->state = state;

	/* Connect signals. A wizard window typically handles only
	 * a subset of the signals connected below, but that's all
	 * right.
	 */
	glade_xml_signal_connect_data(xml, "on_butNext_clicked",
			G_CALLBACK(next_clicked), ww);
	glade_xml_signal_connect_data(xml, "on_butBack_clicked",
			G_CALLBACK(back_clicked), ww);
	glade_xml_signal_connect_data(xml, "on_butFinish_clicked",
			G_CALLBACK(finish_clicked), ww);
	glade_xml_signal_connect_data(xml, "on_butAdv_clicked",
			G_CALLBACK(advanced_clicked), ww);
	glade_xml_signal_connect_data(xml, "on_butOK_clicked",
			G_CALLBACK(ok_clicked), ww);
	glade_xml_signal_connect_data(xml, "on_butHelp_clicked",
			G_CALLBACK(help_clicked), ww);

	/* Connect browse button signals. I assume that there is
	 * a one-to-one correspondence between the name of a
	 * browse button and the name of the text entry widget
	 * that will hold the path name.
	 */
	glade_xml_signal_connect_data(xml, "on_butBrowse_clicked",
			G_CALLBACK(open_file_dialog),
			glade_xml_get_widget(xml, "entDevice"));

	glade_xml_signal_connect_data(xml, "on_butLogfile_clicked",
			G_CALLBACK(save_file_dialog),
			glade_xml_get_widget(xml, "entLogfile"));

	glade_xml_signal_connect_data(xml, "on_butOutput_clicked",
			G_CALLBACK(save_file_dialog),
			glade_xml_get_widget(xml, "entOutput"));

	glade_xml_signal_connect_data(xml, "on_butAdler_clicked",
			G_CALLBACK(save_file_dialog),
			glade_xml_get_widget(xml, "entAdlerFile"));

	glade_xml_signal_connect_data(xml, "on_butCRC_clicked",
			G_CALLBACK(save_file_dialog),
			glade_xml_get_widget(xml, "entCRCFile"));

	glade_xml_signal_connect_data(xml, "on_butEntropy_clicked",
			G_CALLBACK(save_file_dialog),
			glade_xml_get_widget(xml, "entEntropyFile"));

	glade_xml_signal_connect_data(xml, "on_butMD5_clicked",
			G_CALLBACK(save_file_dialog),
			glade_xml_get_widget(xml, "entMD5File"));


	if (ops->init) {
		(*ops->init)(ww);
	}

	*self = ww;
	return RDD_OK;

error:
	*self = 0;
	if (state != 0) free(state);
	if (ww != 0) free(ww);
	return rc;
}

int
rdd_free_wizwin(RDD_WIZWIN *ww)
{
	return RDD_OK;
}

int
rdd_wizwin_run(RDD_WIZWIN *ww)
{
	RDD_WIZWIN *next = 0;
	gint result;

	while (1) {
		gtk_widget_show_all(ww->window);
		result = gtk_dialog_run(GTK_DIALOG(ww->window));

		if (result == GTK_RESPONSE_DELETE_EVENT) {
			/* The user is deleting the dialog window.
			 */
			gtk_widget_hide_all(ww->window);
			return  RDD_ABORTED;
		}

		if (result != 0) {
			/* Hmm, does this really make any sense?
			 */
			gtk_widget_hide_all(ww->window);
			return RDD_OK;
		}

		if (ww->result == RDDGUI_NONE) {
			continue;
		}

		next = ww->next;

		switch (ww->result) {
		case RDDGUI_NONE:
			break;
		case RDDGUI_ADVANCED:
			break;
		case RDDGUI_NEXT:
			next->prev = ww;
			gtk_widget_hide_all(ww->window);
			ww = next;
			next = 0;
			break;
		case RDDGUI_BACK:
			if (ww->prev != 0) {
				gtk_widget_hide_all(ww->window);
				ww = ww->prev;
			}
			break;
		case RDDGUI_FINISH:
			gtk_widget_hide_all(ww->window);
			return RDD_OK;
		}
	}

	return RDD_OK;
}

int
rdd_wizwin_next(RDD_WIZWIN *ww)
{
	RDD_WIZWIN_OPS *ops = ww->ops;
	RDD_WIZWIN *next;
	int rc;	

	/* handler should set ww->next to an appropriate value */
	ww->next = 0;

	if (ops->next != 0) {
		rc = (*ops->next)(ww);
		if (rc != RDD_OK){
			return rc;
		}

#if 0
		if (strcmp(ww->next->name, "dlgConfirmation") == 0){
			/* dlgConfirmation has to be updated every time 
			 * before it is shown.
			 */	
			(ww->next->ops->init)(ww->next);
		}
#endif
	} else {
		rc = 1;
	}

	next = ww->next;

#if 0
	if (next != 0 && next->ops->activated != 0) {
		(*next->ops->activated)(next);
	}
#endif

	return rc;
}

void
rdd_wizwin_advanced(RDD_WIZWIN *ww)
{
	RDD_WIZWIN_OPS *ops = ww->ops;

	ww->advanced = 0;
	if (ops->advanced != 0) {
		(*ops->advanced)(ww);
	}

}
