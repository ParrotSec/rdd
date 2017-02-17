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

#include <math.h>
#include <stdarg.h>
#include <stdlib.h>

#include <gtk/gtk.h>
#include <glade/glade.h>

#include "rdd.h"
#include "rddgui.h"

static gboolean
help_clicked(GtkWidget *widget, gpointer data)
{
	RDDGUI_FINISHEDWIN *win = (RDDGUI_FINISHEDWIN *) data;

	win->action = RDDGUI_FINISH_HELP;

	return TRUE;
}

static gboolean
exit_clicked(GtkWidget *widget, gpointer data)
{
	RDDGUI_FINISHEDWIN *win = (RDDGUI_FINISHEDWIN *) data;

	win->action = RDDGUI_FINISH_EXIT;

	return TRUE;
}

static gboolean
new_clicked(GtkWidget *widget, gpointer data)
{
	RDDGUI_FINISHEDWIN *win = (RDDGUI_FINISHEDWIN *) data;

	win->action = RDDGUI_FINISH_NEW;

	return TRUE;
}

static gboolean
logfile_clicked(GtkWidget *widget, gpointer data)
{
	RDDGUI_FINISHEDWIN *win = (RDDGUI_FINISHEDWIN *) data;

	win->action = RDDGUI_FINISH_LOGFILE;

	return TRUE;
}

static void
set_label_text(GladeXML *xml, const char *name, const char *fmt, ...)
{
	va_list ap;
	GtkWidget *label;
	char textbuf[128];

	va_start(ap, fmt);
	vsnprintf(textbuf, sizeof textbuf, fmt, ap);
	textbuf[(sizeof textbuf) - 1] = '\000';
	va_end(ap);

	label = glade_xml_get_widget(xml, name);
	gtk_label_set_text(GTK_LABEL(label), textbuf);
}

RDDGUI_FINISHEDWIN *
rddgui_create_finished_window(RDDGUI_IMGSTATS *stats)
{
	RDDGUI_FINISHEDWIN *win = 0;
	GtkWidget *exit_button = 0;

	if ((win = calloc(1, sizeof(RDDGUI_FINISHEDWIN))) == 0) {
		rddgui_fatal(0, "out of memory");
	}

	win->xml = glade_xml_new(rddgui_xml_path,
				"dlgFinishedImaging", NULL);
	win->win = glade_xml_get_widget(win->xml, "dlgFinishedImaging");

	gtk_widget_hide_all(win->win);

	/* Display elapsed times.
	 */
	set_label_text(win->xml, "lblShowTime", "%uh %um %us",
		stats->elapsed / 3600,		/* hours */
		(stats->elapsed % 3600) / 60,	/* minutes */
		stats->elapsed % 60);		/* seconds */

	/* Display error statistics.
	 */
	set_label_text(win->xml, "lblShowErrors", "%llu", stats->nreaderr);
	set_label_text(win->xml, "lblShowSubstBlocks", "%llu", stats->nsubst);
	set_label_text(win->xml, "lblShowSubstBytes", "%llu", stats->bytes_dropped);
	
	/* Display hash values.
	 */
	set_label_text(win->xml, "lblShowMD5", "%s", stats->md5);
	set_label_text(win->xml, "lblShowSHA1", "%s", stats->sha1);

	/* Connect signals.
	 */
	glade_xml_signal_connect_data(win->xml, "on_butHelp_clicked",
			G_CALLBACK(help_clicked), win);
	glade_xml_signal_connect_data(win->xml, "on_butExit_clicked",
			G_CALLBACK(exit_clicked), win);
	glade_xml_signal_connect_data(win->xml, "on_butNew_clicked",
			G_CALLBACK(new_clicked), win);
	glade_xml_signal_connect_data(win->xml, "on_butLogfile_clicked",
			G_CALLBACK(logfile_clicked), win);

	exit_button = glade_xml_get_widget(win->xml, "butExit");
	gtk_widget_grab_focus(exit_button);

	return win;
}

rddgui_finish_action_t
rddgui_run_finished_window(RDDGUI_FINISHEDWIN *win)
{
	gboolean quit;

	win->action = RDDGUI_FINISH_NONE;

	gtk_widget_show_all(win->win);

	while (win->action == RDDGUI_FINISH_NONE) {
		quit = gtk_main_iteration_do(TRUE);
	}

	return win->action;
}

void
rddgui_destroy_finished_window(RDDGUI_FINISHEDWIN *win)
{
	gtk_widget_destroy(win->win);
	free(win);
}
