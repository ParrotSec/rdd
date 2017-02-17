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

#include <gtk/gtk.h>
#include <glade/glade.h>

#include "rdd.h"
#include "rdd_internals.h"
#include "numparser.h"
#include "rddgui.h"

static int get_advanced(RDD_WIZWIN *ww);

static gboolean
yes_toggled(GtkWidget *w, gpointer data)
{
	GtkWidget *advanced_button = (GtkWidget *) data;

	gtk_widget_set_sensitive(advanced_button, TRUE);

	return TRUE;
}

static gboolean
no_toggled(GtkWidget *w, gpointer data)
{
	GtkWidget *advanced_button = (GtkWidget *) data;

	gtk_widget_set_sensitive(advanced_button, FALSE);

	return TRUE;
}

static void
recovery_init(RDD_WIZWIN *ww)
{
	GtkWidget *advanced_button = 0;

	ww->help = "rddgui.html#error-recovery";
	ww->advanced = rddgui_recoveryadv_win;
       
	advanced_button = glade_xml_get_widget(ww->xml, "butAdvanced");

	glade_xml_signal_connect_data(ww->xml, "on_radYes_toggled",
			G_CALLBACK(yes_toggled), advanced_button);
	glade_xml_signal_connect_data(ww->xml, "on_radNo_toggled",
			G_CALLBACK(no_toggled), advanced_button);

	rddgui_focus(ww, "butNext");
}

static int
recovery_next(RDD_WIZWIN *ww)
{
	RDDGUI_OPTS *opts = ww->opts;

	if (rddgui_radio_selected(ww, "radYes")) {
		opts->enable_recovery = 1;
	} else if (rddgui_radio_selected(ww, "radNo")) {
		opts->enable_recovery = 0;
	} else {
		rddgui_fatal(0, "No selected value for radio button");
	}

	/* Ignore the data in the advanced window if we're not 
	 * doing error recovery
	 */
	if (opts->enable_recovery == 1) {
		if (! get_advanced(ww->advanced)) {
			return 0;
		}
	}

	ww->next = rddgui_stats_win;
	return 1;
}

static void
recovery_advanced(RDD_WIZWIN *ww)
{
	ww->advanced = rddgui_recoveryadv_win;
}

RDD_WIZWIN_OPS rddgui_recovery_ops = {
	recovery_init,
	recovery_next,
	recovery_advanced
};


static gboolean
giveup_toggled(GtkWidget *widget, gpointer data)
{
	GtkWidget *entry = (GtkWidget *) data;

	gtk_widget_set_sensitive(entry, TRUE);

	return TRUE;
}

static gboolean
never_toggled(GtkWidget *widget, gpointer data)
{
	GtkWidget *entry = (GtkWidget *) data;

	gtk_widget_set_sensitive(entry, FALSE);

	return TRUE;
}

static void
recoveryadv_init(RDD_WIZWIN *ww)
{
	GtkWidget *giveup_entry = 0;

	rddgui_radio_select(ww, "radNever");

	ww->help = "rddgui.html#error-recovery-advanced";
	ww->advanced = 0;
       
	rddgui_set_multnum(ww, ww->opts->retry_block_size,
			"entRetryBlocksize", "cboRetryBlocksize");
	rddgui_set_uint(ww, "entDrop", ww->opts->max_retry_count);

	giveup_entry = glade_xml_get_widget(ww->xml, "entGiveUp");
	gtk_widget_set_sensitive(giveup_entry, FALSE);

	glade_xml_signal_connect_data(ww->xml, "on_radGiveUp_toggled",
			G_CALLBACK(giveup_toggled), giveup_entry);
	glade_xml_signal_connect_data(ww->xml, "on_radNever_toggled",
			G_CALLBACK(never_toggled), giveup_entry);
}

static int
get_advanced(RDD_WIZWIN *ww)
{
	RDDGUI_OPTS *opts = ww->opts;
	int rc;

	rc = rddgui_get_multnum(ww, "retry block size",
				"entRetryBlocksize", "cboRetryBlocksize",
				&opts->retry_block_size);
	if (rc != RDD_OK) {
		return 0;
	}

	rc = rddgui_get_uint(ww, "maximum retry count", "entDrop",
				&opts->max_retry_count);
	if (rc != RDD_OK) {
		return 0;
	}

	if (rddgui_radio_selected(ww, "radNever")) {
		opts->never_give_up = 1;
		opts->max_drop_count = 0;
	} else {
		opts->never_give_up = 0;

		rc = rddgui_get_uint(ww, "maximum drop count", "entGiveUp",
				&opts->max_drop_count);
		if (rc != RDD_OK) {
			return 0;
		}

		if (opts->max_drop_count == 0) {
			rddgui_error(GTK_WINDOW(ww->window),
				"Drop count must be greater than zero.");
			return 0;
		}
	}

	return 1;
}

static int
recoveryadv_next(RDD_WIZWIN *ww)
{
	ww->next = 0;
	return get_advanced(ww);
}

RDD_WIZWIN_OPS rddgui_recoveryadv_ops = {
	recoveryadv_init,
	recoveryadv_next,
	0
};
