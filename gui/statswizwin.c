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
#include <gtk/gtk.h>
#include <glade/glade.h>
#include <string.h>
#include <stdio.h>

#include "rdd.h"
#include "rddgui.h"

static int get_advanced(RDD_WIZWIN *ww);
static void set_values(RDD_WIZWIN *ww);

static void
statsadv_dialog_shown(GtkWidget *widget, gpointer data)
{
	set_values((RDD_WIZWIN *) data);
}

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
stats_init(RDD_WIZWIN *ww)
{
	GtkWidget *advanced_button = 0;

	ww->help = "rddgui.html#statistics";
	ww->advanced = rddgui_statsadv_win;
       
	advanced_button = glade_xml_get_widget(ww->xml, "butAdvanced");

	glade_xml_signal_connect_data(ww->xml, "on_radYes_toggled",
			G_CALLBACK(yes_toggled), advanced_button);
	glade_xml_signal_connect_data(ww->xml, "on_radNo_toggled",
			G_CALLBACK(no_toggled), advanced_button);

	rddgui_focus(ww, "butNext");
}

static int
stats_next(RDD_WIZWIN *ww)
{
	RDDGUI_OPTS *opts = ww->opts;

	if (rddgui_radio_selected(ww, "radYes")) {
		opts->enable_stats = 1;
	} else if (rddgui_radio_selected(ww, "radNo")) {
		opts->enable_stats = 0;
	} else {
		rddgui_fatal(0, "No selected value for radio button");
	}
	
	/* Ignore the data in the advanced screen if we're not doing 
	 * statistics. 
	 */
	if (opts->enable_stats == 1) {
		if (! get_advanced(ww->advanced)) {
			return 0;
		}
	}

	ww->next = rddgui_confirmation_win;
	return 1;
}

static void
stats_advanced(RDD_WIZWIN *ww)
{
	ww->advanced = rddgui_statsadv_win;
}

RDD_WIZWIN_OPS rddgui_stats_ops = {
	stats_init,
	stats_next,
	stats_advanced
};


static gboolean
entropy_toggled(GtkWidget *wdgt, gpointer data)
{
	RDD_WIZWIN *ww = (RDD_WIZWIN *) data;
	const char *widget_names[] = {
		"entEntropyBlocksize",
		"entEntropyFile",
		"butEntropy",
		"cboEntropy"
	};
	gboolean onoff = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(wdgt));
	rddgui_widgets_set_sensitive(ww,
			widget_names, (sizeof widget_names) / sizeof(char *),
			onoff);
	return TRUE;
}

static gboolean
md5_toggled(GtkWidget *wdgt, gpointer data)
{
	RDD_WIZWIN *ww = (RDD_WIZWIN *) data;
	const char *widget_names[] = {
		"entMD5Blocksize",
		"entMD5File",
		"butMD5",
		"cboMD5"
	};
	gboolean onoff = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(wdgt));

	rddgui_widgets_set_sensitive(ww,
			widget_names, (sizeof widget_names) / sizeof(char *),
			onoff);
	return TRUE;
}

static void
statsadv_init(RDD_WIZWIN *ww)
{
	GtkWidget *combo;
	

	ww->help = "rddgui.html#statistics-advanced";

	rddgui_set_text(ww, "entEntropyBlocksize", "32");
	combo = glade_xml_get_widget(ww->xml, "cboEntropy");
	gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(combo)->entry), "kB");

	rddgui_set_text(ww, "entMD5Blocksize", "32");
	combo = glade_xml_get_widget(ww->xml, "cboMD5");
	gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(combo)->entry), "kB");

	glade_xml_signal_connect_data(ww->xml, "on_chkEntropy_toggled",
			G_CALLBACK(entropy_toggled), ww);
	glade_xml_signal_connect_data(ww->xml, "on_chkMD5_toggled",
			G_CALLBACK(md5_toggled), ww);

	glade_xml_signal_connect_data(ww->xml, "on_dlgStatisticsAdv_show",
			G_CALLBACK(statsadv_dialog_shown), ww);
}

static int
get_path_and_block_size(RDD_WIZWIN *ww,
	const char *size_description,
	const char *size_entry_name,
	const char *size_combo_name,
	rdd_count_t *block_size,
	const char *path_description,
	const char *path_entry_name,
	char **path)
{
	char *path_copy;
	int rc;

	rc = rddgui_get_multnum(ww,
			size_description, size_entry_name, size_combo_name,
			block_size);
	if (rc != RDD_OK) {
		return 0;
	}

	path_copy = rddgui_get_text(ww, path_entry_name, 1);
	if (! rddgui_add_output_file(ww, path_description, path_copy)) {
		free(path_copy);
		return 0;
	}
	*path = path_copy;

	return 1;
}

static int
get_advanced(RDD_WIZWIN *ww)
{
	RDDGUI_OPTS *opts = ww->opts;

	if (opts->entropy_path != 0) {
		free(opts->entropy_path);
		opts->entropy_path = 0;
	}
	if (opts->blockmd5_path != 0) {
		free(opts->blockmd5_path);
		opts->blockmd5_path = 0;
	}

	opts->enable_entropy = rddgui_get_checked(ww, "chkEntropy");
	if (opts->enable_entropy) {
		if (! get_path_and_block_size(ww,
			"entropy block size",
			"entEntropyBlocksize", "cboEntropy",
			&opts->entropy_block_size,
			"block entropy output file", "entEntropyFile",
			&opts->entropy_path))
		{
			return 0;
		}
	} else {
		opts->entropy_block_size = 0;
		opts->entropy_path = 0;
	}

	opts->enable_blockmd5 = rddgui_get_checked(ww, "chkMD5");
	if (opts->enable_blockmd5) {
		if (! get_path_and_block_size(ww,
			"MD5 block size",
			"entMD5Blocksize", "cboMD5",
			&opts->blockmd5_block_size,
			"block MD5 output file", "entMD5File",
			&opts->blockmd5_path))
		{
			return 0;
		}
	} else {
		opts->blockmd5_block_size = 0;
		opts->blockmd5_path = 0;
	}

	return 1;
}

static int
statsadv_next(RDD_WIZWIN *ww)
{
	if (! get_advanced(ww)) {
		return 0;
	}

	ww->next = 0;
	return 1;
}

RDD_WIZWIN_OPS rddgui_statsadv_ops = {
	statsadv_init,
	statsadv_next,
	0
};

static void
set_values(RDD_WIZWIN *ww)
{

	build_part_path(ww, "entEntropyFile", "entropy.dat");
	build_part_path(ww, "entMD5File", "block-md5.dat");
}


