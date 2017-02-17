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
#include <unistd.h>

#include "rdd.h"
#include "rddgui.h"

static int get_advanced(RDD_WIZWIN *ww);
static void set_values(RDD_WIZWIN *ww);

static void
integrityadv_dialog_shown(GtkWidget *widget, gpointer data)
{
	set_values((RDD_WIZWIN *) data);
}

static void
integrity_init(RDD_WIZWIN *ww)
{
	ww->help = "rddgui.html#integrity";
	ww->advanced = rddgui_integrityadv_win;

	rddgui_focus(ww, "butNext");
}

static int
integrity_next(RDD_WIZWIN *ww)
{
	RDDGUI_OPTS *opts = ww->opts;

       	opts->md5_stream_filter = rddgui_get_checked(ww, "chkMD5");
       	opts->sha1_stream_filter = rddgui_get_checked(ww, "chkSHA1");

	if (! get_advanced(ww->advanced)) {
		return 0;
	}

	ww->next = rddgui_recovery_win;
	return 1;
}

static void
integrity_advanced(RDD_WIZWIN *ww)
{
	ww->advanced = rddgui_integrityadv_win;
}

RDD_WIZWIN_OPS rddgui_integrity_ops = {
	integrity_init,
	integrity_next,
	integrity_advanced
};



static gboolean
adler32_toggled(GtkWidget *wdgt, gpointer data)
{
	RDD_WIZWIN *ww = (RDD_WIZWIN *) data;
	const char *widget_names[] = {
		"entAdlerBlocksize",
		"cboAdler",
		"entAdlerFile",
		"butAdler"
	};
	gboolean onoff = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(wdgt));

	rddgui_widgets_set_sensitive(ww,
			widget_names, (sizeof widget_names) / sizeof(char *),
			onoff);
	return TRUE;
}

static gboolean
crc32_toggled(GtkWidget *wdgt, gpointer data)
{
	RDD_WIZWIN *ww = (RDD_WIZWIN *) data;
	const char *widget_names[] = {
		"entCRCBlocksize",
		"cboCRC",
		"entCRCFile",
		"butCRC"
	};
	gboolean onoff = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(wdgt));

	rddgui_widgets_set_sensitive(ww,
			widget_names, (sizeof widget_names) / sizeof(char *),
			onoff);
	return TRUE;
}

static void
integrityadv_init(RDD_WIZWIN *ww)
{
	ww->help = "rddgui.html#integrity-advanced";

	glade_xml_signal_connect_data(ww->xml, "on_chkAdler_toggled",
			G_CALLBACK(adler32_toggled), ww);
	glade_xml_signal_connect_data(ww->xml, "on_chkCRC_toggled",
			G_CALLBACK(crc32_toggled), ww);

	glade_xml_signal_connect_data(ww->xml, "on_dlgIntegrityAdv_show",
			G_CALLBACK(integrityadv_dialog_shown), ww);
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

	if (opts->adler32_path != 0) {
		free(opts->adler32_path);
		opts->adler32_path = 0;
	}
	if (opts->crc32_path != 0) {
		free(opts->crc32_path);
		opts->crc32_path = 0;
	}

	opts->enable_adler32 = rddgui_get_checked(ww, "chkAdler");
	if (opts->enable_adler32) {
		if (! get_path_and_block_size(ww,
			"Adler32 block size", "entAdlerBlocksize", "cboAdler",
			&opts->adler32_block_size,
			"Adler-32 output file", "entAdlerFile",
			&opts->adler32_path)) {
			return 0;
		}
	} else {
		opts->adler32_block_size = 0;
		opts->adler32_path = 0;
	}


	opts->enable_crc32 = rddgui_get_checked(ww, "chkCRC");
	if (opts->enable_crc32) {
		if (! get_path_and_block_size(ww,
			"CRC32 block size", "entCRCBlocksize", "cboCRC",
			&opts->crc32_block_size,
			"CRC32 output file", "entCRCFile",
			&opts->crc32_path))
		{
			return 0;
		}
	} else {
		opts->crc32_block_size = 0;
		opts->crc32_path = 0;
	}


	return 1;
}

static int
integrityadv_next(RDD_WIZWIN *ww)
{
	if (! get_advanced(ww)) {
		return 0;
	}

	ww->next = 0;
	return 1;
}

RDD_WIZWIN_OPS rddgui_integrityadv_ops = {
	integrityadv_init,
	integrityadv_next,
	0
};

static void
set_values(RDD_WIZWIN *ww)
{
	build_part_path(ww, "entAdlerFile", "adler32.dat");
	build_part_path(ww, "entCRCFile", "crc32.dat");
}


