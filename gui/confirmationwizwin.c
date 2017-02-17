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

static void set_values(RDD_WIZWIN *ww);

static void
confirmation_dialog_shown(GtkWidget *widget, gpointer data)
{
	set_values((RDD_WIZWIN *) data);
}

static void
confirmation_init(RDD_WIZWIN *ww)
{
	set_values(ww);

	ww->help = "rddgui.html#confirmation";
	rddgui_focus(ww, "butFinish");

	glade_xml_signal_connect_data(ww->xml, "on_dlgConfirmation_show",
			G_CALLBACK(confirmation_dialog_shown), ww);
}

static int
confirmation_next(RDD_WIZWIN *ww)
{
	ww->next = 0;
	return 1;
}

RDD_WIZWIN_OPS rddgui_confirmation_ops = {
	confirmation_init,
	confirmation_next,
	0
};

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

static void
set_sensitive(RDD_WIZWIN *ww, const char *name, int sensitive)
{
	GtkWidget *widget;

	widget = glade_xml_get_widget(ww->xml, name);
	gtk_widget_set_sensitive(widget, sensitive ? TRUE : FALSE);
}

static void
set_na_label(RDD_WIZWIN *ww, char *label)
{
	set_label_text(ww->xml, label, "N/A");
	set_sensitive(ww, label, 0);
}

static void
set_path_label(RDD_WIZWIN *ww, char *label, char *path)
{
	if (path != 0) {
		set_label_text(ww->xml, label, "%s", path);
		set_sensitive(ww, label, 1);
	} else {
		set_na_label(ww, label);
	}
}

static void
set_bool_label(RDD_WIZWIN *ww, char *label, int val)
{
	set_label_text(ww->xml, label, "%s", val ? "yes" : "no");
}

static void
hide_widget(RDD_WIZWIN *ww, const char *name)
{
	GtkWidget *widget;

	widget = glade_xml_get_widget(ww->xml, name);
	gtk_widget_hide(widget);
}

static void
set_values(RDD_WIZWIN *ww)
{
	RDDGUI_OPTS *opts = ww->opts;

	/* Input options
	 */
	set_path_label(ww, "lblInput", opts->input_path);
	set_label_text(ww->xml, "lblInputSize", "%lld", opts->input_size);
	set_label_text(ww->xml, "lblRead", "%lld", opts->count);
	set_label_text(ww->xml, "lblBlockSize", "%lld", opts->block_size);
	set_label_text(ww->xml, "lblOffset", "%lld", opts->offset);

	/* Output options
	 */
	set_path_label(ww, "lblOutput", opts->output_path);
	set_path_label(ww, "lblLogfile", opts->log_path);
	if (opts->split_output) {
		set_label_text(ww->xml, "lblSegmentSize",
				"%lld", opts->split_size);
		set_sensitive(ww, "lblSegmentSize", 1);
		set_sensitive(ww, "lblSegmentSizeBytes", 1);
	} else {
		set_na_label(ww, "lblSegmentSize");
		hide_widget(ww, "lblSegmentSizeBytes");
	}
	
	/* Integrity options
	 */
	set_bool_label(ww, "lblMD5", opts->md5_stream_filter);
	set_bool_label(ww, "lblSHA1", opts->sha1_stream_filter);

	if (opts->enable_adler32) {
		set_label_text(ww->xml, "lblAdlerBlockSize", "%lld", 
				opts->adler32_block_size);
		set_sensitive(ww, "lblAdlerBlockSize", 1);
		set_sensitive(ww, "lblAdlerBlockSizeBytes", 1);
		set_path_label(ww, "lblAdlerFile", opts->adler32_path);
	} else {
		set_na_label(ww, "lblAdlerBlockSize");
		hide_widget(ww, "lblAdlerBlockSizeBytes");
		set_na_label(ww, "lblAdlerFile");
	}

	if (opts->enable_crc32) {
		set_label_text(ww->xml, "lblCRCBlockSize", "%lld", 
				opts->crc32_block_size);
		set_sensitive(ww, "lblCRCBlockSize", 1);
		set_sensitive(ww, "lblCRCBlockSizeBytes", 1);
		set_path_label(ww, "lblCRCFile", opts->crc32_path);
		set_sensitive(ww, "lblCRCFile", 1);
	} else {
		set_na_label(ww, "lblCRCBlockSize");
		hide_widget(ww, "lblCRCBlockSizeBytes");
		set_na_label(ww, "lblCRCFile");
	}
	
	/* Recovery options
	 */
	if (opts->enable_recovery) {
		set_label_text(ww->xml, "lblRetryBlockSize", "%lld", 
				opts->retry_block_size);
		set_sensitive(ww, "lblRetryBlockSize", 1);
		set_sensitive(ww, "lblRetryBlockSizeBytes", 1);
		set_label_text(ww->xml, "lblDrop", "%u", opts->max_retry_count);
		set_sensitive(ww, "lblDrop", 1);
		set_sensitive(ww, "lblDropRetries", 1);

		set_sensitive(ww, "lblGiveUp", 1);
		set_sensitive(ww, "lblGiveUpBlocks", 1);

		if (opts->never_give_up) {
			set_label_text(ww->xml, "lblGiveUpLabel", "Give up:");
			set_label_text(ww->xml, "lblGiveUp", "never");
			set_label_text(ww->xml, "lblGiveUpBlocks", "");
		} else {
			set_label_text(ww->xml, "lblGiveUpLabel", 
							"Give up after:");
			set_label_text(ww->xml, "lblGiveUp", "%u",
					opts->max_drop_count);
			set_label_text(ww->xml, "lblGiveUpBlocks", 
							"blocks dropped");
		}
	} else {
		set_na_label(ww, "lblRetryBlockSize");
		hide_widget(ww, "lblRetryBlockSizeBytes");
		set_na_label(ww, "lblDrop");
		hide_widget(ww, "lblDropRetries");
		set_label_text(ww->xml, "lblGiveUpLabel", "Give up after:");
		set_na_label(ww, "lblGiveUp");
		hide_widget(ww, "lblGiveUpBlocks");
	}

	/* Statistical options
	 */
	if (opts->enable_stats) {
		if (opts->enable_entropy) {
			set_label_text(ww->xml, "lblEntropyBlockSize", "%lld", 
					opts->entropy_block_size);
			set_sensitive(ww, "lblEntropyBlockSize", 1);
			set_path_label(ww, "lblEntropyFile", 
							opts->entropy_path);
		} else {
			set_na_label(ww, "lblEntropyBlockSize");
			hide_widget(ww, "lblEntropyBlockSizeBytes");
			set_na_label(ww, "lblEntropyFile");
		}

		if (opts->enable_blockmd5) {
			set_label_text(ww->xml, "lblBlockMD5BlockSize", "%lld", 
					opts->blockmd5_block_size);
			set_sensitive(ww, "lblBlockMD5BlockSize", 1);
			set_path_label(ww, "lblBlockMD5File", 
							opts->blockmd5_path);
		} else {
			set_na_label(ww, "lblBlockMD5BlockSize");
			hide_widget(ww, "lblBlockMD5BlockSizeBytes");
			set_na_label(ww, "lblBlockMD5File");
		}
	} else {
		set_na_label(ww, "lblEntropyBlockSize");
		hide_widget(ww, "lblEntropyBlockSizeBytes");
		set_na_label(ww, "lblEntropyFile");

		set_na_label(ww, "lblBlockMD5BlockSize");
		hide_widget(ww, "lblBlockMD5BlockSizeBytes");
		set_na_label(ww, "lblBlockMD5File");
	}
}
