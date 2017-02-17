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

#include <ctype.h>

#include "rdd.h"
#include "rdd_internals.h"
#include "rddgui.h"

/** \brief Disables the split size input widgets when the user
 *  indicates that he wants his output in a single file.
 */
static gboolean
allbytes_toggled(GtkWidget *wdgt, gpointer data)
{
	RDD_WIZWIN *ww = (RDD_WIZWIN *) data;
	static const char *names[] = {"entBytesToRead", "cboBytesToRead"};

	rddgui_widgets_set_sensitive(ww, names, (sizeof names)/sizeof(char*),
					FALSE);
	return TRUE;
}

/** \brief Enables the split size input widgets when the user
 *  indicates that he wants to split his output.
 */
static gboolean
bytestoread_toggled(GtkWidget *wdgt, gpointer data)
{
	RDD_WIZWIN *ww = (RDD_WIZWIN *) data;
	static const char *names[] = {"entBytesToRead", "cboBytesToRead"};

	rddgui_widgets_set_sensitive(ww, names, (sizeof names)/sizeof(char*),
					TRUE);
	return TRUE;
}

static void
inputadv_init(RDD_WIZWIN *ww)
{
	ww->help = "rddgui.html#input-advanced";

	glade_xml_signal_connect_data(ww->xml, "on_radAllBytes_toggled",
			G_CALLBACK(allbytes_toggled), ww);
	glade_xml_signal_connect_data(ww->xml, "on_radBytesToRead_toggled",
			G_CALLBACK(bytestoread_toggled), ww);

	rddgui_radio_select(ww, "radAllBytes");

	rddgui_set_multnum(ww, ww->opts->block_size,
			"entBlocksize", "cboBlocksize");
}

int
inputadv_next(RDD_WIZWIN *ww)
{
	int rc = RDD_OK;

	/* How much should we read?
	 */
	if (rddgui_radio_selected(ww, "radBytesToRead")) {
		rc = rddgui_get_multnum(ww,
				"bytes to read", "entBytesToRead", 
				"cboBytesToRead", &ww->opts->count);
		if (rc != RDD_OK) {
			return 0;
		}
	} else {
		ww->opts->count = RDD_WHOLE_FILE;
	}

	/* Block size.
	 */
	rc = rddgui_get_multnum(ww, "block size", "entBlocksize", 
					"cboBlocksize", &ww->opts->block_size);
	if (rc != RDD_OK) {
		return 0;
	}

	/* Offset.
	 */
	rc = rddgui_get_multnum(ww, "offset", "entOffset", "cboOffset",
			&ww->opts->offset);
	if (rc != RDD_OK) {
		return 0;
	}

	ww->next = 0;
	return 1;
}

RDD_WIZWIN_OPS rddgui_inputadv_ops = {
	inputadv_init,
	inputadv_next,
	0
};
