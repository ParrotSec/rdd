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

#include "rdd.h"
#include "rddgui.h"

#define SPLASH_TIMEOUT 10000 /* milliseconds */

static gboolean
splash_timeout(gpointer data)
{
	GtkDialog *splash = GTK_DIALOG(data);

	/* A timeout occurred. Act as though the user
	 * pressed the OK/close button.
	 */
	gtk_dialog_response(splash, GTK_RESPONSE_OK);

	return FALSE;
}

void
rddgui_splash(const char *path)
{
	GladeXML *xml = 0;
	GtkWidget *splash = 0;
	GtkWidget *version_label = 0;
	guint timeout_id;
	gint result;
	gchar version[255];

	xml = glade_xml_new(path, "dlgSplash", NULL);
	splash = glade_xml_get_widget(xml, "dlgSplash");

	version_label = glade_xml_get_widget(xml, "lblVersion");
	sprintf(version, "%s %s", "rdd-gui", VERSION);
	gtk_label_set_text(version_label, version);

	timeout_id = gtk_timeout_add(SPLASH_TIMEOUT,
			splash_timeout, GTK_DIALOG(splash));

	result = gtk_dialog_run(GTK_DIALOG(splash));

	gtk_widget_destroy(splash);
	gtk_timeout_remove(timeout_id);
}
