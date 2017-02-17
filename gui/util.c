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
#include <limits.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <libgen.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>

#include "rdd.h"
#include "rdd_internals.h"
#include "numparser.h"
#include "rddgui.h"

#define KILOBYTE 1024
#define MEGABYTE (KILOBYTE * KILOBYTE)
#define GIGABYTE (KILOBYTE * KILOBYTE * KILOBYTE)

static void
show_message(GtkWindow *parent, GtkButtonsType buttons,
	const char *fmt, va_list ap)
{
	GtkWidget *dialog;
	char buf[256];

	vsnprintf(buf, sizeof buf, fmt, ap);

	dialog = gtk_message_dialog_new(parent, GTK_DIALOG_DESTROY_WITH_PARENT,
					  buttons, GTK_BUTTONS_CLOSE, buf);
	gtk_dialog_run(GTK_DIALOG(dialog));
	gtk_widget_destroy(dialog);
}

void
rddgui_fatal(GtkWindow *parent, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	show_message(parent, GTK_MESSAGE_ERROR, fmt, ap);
	va_end(ap);

	exit(EXIT_FAILURE);
}

void
rddgui_error(GtkWindow *parent, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	show_message(parent, GTK_MESSAGE_ERROR, fmt, ap);
	va_end(ap);
}

void
rddgui_warn(GtkWindow *parent, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	show_message(parent, GTK_MESSAGE_WARNING, fmt, ap);
	va_end(ap);
}

void
rddgui_info(GtkWindow *parent, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	show_message(parent, GTK_MESSAGE_INFO, fmt, ap);
	va_end(ap);
}

int
rddgui_yesno_dialog(GtkWindow *parent, const char *fmt, ...)
{
	GtkWidget *dialog;
	va_list ap;
	char buf[256];
	gint answer = GTK_RESPONSE_NONE;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof buf, fmt, ap);
	va_end(ap);

	dialog = gtk_message_dialog_new(parent,
			  GTK_DIALOG_DESTROY_WITH_PARENT,
			  GTK_MESSAGE_QUESTION,
			  GTK_BUTTONS_YES_NO,
			  buf);
	answer = gtk_dialog_run(GTK_DIALOG(dialog));
	gtk_widget_destroy(dialog);

	return (answer == GTK_RESPONSE_YES ? 1 : 0);
}

int
rddgui_radio_selected(RDD_WIZWIN *ww, const char *name)
{
	GtkWidget *w = glade_xml_get_widget(ww->xml, name);

	return gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(w)) ? 1 : 0;
}

void
rddgui_radio_select(RDD_WIZWIN *ww, const char *name)
{
	GtkWidget *w = glade_xml_get_widget(ww->xml, name);

	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w), TRUE);
}

char *
rddgui_get_text(RDD_WIZWIN *ww, const char *name, int copy)
{
	GtkWidget *w = glade_xml_get_widget(ww->xml, name);
	const char *txt;
	char *cpy;

	txt = gtk_entry_get_text(GTK_ENTRY(w));

	if (txt == 0 || !copy) return (char *) txt;

	if ((cpy = malloc(strlen(txt) + 1)) == 0) {
		rddgui_fatal(GTK_WINDOW(ww), "Out of memory");
	}
	strcpy(cpy, txt);
	return cpy;
}

void
rddgui_set_text(RDD_WIZWIN *ww, const char *name, const char *text)
{
	GtkWidget *w = glade_xml_get_widget(ww->xml, name);

	gtk_entry_set_text(GTK_ENTRY(w), text);
}

int
rddgui_get_checked(RDD_WIZWIN *ww, const char *name)
{
	GtkWidget *w = glade_xml_get_widget(ww->xml, name);

	return gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(w)) ? 1 : 0;
}

int
rddgui_get_uint(RDD_WIZWIN *ww, const char *label, const char *name,
	unsigned *num)
{
	GtkWidget *num_wdgt = glade_xml_get_widget(ww->xml, name);
	rdd_count_t n = 0;
	int rc = RDD_OK;

	rc = rdd_parse_bignum(
		gtk_entry_get_text(GTK_ENTRY(num_wdgt)), 0, &n);
	if (rc != RDD_OK) {
		rddgui_error(GTK_WINDOW(ww->window), "Bad %s", label);
		return rc;
	}

	if (n >= UINT_MAX) {
		rddgui_error(GTK_WINDOW(ww->window), "Number too large");
		return RDD_ERANGE;
	}

	*num = (unsigned) n;
	return RDD_OK;
}

void
rddgui_set_uint(RDD_WIZWIN *ww, const char *entryname, unsigned num)
{
	GtkWidget *num_wdgt = glade_xml_get_widget(ww->xml, entryname);
	char buf[32];

	snprintf(buf, (sizeof buf) - 1, "%u", num);
	buf[(sizeof buf) - 1] = '\000';

	gtk_entry_set_text(GTK_ENTRY(num_wdgt), buf);
}

int
rddgui_get_multnum(RDD_WIZWIN *ww, const char *label,
	const char *num, const char *mult,
	rdd_count_t *np)
{
	GtkWidget *num_wdgt = glade_xml_get_widget(ww->xml, num);
	GtkWidget *mult_cbo = glade_xml_get_widget(ww->xml, mult);
	rdd_count_t n = 0;
	const char *m = 0;
	int rc = RDD_OK;
	const char *numtext = gtk_entry_get_text(GTK_ENTRY(num_wdgt));

	if (numtext == 0 || strlen(numtext) == 0) {
		rddgui_error(GTK_WINDOW(ww->window), "Empty %s field", label);
		return RDD_ESYNTAX;
	}
	
	rc = rdd_parse_bignum(numtext, 0, &n);
	if (rc != RDD_OK) {
		rddgui_error(GTK_WINDOW(ww->window), "Bad number in the %s "
							"field", label);
		return rc;
	}

	m = gtk_entry_get_text(GTK_ENTRY(GTK_COMBO(mult_cbo)->entry));
	
	if (tolower(m[0]) == 'b') {
		/* multiply by 1 */
	} else if (tolower(m[0]) == 'k') {
		n *= 1 << 10;
	} else if (tolower(m[0]) == 'm') {
		n *= 1 << 20;
	} else if (tolower(m[0]) == 'g') {
		n *= 1 << 30;
	} else {
		rddgui_fatal(GTK_WINDOW(ww->window), "Bad multiplier");
	}

	*np = n;
	return RDD_OK;
}

void
rddgui_set_multnum(RDD_WIZWIN *ww, rdd_count_t n,
		const char *numname, const char *multname)
{
	GtkWidget *mult_cbo = glade_xml_get_widget(ww->xml, multname);
	rdd_count_t entry_value = 0;
	char entry_buf[32];
	char *multiplier = 0;

	if (n / GIGABYTE > 0 && n % GIGABYTE == 0) {
		entry_value = n / GIGABYTE;
		multiplier = "GB";
	} else if (n / MEGABYTE > 0 && n % MEGABYTE == 0) {
		entry_value = n / MEGABYTE;
		multiplier = "MB";
	} else if (n / KILOBYTE > 0 && n % KILOBYTE == 0) {
		entry_value = n / KILOBYTE;
		multiplier = "kB";
	} else {
		entry_value = n;
		multiplier = "bytes";
	}

	snprintf(entry_buf, (sizeof entry_buf) - 1, "%llu", entry_value);
	entry_buf[(sizeof entry_buf) - 1] = '\000'; /* always null-terminate */
	rddgui_set_text(ww, numname, entry_buf);

	gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(mult_cbo)->entry), multiplier);
}

void
rddgui_widgets_set_sensitive(RDD_WIZWIN *ww,
	const char **names, unsigned nname, gboolean sensitive)
{
	GtkWidget *widget = 0;
	unsigned i = 0;

	for (i = 0; i < nname; i++) {
		widget = glade_xml_get_widget(ww->xml, names[i]);
		if (widget != 0) {
			gtk_widget_set_sensitive(widget, sensitive);
		}
	}
}

void
rddgui_focus(RDD_WIZWIN *ww, const char *name)
{
	GtkWidget *wdgt = glade_xml_get_widget(ww->xml, name);

	gtk_widget_grab_focus(wdgt);
}

int
rddgui_get_dir(const char *path, char *dir){

	char copy[RDDGUI_MAX_FILENAME_SIZE];
	int rc;
	struct stat pathinfo;	
	
	rc = stat(path, &pathinfo);

	/* Ignore stat errors. It is normal that output files do 
	 * not exist yet.
	 */
	if (rc == 0) {
		if (S_ISDIR(pathinfo.st_mode)) {
			/* path is already a dir. Just copy.
			 */
			sprintf(dir, "%s", path);
			return 1;
		}
	}

	/* Function dirname changes the argument!
	 */
	if (strlen(path) < RDDGUI_MAX_FILENAME_SIZE) {
		strcpy(copy, path);
		sprintf(dir, "%s", dirname(copy));
		return 1;
	} else {
		sprintf(dir, "");
		return 0;
	}
	
}

void
build_part_path(RDD_WIZWIN *ww, char *widget, char *filename)
{

	GtkWidget *wdg;
	gchar *path;
	char *dir;
	char new_path[RDDGUI_MAX_FILENAME_SIZE];
	int ret;

	/* If the entry for the entropy file is empty, make up a name
	 * from the log file path and a filename.
	 */
	wdg = glade_xml_get_widget(ww->xml, widget);
	path = (gchar *)gtk_entry_get_text(GTK_ENTRY(wdg));
	
	if (! path) {
		path = "";
	}

	if (strlen(path) == 0) {
		if (rddgui_get_dir(ww->opts->log_path, dir)) {
			
			if (strlen(dir) < (RDDGUI_MAX_FILENAME_SIZE - 11)) {
				sprintf(new_path, "%s/%s", dir, filename);
				gtk_entry_set_text(GTK_ENTRY(wdg), 
							(gchar *)new_path);
			} else {
				gtk_entry_set_text(GTK_ENTRY(wdg), (gchar *)"");
			}
		} else {
			gtk_entry_set_text(GTK_ENTRY(wdg), (gchar *)"");
		}
	}
}

