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

#include <string.h>
#include <sys/stat.h>

#include <gtk/gtk.h>

#include "rdd.h"
#include "rddgui.h"
#include "rdd_internals.h"
#include "msgprinter.h"

typedef struct _RDD_GUILOG_MSGPRINTER {
	GtkTextBuffer *textbuf;
	GtkTextTag    *info_tag;
	GtkTextTag    *warn_tag;
	GtkTextTag    *debug_tag;
	GtkTextTag    *error_tag;
	gint           maxline;
} RDD_GUILOG_MSGPRINTER;

static void guilog_print(RDD_MSGPRINTER *printer,
		rdd_message_t type, int errcode, const char *msg);
static int  guilog_close(RDD_MSGPRINTER *printer, unsigned flags);

static RDD_MSGPRINTER_OPS guilog_ops = {
	guilog_print,
	guilog_close
};

int
rdd_mp_open_guilog_printer(RDD_MSGPRINTER **printer, GtkTextBuffer *textbuf)
{	
	RDD_GUILOG_MSGPRINTER *gui = 0;
	RDD_MSGPRINTER *p = 0;
	int rc = RDD_OK;
	GtkTextIter start;
	GtkTextIter end;

	rc = rdd_mp_open_printer(&p, &guilog_ops, sizeof(RDD_GUILOG_MSGPRINTER));
	if (rc != RDD_OK) {
		goto error;
	}

	gui = (RDD_GUILOG_MSGPRINTER *) p->state;
	gui->textbuf = textbuf;
	gui->maxline = 1000;
	gui->info_tag = gtk_text_buffer_create_tag(textbuf, "info",
				"foreground", "black", NULL);
	gui->warn_tag = gtk_text_buffer_create_tag(textbuf, "warn",
				"foreground", "blue", NULL);
	gui->debug_tag = gtk_text_buffer_create_tag(textbuf, "debug",
				"foreground", "brown", NULL);
	gui->error_tag = gtk_text_buffer_create_tag(textbuf, "error",
				"foreground", "red", NULL);

	/* Delete all text in the text buffer.
	 */
	gtk_text_buffer_get_start_iter(textbuf, &start);
	gtk_text_buffer_get_end_iter(textbuf, &end);
	gtk_text_buffer_delete(textbuf, &start, &end);

	*printer = p;
	return RDD_OK;

error:
	*printer = 0;
	if (gui != 0) free(gui);
	return rc;
}

static void
guilog_print(RDD_MSGPRINTER *printer, rdd_message_t type, int errcode,
	const char *msg)
{
	RDD_GUILOG_MSGPRINTER *gui = (RDD_GUILOG_MSGPRINTER *) printer->state;
	GtkTextBuffer *textbuf = gui->textbuf;
	GtkTextIter end;
	GtkTextTag *tag;
	gint nline;
       
	switch (type) {
	case RDD_MSG_INFO:
		tag = gui->info_tag;
		break;
	case RDD_MSG_WARN:
		tag = gui->warn_tag;
		break;
	case RDD_MSG_DEBUG:
		tag = gui->debug_tag;
		break;
	case RDD_MSG_ERROR:
		tag = gui->error_tag;
		break;
	default:
		return;
	}

	nline = gtk_text_buffer_get_line_count(textbuf);

	if (nline >= gui->maxline) {
		/* Too many lines; delete the oldest line.
		 */
		GtkTextIter line0;
		GtkTextIter line1;

		gtk_text_buffer_get_iter_at_line(textbuf, &line0, 0);
		gtk_text_buffer_get_iter_at_line(textbuf, &line1, 1);

		gtk_text_buffer_delete(textbuf, &line0, &line1);
	}

	/* Append new line.
	 */
	gtk_text_buffer_get_end_iter(textbuf, &end);
	gtk_text_buffer_insert_with_tags(textbuf, &end, msg, strlen(msg),
						tag, NULL);
	gtk_text_buffer_insert_at_cursor(textbuf, "\n", 1);
}

static int
guilog_close(RDD_MSGPRINTER *printer, unsigned flags)
{
	RDD_GUILOG_MSGPRINTER *gui = (RDD_GUILOG_MSGPRINTER *) printer->state;

	memset(gui, 0, sizeof *gui);

	return RDD_OK;
}
