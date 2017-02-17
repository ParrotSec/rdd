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
#include "rddgui.h"

static char *
about_message = "rdd-gui version " VERSION "\n"
		"Netherlands Forensic Institute\n"
		"The Hague, The Netherlands\n";

static GtkWidget *logwin;
static GtkWidget *canvas;
static GdkGC *gcontext;

static gboolean
new_image_clicked(GtkWidget *widget, gpointer data)
{
	/* write log message to logwin */
	return TRUE;
}

static gboolean
quit_clicked(GtkWidget *widget, gpointer data)
{
	/* Ask for confirmation? */
	gtk_main_quit();
	return TRUE;
}

static gboolean
about_clicked(GtkWidget *widget, gpointer data)
{
	rddgui_info(0, "%s", about_message);
	return TRUE;
}

static gint
canvas_exposed(GtkWidget *widget, GdkEventExpose *event, gpointer data)
{
	int w, h;
	int i;

	gdk_window_get_geometry(widget->window, NULL, NULL, &w, &h, NULL);

	printf("%u x %u\n", w, h);

	for (i = 0; i < w; i++) {
		gdk_draw_point(widget->window, gcontext, i, (h*i)/h);
	}

	return 0;
}

static void
rddgui_winmain_run(void)
{
	GladeXML *xml;
	GtkWidget *mainwin;

	printf("XML\n");
	xml = glade_xml_new(rddgui_xml_path, "winMain", NULL);
	printf("WIDGET GET MAIN\n");
	mainwin = glade_xml_get_widget(xml, "winMain");
	printf("WIDGET GET LOG\n");
	logwin = glade_xml_get_widget(xml, "txtLog");
	canvas = glade_xml_get_widget(xml, "canvas");

	gtk_drawing_area_size(GTK_DRAWING_AREA(canvas), 100, 100);

	gcontext = gdk_gc_new(canvas->window);

	printf("HIDE\n");
	gtk_widget_hide_all(mainwin);
	printf("CONNECT\n");

	glade_xml_signal_connect_data(xml, "on_quit_clicked",
			G_CALLBACK(quit_clicked), mainwin);
	glade_xml_signal_connect_data(xml, "on_about_clicked",
			G_CALLBACK(about_clicked), mainwin);
	glade_xml_signal_connect_data(xml, "on_canvas_expose_event",
			G_CALLBACK(canvas_exposed), canvas);

	printf("SHOW\n");
	gtk_widget_show_all(mainwin);

	printf("MAIN\n");
	gtk_main();
}

int
main(int argc, char **argv)
{
	gtk_init(&argc, &argv);
	glade_init();
	printf("RUN\n");
	rddgui_winmain_run();
	return 0;
}
