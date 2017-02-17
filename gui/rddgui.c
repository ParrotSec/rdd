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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gtk/gtk.h>
#include <glade/glade.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_PWD_H
#include <pwd.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_UTSNAME_H
#include <sys/utsname.h>
#endif

#include "rdd.h"
#include "rdd_internals.h"
#include "reader.h"
#include "writer.h"
#include "filter.h"
#include "filterset.h"
#include "copier.h"
#include "error.h"
#include "msgprinter.h"
#include "rddgui.h"

#if defined(HAVE_LIBCRYPTO) && defined(HAVE_OPENSSL_CRYPTO_H)
#include <openssl/crypto.h>
#endif

#define MAX_ENTROPY_POINTS 1000

typedef struct _RDDGUI_IMAGINGWIN {
	struct {
		const char  *help;		/* help page */
		rdd_count_t  size;		/* input size (bytes) */
		rdd_count_t  pos;		/* current position (bytes) */
		time_t       start;		/* start time */
		unsigned     elapsed;		/* elapsed time (secs) */
		int          cancelled;		/* copy cancelled flag */
		rdd_count_t  nreaderr;		/* read error count */
		rdd_count_t  nsubst;		/* substitution count */
		rdd_count_t  bytes_dropped;	/* #bytes substituted */
#if defined(PLOT_ENTROPY)
		double      *entropy_points;
		unsigned     next_point;
#endif
	} model;
	struct {
		GtkWidget   *win;		/* progress window */
		GtkWidget   *bar;		/* progress bar */
		GtkWidget   *elapsed;		/* elapsed-time label */
		GtkWidget   *readerrs;		/* read error count label */
		GtkWidget   *substs;		/* subst. count label */
		GtkWidget   *nbyte;		/* #bytes substituted label */
#if defined(PLOT_ENTROPY)
		GtkWidget   *canvas;		/* entropy plot */
#endif
		GtkWidget   *logwin;            /* log window */
	} view;
} RDDGUI_IMAGINGWIN;

#if defined(PLOT_ENTROPY)
static void add_entropy(unsigned blocknum, double entropy, void *data);
#endif

static RDD_MSGPRINTER *gui_printer = 0;
static RDD_MSGPRINTER *log_printer = 0;

static void
fatal_rddgui_error(int rc, char *fmt, ...)
{
	exit(EXIT_FAILURE);
}

static RDD_MSGPRINTER *
open_gui_printer(void)
{
	RDD_MSGPRINTER *printer = 0;
	int rc = RDD_OK;

	rc = rdd_mp_open_gui_printer(&printer);
	if (rc != RDD_OK) {
		rddgui_fatal(0, "cannot open GUI printer");
	}

	return printer;
}

static RDD_MSGPRINTER *
open_log_printer(const char *path, GtkWidget *logwin)
{
	RDD_MSGPRINTER *printers[2];
	RDD_MSGPRINTER *p1 = 0;
	RDD_MSGPRINTER *p2 = 0;
	RDD_MSGPRINTER *printer = 0;
	char hostname[128];
	int rc = RDD_OK;
	struct passwd *pwd = 0;
	struct utsname sysinfo;
	GtkTextBuffer *textbuf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(logwin));

	rc = rdd_mp_open_file_printer(&p1, path);
	if (rc != RDD_OK) {
		rddgui_fatal(0, "cannot open log file (%s)", path);
	}

	rc = rdd_mp_open_guilog_printer(&p2, textbuf);
	if (rc != RDD_OK) {
		rddgui_fatal(0, "cannot open log window");
	}

	printers[0] = p1;
	printers[1] = p2;

	rc = rdd_mp_open_bcast_printer(&printer, 2, printers);
	if (rc != RDD_OK) {
		rddgui_fatal(0, "cannot open broadcast printer");
	}

	rc = rdd_mp_open_log_printer(&printer, printer);
	if (rc != RDD_OK) {
		rddgui_fatal(0, "cannot stack log printer");
	}

	rdd_mp_message(printer, RDD_MSG_INFO, "%s", rdd_ctime());

	/* Rdd-gui version number.
	 */
	rdd_mp_message(printer, RDD_MSG_INFO, "rdd-gui version " VERSION);
	rdd_mp_message(printer, RDD_MSG_INFO, "Copyright (c) 2002 Nederlands "
					"Forensisch Instituut");

	/* GTK library version.
	 */
	rdd_mp_message(printer, RDD_MSG_INFO, "GTK+ library version %u.%u.%u",
		gtk_major_version, gtk_minor_version, gtk_micro_version);

#if defined(HAVE_LIBCRYPTO)
	rdd_mp_message(printer, RDD_MSG_INFO, "openssl version %s", 
					OPENSSL_VERSION_TEXT);
	rdd_mp_message(printer, RDD_MSG_INFO, 
					"Copyright (c) 1995-1998 Eric Young");
#else
	rdd_mp_message(printer, RDD_MSG_INFO, "NOT using openssl");
#endif

	/* Host name.
	 */
	if (gethostname(hostname, sizeof hostname) < 0) {
		rdd_mp_message(printer, RDD_MSG_INFO, "hostname: "
				"unknown (gethostname() failed)");
	} else {
		hostname[(sizeof hostname) - 1] = '\000';
		rdd_mp_message(printer, RDD_MSG_INFO, "hostname: %s", hostname);
	}

	/* Operating system.
	 */
	if (uname(&sysinfo) < 0) {
		rdd_mp_message(printer, RDD_MSG_INFO, "operating system: "
			"unknown (uname() failed)");
	} else {
		rdd_mp_message(printer, RDD_MSG_INFO,
			"operating system: %s version %s release %s",
			sysinfo.sysname, sysinfo.version, sysinfo.release);
	}

	/* User id and user name.
	 */
	rdd_mp_message(printer, RDD_MSG_INFO, "user id: %d", getuid());
	if ((pwd = getpwuid(getuid())) == 0) {
		rdd_mp_message(printer, RDD_MSG_INFO, "user name: "
				"unknown (getpwuid() failed)");
	} else {
		rdd_mp_message(printer, RDD_MSG_INFO, "user name: %s",
				pwd->pw_name);
	}

	return printer;
}

static void
close_printer(RDD_MSGPRINTER *printer, const char *printer_name)
{
	int rc;

	if (printer == 0) return;

	rc = rdd_mp_close(printer, RDD_MP_RECURSE|RDD_MP_READONLY);
	if (rc != RDD_OK) {
		rddgui_fatal(0, "cannot close %s printer", printer_name);
	}
}

static RDD_READER *
open_disk_input(rdd_count_t *inputlen)
{
	RDD_READER *reader = 0;
	int rc;

	rc = rdd_open_file_reader(&reader, rddgui_options.input_path,
			0 /* not raw */);
	if (rc != RDD_OK) {
		rdd_error(rc, "cannot open %s", rddgui_options.input_path);
	}
	if ((rc = rdd_reader_seek(reader, 0)) != RDD_OK) {
		rdd_error(rc, "cannot seek on %s", rddgui_options.input_path);
	}

	*inputlen = RDD_WHOLE_FILE;
	rc = rdd_device_size(rddgui_options.input_path, inputlen);
	if (rc != RDD_OK) {
		rdd_error(rc, "%s: cannot determine device size",
			rddgui_options.input_path);
	}

	return reader;
}

#if 0
static RDD_READER *
open_net_input(rdd_count_t *inputlen)
{
	RDD_READER *reader = 0;
	int server_sock = -1;
	unsigned flags;
	int fd = -1;
	int rc;

	*inputlen = RDD_WHOLE_FILE;

	/* In server mode, we read from the network */
	if (opts.inetd) {
		/* started by (x)inetd */
		fd = STDIN_FILENO;
	} else {
		rc = rdd_init_server(opts.server_port, &server_sock);
		if (rc != RDD_OK) {
			rdd_error(rc, "cannot start rdd-copy server");
		}
		fd = rdd_await_connection(server_sock);
	}

	rc = rdd_open_fd_reader(&reader, fd);
	if (rc != RDD_OK) {
		rdd_error(rc, "cannot open reader on server socket");
	}

	rc = rdd_recv_info(reader, &opts.outpath, inputlen,
			&opts.blocklen, &opts.splitlen, &flags);
	if (rc != RDD_OK) {
		rdd_error(rc, "bad client request");
	}

	if (opts.verbose) {
		errlognl("Received rdd request:");
		errlognl("\tfile name:   %s", opts.outpath);
		errlognl("\tfile size:   %s", rdd_strsize(*inputlen));
		errlognl("\tblock size:  %llu", opts.blocklen);
		errlognl("\tsplit size:  %llu", opts.splitlen);
	}

#if defined(DEBUG)
	errlognl("file=%s size=%llu bsize=%llu splitsize=%llu",
		opts.outpath, rdd_strsize(*filelen),
		*blocklen, *splitlen);
#endif
	if ((flags & RDD_NET_COMPRESS) != 0) {
		if ((rc = rdd_open_zlib_reader(&reader, reader)) != RDD_OK) {
			rdd_error(rc, "cannot open zlib reader");
		}
	}

	return reader;
}
#endif

/* Creates a reader stack that corresponds to the user's options.
 */
static RDD_READER *
open_input(rdd_count_t *inputlen)
{
	if (rddgui_options.mode == RDDGUI_SERVER) {
#if 0
		return open_net_input(inputlen);
#else
		return 0;
#endif
	} else {
		return open_disk_input(inputlen);
	}
}

static RDD_WRITER *
open_disk_output(rdd_count_t outputsize)
{
	RDD_WRITER *writer = 0;
	rdd_write_mode_t wrmode;
	int rc;

	if (rddgui_options.output_path == 0) return 0;

	wrmode = RDD_OVERWRITE;

	if (rddgui_options.split_output) {
		rc = rdd_open_part_writer(&writer,
					rddgui_options.output_path,
					outputsize,
					rddgui_options.split_size,
					wrmode);
		if (rc != RDD_OK) {
			rdd_error(rc, "cannot add multipart write filter");
		}
	} else {
		rc = rdd_open_safe_writer(&writer,
					rddgui_options.output_path,
					wrmode);
		if (rc != RDD_OK) {
			rdd_error(rc, "cannot add safe write filter");
		}
	}

	return writer;
}

#if 0
static RDD_WRITER *
open_net_output(rdd_count_t outputsize)
{
	RDD_WRITER *writer = 0;
	unsigned flags = 0;
	int rc;
	char *server = opts.server_host;
	unsigned port = opts.server_port;

	assert(opts.outpath != 0);

	rc = rdd_open_tcp_writer(&writer, server, port);
	if (rc != RDD_OK) {
		rdd_error(rc, "cannot connect to %s:%u", server, port);
	}

	flags = (opts.compress ? RDD_NET_COMPRESS : 0);
	rc = rdd_send_info(writer, opts.outpath, outputsize,
			opts.blocklen, opts.splitlen, flags);
	if (rc != RDD_OK) {
		rdd_error(rc, "cannot send header to %s:%u", server, port);
	}

	if (opts.compress) {
		/* Stack a zlib writer on top of the TCP writer.
		 */
		rc = rdd_open_zlib_writer(&writer, writer);
		if (rc != RDD_OK) {
			rdd_error(rc, "cannot compress network traffic to "
				" %s:%u", server, port);
		}
	}

	return writer;
}
#endif

/** Creates a writer stack that corresponds to the user's options.
 *  The outputsize argument contains the size of the output in
 *  bytes if that size is known or RDD_WHOLE_FILE if is not known.
 */
static RDD_WRITER *
open_output(rdd_count_t outputsize)
{
	if (rddgui_options.mode == RDDGUI_CLIENT) {
#if 0
		return open_net_output(outputsize);
#else
		return 0;
#endif
	} else {
		return open_disk_output(outputsize);
	}
}

static void
add_filter(RDD_FILTERSET *fset, const char *name, RDD_FILTER *f)
{
	int rc;

	if ((rc = rdd_fset_add(fset, name, f)) != RDD_OK) {
		rddgui_fatal(0, "Cannot install %s filter", name);
	}
}

static void
install_stats_filters(RDD_FILTERSET *fset, RDDGUI_IMAGINGWIN *imgwin)
{
	RDD_FILTER *f;
	int rc;

	/* MD5
	 */
	f = 0;
	if (rddgui_options.enable_blockmd5) {
		rc = rdd_new_md5_blockfilter(&f,
				rddgui_options.blockmd5_block_size,
				rddgui_options.blockmd5_path,
				0 /* do not overwrite existing file */);
		if (rc != RDD_OK) {
			rddgui_fatal(0, "Cannot create MD5 block filter");
		}
		add_filter(fset, "MD5 block", f);
	}

	/* Entropy
	 */
	f = 0;
	if (rddgui_options.enable_entropy) {
		rc = rdd_new_stats_blockfilter(&f,
				rddgui_options.entropy_block_size,
				rddgui_options.entropy_path,
				0 /* do not overwrite existing file */);
		if (rc != RDD_OK) {
			rddgui_fatal(0, "Cannot create statistics block filter");
		}
		add_filter(fset, "statistical block", f);
#if defined(PLOT_ENTROPY)
		rc = rddgui_new_plotentropy_blockfilter(&f,
				rddgui_options.entropy_block_size,
				add_entropy, imgwin);
		if (rc != RDD_OK) {
			rddgui_fatal(0, "Cannot create entropy-plot block filter");
		}
		add_filter(fset, "entropy-plot block", f);
#endif
	}
}

static void
install_filters(RDD_FILTERSET *fset, RDD_WRITER *writer,
	RDDGUI_IMAGINGWIN *imgwin)
{
	RDD_FILTER *f = 0;
	RDDGUI_OPTS *opts = &rddgui_options;
	int rc;

	if ((rc = rdd_fset_init(fset)) != RDD_OK) {
		rdd_error(rc, "cannot create filter fset");
	}

	if (writer != 0) {
		rc = rdd_new_write_streamfilter(&f, writer);
		if (rc != RDD_OK) {
			rdd_error(rc, "cannot create write filter");
		}
		add_filter(fset, "write", f);
	}

	if (opts->md5_stream_filter) {
		rc = rdd_new_md5_streamfilter(&f);
		if (rc != RDD_OK) {
			rddgui_error(0, "cannot create MD5 filter");
		}
		add_filter(fset, "MD5 stream", f);
	}

	if (opts->sha1_stream_filter) {
		rc = rdd_new_sha1_streamfilter(&f);
		if (rc != RDD_OK) {
			rddgui_error(0, "cannot create SHA-1 filter");
		}
		add_filter(fset, "SHA-1 stream", f);
	}

	if (opts->enable_adler32) {
		rc = rdd_new_adler32_blockfilter(&f,
				opts->adler32_block_size, opts->adler32_path,
				RDD_OVERWRITE);
		if (rc != RDD_OK) {
			rddgui_error(0, "cannot create Adler32 filter");
		}
		add_filter(fset, "Adler32 block", f);
	}

	if (opts->enable_crc32) {
		rc = rdd_new_crc32_blockfilter(&f,
				opts->crc32_block_size, opts->crc32_path,
				RDD_OVERWRITE);
		if (rc != RDD_OK) {
			rddgui_error(0, "cannot create CRC-32 filter");
		}
		add_filter(fset, "CRC-32 block", f);
	}

	if (opts->enable_stats) {
		install_stats_filters(fset, imgwin);
	}
}

/** Updates the GUI by processing pending events. Quits when
 *  all events have been processed or when the user presses
 *  the 'Stop' button.
 */
static int
imgwin_update(RDDGUI_IMAGINGWIN *imgwin)
{
	gboolean quit = FALSE;

	while (gtk_events_pending()) {
		quit = gtk_main_iteration_do(FALSE);
#if 0
		if (quit) return RDD_ABORTED;
#endif
		/* Check whether user pressed the 'stop' button.
		 */
		if (imgwin->model.cancelled) return RDD_ABORTED;
	}

	return RDD_OK;
}

static void
draw_number(GtkWidget *w, rdd_count_t num)
{
	char buf[32];

	snprintf(buf, sizeof buf, "%llu", num);
	buf[(sizeof buf) - 1] = '\000';
	gtk_label_set_text(GTK_LABEL(w), buf);
}

static void
draw_progress(RDDGUI_IMAGINGWIN *imgwin)
{
	gdouble fraction;

	if (imgwin->model.size > 0) {
		fraction = ((gdouble) imgwin->model.pos) /
			   ((gdouble) imgwin->model.size);
	} else {
		fraction = 0.0;
	}
	gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(imgwin->view.bar),
				      fraction);
}

static void
draw_elapsed(RDDGUI_IMAGINGWIN *imgwin)
{
	unsigned hours =  imgwin->model.elapsed / 3600;
	unsigned mins  = (imgwin->model.elapsed % 3600) / 60;
	unsigned secs  =  imgwin->model.elapsed % 60;
	char buf[128];

	snprintf(buf, sizeof buf, "%3u hours %2.2u mins %2.2u secs",
		hours, mins, secs);
	gtk_label_set_text(GTK_LABEL(imgwin->view.elapsed), buf);
}

#if defined(PLOT_ENTROPY)
static void
add_entropy(unsigned blocknum, double entropy, void *data)
{
	RDDGUI_IMAGINGWIN *imgwin = (RDDGUI_IMAGINGWIN *) data;
	double *points = imgwin->model.entropy_points;

	points[imgwin->model.next_point] = entropy;
	imgwin->model.next_point =
		(imgwin->model.next_point + 1) % MAX_ENTROPY_POINTS;
}

static void
draw_entropy(RDDGUI_IMAGINGWIN *imgwin)
{
	double *points = imgwin->model.entropy_points;
	GtkWidget *canvas = imgwin->view.canvas;
	int w, h;
	int x, y;
	int i, j;

	gdk_window_get_geometry(canvas->window, NULL, NULL, &w, &h, NULL);

	for (i = 0; i < MAX_ENTROPY_POINTS; i++) {
		j = (imgwin->model.next_point + i) % MAX_ENTROPY_POINTS;
		x = (i * w) / MAX_ENTROPY_POINTS;
		y = h - (points[j] * h / 8.0);
		if (y >= h) y = h - 1;

		/* Delete the previous point at this x location by
		 * drawing a line.  This way we do not have to remember
		 * the y coordinate of the previous point.
		 */
		gdk_draw_line(canvas->window, canvas->style->bg_gc[GTK_STATE_NORMAL], x, 0, x, h-1);

		/* Draw the new point.
		 */
		gdk_draw_point(canvas->window, canvas->style->fg_gc[GTK_STATE_NORMAL], x, y);
	}
}
#endif

static void
imgwin_draw(RDDGUI_IMAGINGWIN *imgwin)
{
	draw_number(imgwin->view.readerrs, imgwin->model.nreaderr);
	draw_number(imgwin->view.substs, imgwin->model.nsubst);
	draw_number(imgwin->view.nbyte, imgwin->model.bytes_dropped);
	draw_progress(imgwin);
	draw_elapsed(imgwin);
}

static void
handle_read_error(rdd_count_t offset, unsigned nbyte, void *env)
{
	RDDGUI_IMAGINGWIN *imgwin = (RDDGUI_IMAGINGWIN *) env;

	imgwin->model.nreaderr++;

	draw_number(imgwin->view.readerrs, imgwin->model.nreaderr);
	(void) imgwin_update(imgwin);
}

static void
handle_substitution(rdd_count_t offset, unsigned nbyte, void *env)
{
	RDDGUI_IMAGINGWIN *imgwin = (RDDGUI_IMAGINGWIN *) env;

	imgwin->model.nsubst++;
	imgwin->model.bytes_dropped += nbyte;

	if (log_printer != 0) {
		rdd_mp_message(log_printer, RDD_MSG_ERROR,
			"unrecoverable read failure: "
			"dropping %u input bytes at offset %llu",
			nbyte, offset);
	}

	draw_number(imgwin->view.substs, imgwin->model.nsubst);
	draw_number(imgwin->view.nbyte, imgwin->model.bytes_dropped);
	(void) imgwin_update(imgwin);
}

static int
handle_progress(rdd_count_t pos, void *env)
{
	RDDGUI_IMAGINGWIN *imgwin = (RDDGUI_IMAGINGWIN *) env;

	imgwin->model.pos = pos;
	imgwin->model.elapsed = time(NULL) - imgwin->model.start;

	draw_progress(imgwin);
	draw_elapsed(imgwin);
#if defined(PLOT_ENTROPY)
	draw_entropy(imgwin);
#endif
	return imgwin_update(imgwin);
}

static RDD_COPIER *
create_copier(RDDGUI_IMAGINGWIN *imgwin)
{
	RDD_COPIER *copier = 0;
	rdd_count_t offset = rddgui_options.offset;
	rdd_count_t count = rddgui_options.count;
	int rc = RDD_OK;

	if (rddgui_options.mode == RDDGUI_SERVER
	||  !rddgui_options.enable_recovery) {
		RDD_SIMPLE_PARAMS p;

		memset(&p, 0, sizeof p);
		p.progressfun = handle_progress;
		p.progressenv = imgwin;

		rc = rdd_new_simple_copier(&copier, &p);
		if (rc != RDD_OK) {
			rdd_error(rc, "cannot create simple copier");
		}
	} else {
		RDD_ROBUST_PARAMS p;

		memset(&p, 0, sizeof p);
		p.minblocklen = rddgui_options.retry_block_size;
		p.maxblocklen = rddgui_options.block_size;
		p.nretry = rddgui_options.max_retry_count;
		p.maxsubst = rddgui_options.max_drop_count;
		p.readerrfun = handle_read_error;
		p.readerrenv = imgwin;
		p.substfun = handle_substitution;
		p.substenv = imgwin;
		p.progressfun = handle_progress;
		p.progressenv = imgwin;

		rc = rdd_new_robust_copier(&copier, offset, count, &p);
		if (rc != RDD_OK) {
			rdd_error(rc, "cannot create robust copier");
		}
	}

	return copier;
}

static gboolean
cancel_clicked(GtkWidget *widget, gpointer data)
{
	RDDGUI_IMAGINGWIN *imgwin = (RDDGUI_IMAGINGWIN *) data;

	imgwin->model.cancelled = 1;

	return TRUE;
}

static gboolean
help_clicked(GtkWidget *widget, gpointer data)
{
	RDDGUI_IMAGINGWIN *imgwin = (RDDGUI_IMAGINGWIN *) data;
	int rc;

	if (imgwin->model.help) {
		rc = rddgui_showhtml(imgwin->model.help);
		if (rc == RDD_NOTFOUND) {
			rddgui_error(GTK_WINDOW(imgwin->view.win),
					"No browser found");
		}
	}

	return TRUE;
}

#if defined(PLOT_ENTROPY)
static gint
canvas_exposed(GtkWidget *widget, GdkEventExpose *event, gpointer data)
{
	return 0;
}
#endif

static RDDGUI_IMAGINGWIN *
imgwin_create(GladeXML *xml, rdd_count_t input_size)
{
	RDDGUI_IMAGINGWIN *imgwin = 0;

	if ((imgwin = calloc(1, sizeof(RDDGUI_IMAGINGWIN))) == 0) {
		rddgui_fatal(0, "out of memory");
	}

	imgwin->view.win = glade_xml_get_widget(xml, "winImaging");
	imgwin->view.bar = glade_xml_get_widget(xml, "prgProgress");
	imgwin->view.elapsed = glade_xml_get_widget(xml, "lblShowTime");
	imgwin->view.readerrs = glade_xml_get_widget(xml, "lblShowReadErrors");
	imgwin->view.substs = glade_xml_get_widget(xml, "lblShowSubstBlocks");
	imgwin->view.nbyte = glade_xml_get_widget(xml, "lblShowSubstBytes");
#if defined(PLOT_ENTROPY)
	imgwin->view.canvas = glade_xml_get_widget(xml, "daEntropyPlot");
	gtk_drawing_area_size(GTK_DRAWING_AREA(imgwin->view.canvas), 200, 80);
#endif
	imgwin->view.logwin = glade_xml_get_widget(xml, "tvLog");

	imgwin->model.help = "rddgui.html#imaging";
	imgwin->model.size = input_size;
	imgwin->model.pos = 0;
	imgwin->model.elapsed = 0;
	imgwin->model.nreaderr = 0;
	imgwin->model.nsubst = 0;
	imgwin->model.bytes_dropped = 0;
#if defined(PLOT_ENTROPY)
	imgwin->model.entropy_points = calloc(sizeof(double),
						MAX_ENTROPY_POINTS);
	if (imgwin->model.entropy_points == 0) {
		rddgui_fatal(0, "out of memory");
	}
#endif

	imgwin_draw(imgwin);

	gtk_widget_hide_all(imgwin->view.win);

	/* Connect signals.
	 */
	glade_xml_signal_connect_data(xml, "on_butStop_clicked",
				G_CALLBACK(cancel_clicked), imgwin);
	glade_xml_signal_connect_data(xml, "on_butHelp_clicked",
				G_CALLBACK(help_clicked), imgwin);
#if defined(PLOT_ENTROPY)
	glade_xml_signal_connect_data(xml, "on_daEntropyPlot_exposed",
				G_CALLBACK(canvas_exposed), imgwin);
#endif

	gtk_widget_show_all(imgwin->view.win);

	return imgwin;
}

static char
hexchar(unsigned val)
{
	return (val < 10 ? '0' + val
			 : 'a' + (val - 10));
}

static void
bin2hex(unsigned char *bin, unsigned binlen, char *text)
{
	unsigned i, k;
	unsigned byteval;

	for (i = k = 0; i < binlen; i++) {
		byteval = (bin[i] >> 4) & 0xf;
		text[k++] = hexchar(byteval);

		byteval = bin[i] & 0xf;
		text[k++] = hexchar(byteval);
	}
	text[k++] = '\000';
}

static void
imgwin_get_stats(RDDGUI_IMGSTATS *stats, RDDGUI_IMAGINGWIN *imgwin,
		RDD_FILTERSET *fset)
{
	unsigned char md5buf[16];
	unsigned char sha1buf[20];
	RDD_FILTER *f = 0;
	int rc;

	stats->elapsed = imgwin->model.elapsed;
	stats->nreaderr = imgwin->model.nreaderr;
	stats->nsubst = imgwin->model.nsubst;
	stats->bytes_dropped = imgwin->model.bytes_dropped;

	/* Retrieve hash values (if any).
	 */
	rc = rdd_fset_get(fset, "MD5 stream", &f);
	if (rc == RDD_OK) {
		rdd_filter_get_result(f, md5buf, sizeof md5buf);
		bin2hex(md5buf, sizeof md5buf, stats->md5);
	} else if (rc == RDD_NOTFOUND) {
		snprintf(stats->md5, sizeof stats->md5, "N/A");
	} else {
		strcpy(stats->md5, "");
	}

	rc = rdd_fset_get(fset, "SHA-1 stream", &f);
	if (rc == RDD_OK) {
		rdd_filter_get_result(f, sha1buf, sizeof sha1buf);
		bin2hex(sha1buf, sizeof sha1buf, stats->sha1);
	} else if (rc == RDD_NOTFOUND) {
		snprintf(stats->sha1, sizeof stats->sha1, "N/A");
	} else {
		strcpy(stats->md5, "");
	}
}

#define bool2str(b)   ((b) ? "yes" : "no")
#define str2str(s)    ((s) == 0? "N/A" : (s))

static void
log_opts(void)
{

	RDDGUI_OPTS *opts = &rddgui_options;

	rdd_mp_message(log_printer, RDD_MSG_INFO, "");
	rdd_mp_message(log_printer, RDD_MSG_INFO, 
			"========== Parameter settings ==========");
	/* Input
	 */
	rdd_mp_message(log_printer, RDD_MSG_INFO, 
			"Input file: %s", str2str(opts->input_path));
	rdd_mp_message(log_printer, RDD_MSG_INFO, 
			"Input size: %llu", opts->count);
	rdd_mp_message(log_printer, RDD_MSG_INFO, 
			"Read: %llu bytes", opts->count);
	rdd_mp_message(log_printer, RDD_MSG_INFO, 
			"Block size: %llu bytes", opts->block_size);
	rdd_mp_message(log_printer, RDD_MSG_INFO, 
			"Offset: %llu bytes", opts->offset);

	/* Output
	 */
	rdd_mp_message(log_printer, RDD_MSG_INFO, 
			"");
	rdd_mp_message(log_printer, RDD_MSG_INFO, 
			"Output file: %s", str2str(opts->output_path));
	rdd_mp_message(log_printer, RDD_MSG_INFO, 
			"Log file: %s", str2str(opts->log_path));
	if (opts->split_output) {
		rdd_mp_message(log_printer, RDD_MSG_INFO, 
			"Segment size: %llu bytes", opts->split_size);
	} else {
		rdd_mp_message(log_printer, RDD_MSG_INFO, 
			"Segment size: N/A");
	}
			
	/* Hashing
	 */
	rdd_mp_message(log_printer, RDD_MSG_INFO, 
			"");
	rdd_mp_message(log_printer, RDD_MSG_INFO, 
			"compute MD5: %s", bool2str(opts->md5_stream_filter));
	rdd_mp_message(log_printer, RDD_MSG_INFO, 
			"compute SHA1: %s", bool2str(opts->sha1_stream_filter));

	/* Integrity options */
	rdd_mp_message(log_printer, RDD_MSG_INFO, 
			"");
	if (opts->enable_adler32) {
		rdd_mp_message(log_printer, RDD_MSG_INFO, 
			"Adler32 file: %s", str2str(opts->adler32_path));
		rdd_mp_message(log_printer, RDD_MSG_INFO, 
			"Adler32 block size: %llu bytes", 
						opts->adler32_block_size);
	} else {
		rdd_mp_message(log_printer, RDD_MSG_INFO, 
			"Adler32 file: N/A");
		rdd_mp_message(log_printer, RDD_MSG_INFO, 
			"Adler32 block size: N/A");
	}
		

	rdd_mp_message(log_printer, RDD_MSG_INFO, 
			"");
	if (opts->enable_crc32) {
		rdd_mp_message(log_printer, RDD_MSG_INFO, 
			"CRC32 file: %s", str2str(opts->crc32_path));
		rdd_mp_message(log_printer, RDD_MSG_INFO, 
			"CRC32 block size: %llu bytes", opts->crc32_block_size);
	} else {
		rdd_mp_message(log_printer, RDD_MSG_INFO, 
			"CRC32 file: N/A");
		rdd_mp_message(log_printer, RDD_MSG_INFO, 
			"CRC32 block size: N/A");
	}

	/* Recovery
	 */
	rdd_mp_message(log_printer, RDD_MSG_INFO, 
			"");
	if (opts->enable_recovery){
		rdd_mp_message(log_printer, RDD_MSG_INFO, 
			"Retry block size: %llu bytes", opts->retry_block_size);
		rdd_mp_message(log_printer, RDD_MSG_INFO, 
			"Drop block after: %u retries", opts->max_retry_count);
		if (opts->never_give_up) {
			rdd_mp_message(log_printer, RDD_MSG_INFO, 
			"Never give up");
		} else {
			rdd_mp_message(log_printer, RDD_MSG_INFO, 
				"Give up after: %llu blocks dropped", 
						opts->max_drop_count);
		}
	} else {
		rdd_mp_message(log_printer, RDD_MSG_INFO, 
			"No recovery");
	}
		
	/* Statistics
	 */
	rdd_mp_message(log_printer, RDD_MSG_INFO, 
			"");
	if (opts->enable_stats && opts->enable_entropy) {
		rdd_mp_message(log_printer, RDD_MSG_INFO, 
			"Entropy file: %s", str2str(opts->entropy_path));
		rdd_mp_message(log_printer, RDD_MSG_INFO,
			"Entropy block size: %llu bytes", 
						opts->entropy_block_size);
	} else {
		rdd_mp_message(log_printer, RDD_MSG_INFO, 
			"Entropy file: N/A", str2str(opts->entropy_path));
		rdd_mp_message(log_printer, RDD_MSG_INFO,
			"Entropy block size: N/A");
	}

	rdd_mp_message(log_printer, RDD_MSG_INFO, 
			"");
	if (opts->enable_stats && opts->enable_blockmd5) {
		rdd_mp_message(log_printer, RDD_MSG_INFO, 
			"Block MD5 file: %s", str2str(opts->blockmd5_path));
		rdd_mp_message(log_printer, RDD_MSG_INFO, 
			"MD5 block size: %llu bytes", opts->blockmd5_block_size);
	}

	rdd_mp_message(log_printer, RDD_MSG_INFO, 
			"========================================");
	rdd_mp_message(log_printer, RDD_MSG_INFO, "");

}

static void
log_stats(RDDGUI_IMGSTATS *stats)
{
	rdd_mp_message(log_printer, RDD_MSG_INFO, "read errors: %llu",
			stats->nreaderr);
	rdd_mp_message(log_printer, RDD_MSG_INFO, "substitutions: %llu blocks",
			stats->nsubst);
	rdd_mp_message(log_printer, RDD_MSG_INFO, "dropped: %llu bytes",
			stats->bytes_dropped);
	rdd_mp_message(log_printer, RDD_MSG_INFO, "MD5: %s", stats->md5);
	rdd_mp_message(log_printer, RDD_MSG_INFO, "SHA-1: %s", stats->sha1);
}

static void
imgwin_destroy(RDDGUI_IMAGINGWIN *imgwin)
{
	gtk_widget_destroy(imgwin->view.win);
	free(imgwin);
}

static int
image_or_verify(void)
{
	RDD_READER *reader;
	RDD_WRITER *writer;
	RDD_COPIER *copier;
	RDD_FILTERSET filterset;
	RDD_COPIER_RETURN copier_ret;
	rdd_count_t input_size;
	RDDGUI_IMAGINGWIN *imgwin;
	RDDGUI_IMGSTATS imgstats;
	RDDGUI_FINISHEDWIN *donewin;
	rddgui_finish_action_t finish_action;
	double start, end;
	GladeXML *xml;
	int rc;
	RDDGUI_OPTS *opts = &rddgui_options;

	while (1) {

		xml = glade_xml_new(rddgui_xml_path, "winImaging", NULL);

		rddgui_clear_output_files();

		/* Collect rdd arguments.
		 */
		rc = rdd_wizwin_run(rddgui_imageorverify_win);
		if (rc != RDD_OK) {
			exit(EXIT_FAILURE);
		}

		/* XXX For now, assume that we must copy data. Keep
		 * in mind that the user may also select the verification
		 * path.
		 */
		log_printer = open_log_printer(rddgui_options.log_path,
				glade_xml_get_widget(xml, "tvLog"));
		log_opts();

		/* Run rdd.
		 */
		reader = open_input(&input_size);
		writer = open_output(RDD_WHOLE_FILE);

		/* The input size from open_input() is the size of the 
		 * device. That is not necessarily the number of bytes
		 * we'll be reading
		 */
		if (opts->input_size == opts->count) {
			if (opts->offset == 0) {
				/* No offset, no limited count.
				 */
				input_size = opts->input_size;
			} else {
				/* Offset, no limited count.
				 */
				input_size = opts->input_size - opts->offset;
			}
		} else {
			/* Limited count.
			 */
			input_size = opts->count;
		}
		
		imgwin = imgwin_create(xml, input_size);

		install_filters(&filterset, writer, imgwin);

		copier = create_copier(imgwin);

		/* Run dialog in a nonblocking manner? */

		imgwin->model.start = time(NULL);

		rdd_mp_message(log_printer, RDD_MSG_INFO, "starting copy");
		start = rdd_gettime();
		rc = rdd_copy_exec(copier, reader, &filterset, &copier_ret);
		end = rdd_gettime();
		if (rc == RDD_OK) {
			rdd_mp_message(log_printer, RDD_MSG_INFO, "copy done");
			rddgui_info(GTK_WINDOW(imgwin->view.win), "Copy done");
		} else if (rc == RDD_ABORTED) {
			rdd_mp_message(log_printer, RDD_MSG_WARN, "");
			rdd_mp_message(log_printer, RDD_MSG_WARN,
					"COPY ABORTED BY USER");
			rdd_mp_message(log_printer, RDD_MSG_WARN, "");

			rddgui_error(GTK_WINDOW(imgwin->view.win),
					"Copy aborted");
		} else {
			int errcode = rc;
			char msg[64];

			rc = rdd_strerror(errcode, msg, sizeof msg);
			if (rc == RDD_OK) {
				rdd_mp_message(log_printer, RDD_MSG_WARN, "");
				rdd_mp_message(log_printer, RDD_MSG_ERROR,
						"COPY ERROR: %s", msg);
				rdd_mp_message(log_printer, RDD_MSG_WARN, "");

				rddgui_fatal(GTK_WINDOW(imgwin->view.win),
						"Copy error: %s", msg);
			} else {
				rdd_mp_message(log_printer, RDD_MSG_WARN, "");
				rdd_mp_message(log_printer, RDD_MSG_ERROR,
						"UNKNOWN COPY ERROR [%d]",
						errcode);
				rdd_mp_message(log_printer, RDD_MSG_WARN, "");

				rddgui_fatal(GTK_WINDOW(imgwin->view.win),
						"Unknown copy error [%d]",
						errcode);
			}
		}


		/* Clean up.
		 */
		if ((rc = rdd_copy_free(copier)) != RDD_OK) {
			rdd_mp_rddmsg(gui_printer, RDD_MSG_ERROR, rc,
					"cannot clean up copier");
			exit(EXIT_FAILURE);
		}
		if (writer != 0) {
			if ((rc = rdd_writer_close(writer)) != RDD_OK) {
				rdd_mp_rddmsg(gui_printer, RDD_MSG_ERROR, rc,
						"cannot clean up writer");
				exit(EXIT_FAILURE);
			}
		}

		if ((rc = rdd_reader_close(reader, 1)) != RDD_OK) {
			rdd_mp_rddmsg(gui_printer, RDD_MSG_ERROR, rc,
					"cannot clean up reader");
			exit(EXIT_FAILURE);
		}


		imgwin_get_stats(&imgstats, imgwin, &filterset);

		log_stats(&imgstats);
		close_printer(log_printer, "log-file");
		imgwin_destroy(imgwin);

		donewin = rddgui_create_finished_window(&imgstats);

		if ((rc = rdd_fset_clear(&filterset)) != RDD_OK) {
			rdd_mp_rddmsg(gui_printer, RDD_MSG_ERROR, rc,
					"cannot clean up filters");
			exit(EXIT_FAILURE);
		}


again:
		finish_action = rddgui_run_finished_window(donewin);

		switch (finish_action) {
		case RDDGUI_FINISH_NONE:
			goto again;
		case RDDGUI_FINISH_NEW:
			break;
		case RDDGUI_FINISH_HELP:
			rddgui_showhtml("rddgui.html#finished-imaging");
			goto again;
		case RDDGUI_FINISH_EXIT:
			rddgui_destroy_finished_window(donewin);
			goto done;
		case RDDGUI_FINISH_LOGFILE:
			rddgui_error(GTK_WINDOW(donewin->win), "SHOW LOGFILE: NOT IMPLEMENTED");
			/* XXX HOW TO SHOW LOGFILE */
			goto again;
		}

		rddgui_destroy_finished_window(donewin);
	}
done:

	return 0;
}

int
main(int argc, char **argv)
{
	int rc;
	int again = 0;

	gtk_init(&argc, &argv);
	glade_init();
	set_progname(argv[0]);
	rdd_init();
	rdd_cons_open();
	if ((rc = rddgui_init()) != RDD_OK) {
		rdd_error(rc, "cannot initialize GUI");
	}

	gui_printer = open_gui_printer();

	rddgui_splash(rddgui_xml_path);

	do {
		again = image_or_verify();
	} while(again);

	close_printer(gui_printer, "GUI");

	return 0;
}
