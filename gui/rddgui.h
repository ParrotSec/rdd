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


#ifndef __rddgui_h__
#define __rddgui_h__

#ifdef __cplusplus__
extern "C" {
#endif

#include <stdio.h>
#include <gtk/gtk.h>
#include <glade/glade.h>

#include "msgprinter.h"
#include "writer.h"
#include "filter.h"
#include "filterset.h"

#define __rddgui_str(dirmac) #dirmac
#define __rddgui_path(dirmac, filemac)	( __rddgui_str(dirmac) "/" #filemac )
#define RDDGUI_GLADE_XML_PATH   __rddgui_path(PKGDATADIR, rddgui.glade)
#define __rddgui_dir(dirmac) (__rddgui_str(dirmac))
#define RDDGUI_DATADIR __rddgui_dir(PKGDATADIR)

#define RDDGUI_MAX_FILENAME_SIZE	256

typedef enum _rddgui_mode_t {
	RDDGUI_LOCAL,
	RDDGUI_CLIENT,
	RDDGUI_SERVER
} rddgui_mode_t;

typedef enum _rddgui_wizbutton_t {
	RDDGUI_NONE,
	RDDGUI_NEXT,
	RDDGUI_BACK,
	RDDGUI_ADVANCED,
	RDDGUI_FINISH
} rddgui_wizbutton_t;

typedef struct _RDDGUI_OPTS {
	rddgui_mode_t  mode;

	/* Input options.
	 */
	char          *input_path;
	rdd_count_t    input_size;
	rdd_count_t    offset;
	rdd_count_t    count;
	rdd_count_t    block_size;

	/* Output options.
	 */
	char          *output_path;
	char          *log_path;
	int            split_output;
	rdd_count_t    split_size;

	/* Network options.
	 */
	unsigned       server_port;

	/* Integrity options.
	 */
	int            md5_stream_filter;
	int            sha1_stream_filter;
	int            enable_adler32;
	rdd_count_t    adler32_block_size;
	char          *adler32_path;
	int            enable_crc32;
	rdd_count_t    crc32_block_size;
	char          *crc32_path;

	/* Recovery options.
	 */
	int            enable_recovery;
	rdd_count_t    retry_block_size;
	unsigned       max_retry_count;
	unsigned       max_drop_count;
	int            never_give_up;

	/* Statistical options.
	 */
	int            enable_stats;
	int            enable_entropy;
	rdd_count_t    entropy_block_size;
	char          *entropy_path;
	int            enable_blockmd5;
	rdd_count_t    blockmd5_block_size;
	char          *blockmd5_path;
} RDDGUI_OPTS;

struct _RDD_WIZWIN;

#define RDD_MAX_WIDGET_NAME_LEN	256 /* The max length of a name for a widget */

typedef void (*rdd_wizwin_init_fun)(struct _RDD_WIZWIN *ww);
typedef int  (*rdd_wizwin_next_fun)(struct _RDD_WIZWIN *ww);
typedef void (*rdd_wizwin_advanced_fun)(struct _RDD_WIZWIN *ww);

typedef struct _RDD_WIZWIN_OPS {
	rdd_wizwin_init_fun     init;     /**< Initialize wizard window */
	rdd_wizwin_next_fun     next;     /**< Validate input and give successor */
	rdd_wizwin_advanced_fun advanced; /**< Gives advanced window */
} RDD_WIZWIN_OPS;

/** \brief An \c RDD_WIZWIN structure describes a single wizard window.
 *  Each wizard window type is described in XML generated by the Glade
 *  GUI designer. Each wizard window type supplies a number of type-specific
 *  operations. These operations are described in a \c RDD_WIZWIN_OPS structure.
 */
typedef struct _RDD_WIZWIN {
	GladeXML           *xml;	/**< in-memory XML */
	GtkWidget          *window;	/**< root widget (a dialog window) */
	char                name[RDD_MAX_WIDGET_NAME_LEN];	
					/**< Glade name of the window */
	const char         *help;       /**< address of HTML help */
	RDDGUI_OPTS        *opts;	/**< rdd options */
	RDD_WIZWIN_OPS     *ops;	/**< type-specific operation table */
	void               *state;	/**< type-specific state */
	rddgui_wizbutton_t  result;	/**< dialog result */
	struct _RDD_WIZWIN *prev;	/**< dynamic predecessor window */
	struct _RDD_WIZWIN *next;	/**< dynamic successor window */
	struct _RDD_WIZWIN *advanced;	/**< advanced-options window */
} RDD_WIZWIN;

typedef struct _RDDGUI_IMGSTATS {
	unsigned    elapsed;
	rdd_count_t nreaderr;
	rdd_count_t nsubst;
	rdd_count_t bytes_dropped;
	char        md5[33];
	char        sha1[41];
} RDDGUI_IMGSTATS;

typedef enum _rddgui_finish_action_t {
	RDDGUI_FINISH_NONE,
	RDDGUI_FINISH_HELP,
	RDDGUI_FINISH_EXIT,
	RDDGUI_FINISH_LOGFILE,
	RDDGUI_FINISH_NEW
} rddgui_finish_action_t;

typedef struct _RDDGUI_FINISHEDWIN {
	GladeXML               *xml;
	GtkWidget              *win;
	rddgui_finish_action_t  action;
} RDDGUI_FINISHEDWIN;

extern RDDGUI_OPTS rddgui_options;

/* Declare dialog windows and their operation tables as global variables.
 */
#define RDD_EXTDECL_WIN(varname) \
extern RDD_WIZWIN_OPS rddgui_##varname##_ops; \
extern struct _RDD_WIZWIN *rddgui_##varname##_win;

RDD_EXTDECL_WIN(imageorverify)
RDD_EXTDECL_WIN(network)
RDD_EXTDECL_WIN(input)
RDD_EXTDECL_WIN(inputadv)
RDD_EXTDECL_WIN(output)
RDD_EXTDECL_WIN(outputadv)
RDD_EXTDECL_WIN(integrity)
RDD_EXTDECL_WIN(integrityadv)
RDD_EXTDECL_WIN(recovery)
RDD_EXTDECL_WIN(recoveryadv)
RDD_EXTDECL_WIN(stats)
RDD_EXTDECL_WIN(statsadv)
RDD_EXTDECL_WIN(confirmation)
RDD_EXTDECL_WIN(client)
RDD_EXTDECL_WIN(clientadv)
RDD_EXTDECL_WIN(server)
RDD_EXTDECL_WIN(serveradv)
RDD_EXTDECL_WIN(verify)
RDD_EXTDECL_WIN(verifyadv)

extern char *rddgui_xml_path;

int  rddgui_init(void);

void rddgui_splash(const char *path);

int  rddgui_showhtml(const char *htmlfile);

void rddgui_fatal(GtkWindow *parent, const char *fmt, ...);

void rddgui_error(GtkWindow *parent, const char *fmt, ...);

void rddgui_warn(GtkWindow *parent, const char *fmt, ...);

void rddgui_info(GtkWindow *parent, const char *fmt, ...);

int  rddgui_add_output_file(RDD_WIZWIN *ww, const char *label, const char *path);

void rddgui_clear_output_files(void);

void rddgui_dump_output_files(void);

int  rddgui_yesno_dialog(GtkWindow *parent, const char *fmt, ...);

int  rddgui_radio_selected(RDD_WIZWIN *ww, const char *name);

void rddgui_radio_select(RDD_WIZWIN *ww, const char *name);

void rddgui_widgets_set_sensitive(RDD_WIZWIN *ww,
		const char **names, unsigned nname, gboolean sensitive);

char *rddgui_get_text(RDD_WIZWIN *ww, const char *name, int copy);

void  rddgui_set_text(RDD_WIZWIN *ww, const char *name, const char *text);

int  rddgui_get_uint(RDD_WIZWIN *ww, const char *label, const char *name,
		unsigned *num);

void rddgui_set_uint(RDD_WIZWIN *ww, const char *entryname, unsigned num);

int  rddgui_get_checked(RDD_WIZWIN *ww, const char *name);

int  rddgui_get_multnum(RDD_WIZWIN *ww, const char *label,
		const char *num, const char *mult, rdd_count_t *np);

void rddgui_set_multnum(RDD_WIZWIN *ww, rdd_count_t n,
		const char *numname, const char *multname);

void rddgui_focus(RDD_WIZWIN *ww, const char *name);

int  rdd_mp_open_gui_printer(RDD_MSGPRINTER **printer);

int  rdd_mp_open_guilog_printer(RDD_MSGPRINTER **printer,
		GtkTextBuffer *textbuf);

int  rdd_new_wizwin(RDD_WIZWIN **self, const char *path, const char *name,
	RDDGUI_OPTS *opts, RDD_WIZWIN_OPS *ops, unsigned statesize);

int  rdd_free_wizwin(RDD_WIZWIN *ww);

int  rdd_wizwin_run(RDD_WIZWIN *ww);

int  rdd_wizwin_next(RDD_WIZWIN *ww);

void rdd_wizwin_advanced(RDD_WIZWIN *ww);

RDDGUI_FINISHEDWIN *rddgui_create_finished_window(RDDGUI_IMGSTATS *stats);

rddgui_finish_action_t rddgui_run_finished_window(RDDGUI_FINISHEDWIN *win);

void rddgui_destroy_finished_window(RDDGUI_FINISHEDWIN *win);

int rddgui_get_dir(const char *path, char *dir);

void build_part_path(RDD_WIZWIN *ww, char *widget, char *filename);

#if defined(PLOT_ENTROPY)
int rddgui_new_plotentropy_blockfilter(RDD_FILTER **self, unsigned blocksize,
	void (*entropy_handler)(unsigned blocknum, double entropy, void *env),
	void *env);
#endif

#ifdef __cplusplus__
}
#endif

#endif /* __rddgui_h__ */
