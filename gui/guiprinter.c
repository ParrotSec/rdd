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

#include "rdd.h"
#include "rddgui.h"
#include "rdd_internals.h"
#include "msgprinter.h"

typedef struct _RDD_GUI_MSGPRINTER {
	int dummy;	/* prevent empty struct */
} RDD_GUI_MSGPRINTER;

static void gui_print(RDD_MSGPRINTER *printer,
		rdd_message_t type, int errcode, const char *msg);
static int  gui_close(RDD_MSGPRINTER *printer, unsigned flags);

static RDD_MSGPRINTER_OPS gui_ops = {
	gui_print,
	gui_close
};

int
rdd_mp_open_gui_printer(RDD_MSGPRINTER **printer)
{	
	RDD_GUI_MSGPRINTER *gui = 0;
	RDD_MSGPRINTER *p = 0;
	int rc = RDD_OK;

	rc = rdd_mp_open_printer(&p, &gui_ops, sizeof(RDD_GUI_MSGPRINTER));
	if (rc != RDD_OK) {
		goto error;
	}

	gui = (RDD_GUI_MSGPRINTER *) p->state;
	gui->dummy = -1;

	*printer = p;
	return RDD_OK;

error:
	*printer = 0;
	if (gui != 0) free(gui);
	return rc;
}

static void
gui_print(RDD_MSGPRINTER *printer, rdd_message_t type, int errcode,
	const char *msg)
{
	switch (type) {
	case RDD_MSG_INFO:
		rddgui_info(0, "%s", msg);
		break;
	case RDD_MSG_ERROR:
		rddgui_error(0, "%s", msg);
		break;
	case RDD_MSG_WARN:
		rddgui_warn(0, "%s", msg);
		break;
	case RDD_MSG_DEBUG:
		rddgui_info(0, "%s", msg);
		break;
	}
}

static int
gui_close(RDD_MSGPRINTER *printer, unsigned flags)
{
	RDD_GUI_MSGPRINTER *gui = (RDD_GUI_MSGPRINTER *) printer->state;

	memset(gui, 0, sizeof *gui);

	return RDD_OK;
}
