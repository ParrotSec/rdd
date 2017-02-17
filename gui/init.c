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
#include <stdlib.h>

#include "rdd.h"
#include "rddgui.h"

#define RDDGUI_DUMMY int

#define CREATE_WIZWIN(varname, gladename, winstatetype) \
do { \
	int __rc = rdd_new_wizwin(&rddgui_##varname##_win, \
			rddgui_xml_path, \
                        #gladename, \
			&rddgui_options, \
			&rddgui_##varname##_ops, \
			sizeof(RDDGUI_##winstatetype)); \
	if (__rc != RDD_OK) return __rc; \
} while (0)

RDDGUI_OPTS rddgui_options;

#define RDD_DECL_WIN(varname) \
RDD_WIZWIN *rddgui_##varname##_win;

RDD_DECL_WIN(imageorverify)
RDD_DECL_WIN(network)
RDD_DECL_WIN(input)
RDD_DECL_WIN(inputadv)
RDD_DECL_WIN(output)
RDD_DECL_WIN(outputadv)
RDD_DECL_WIN(integrity)
RDD_DECL_WIN(integrityadv)
RDD_DECL_WIN(recovery)
RDD_DECL_WIN(recoveryadv)
RDD_DECL_WIN(stats)
RDD_DECL_WIN(statsadv)
RDD_DECL_WIN(confirmation)
RDD_DECL_WIN(client)
RDD_DECL_WIN(server)
RDD_DECL_WIN(serveradv)

char *rddgui_xml_path;

static void
init_options(void)
{
	memset(&rddgui_options, 0, sizeof rddgui_options);

	rddgui_options.mode = RDDGUI_LOCAL;
	rddgui_options.offset = 0;
	rddgui_options.count = RDD_WHOLE_FILE;
	rddgui_options.input_size = RDD_WHOLE_FILE;
	rddgui_options.split_output = 0;
	rddgui_options.split_size = 0;
	rddgui_options.block_size = 128 * 1024;
	rddgui_options.enable_recovery = 1;
	rddgui_options.retry_block_size = 512;
	rddgui_options.max_retry_count = 2;
	rddgui_options.enable_stats = 1;
	rddgui_options.never_give_up = 1;
}

static int
init_windows(void)
{
	/* Initialization order is important! One window may
	 * refer to another window at initialization time.
	 * If window A is referenced by window B at init time
	 * then A must be created first.
	 */
	CREATE_WIZWIN(imageorverify, dlgImageOrVerify, DUMMY);
	CREATE_WIZWIN(network, dlgNetwork, DUMMY);
	CREATE_WIZWIN(inputadv, dlgInputAdv, DUMMY);
	CREATE_WIZWIN(input, dlgInput, DUMMY);
	CREATE_WIZWIN(outputadv, dlgOutputAdv, DUMMY);
	CREATE_WIZWIN(output, dlgOutput, DUMMY);
	CREATE_WIZWIN(integrityadv, dlgIntegrityAdv, DUMMY);
	CREATE_WIZWIN(integrity, dlgIntegrity, DUMMY);
	CREATE_WIZWIN(recoveryadv, dlgErrorRecoveryAdv, DUMMY);
	CREATE_WIZWIN(recovery, dlgErrorRecovery, DUMMY);
	CREATE_WIZWIN(statsadv, dlgStatisticsAdv, DUMMY);
	CREATE_WIZWIN(stats, dlgStatistics, DUMMY);
	CREATE_WIZWIN(confirmation, dlgConfirmation, DUMMY);

	return RDD_OK;
}

int
rddgui_init(void)
{
	char *xmlpath;
	int rc;

	xmlpath = getenv("RDDGUI_XML_PATH");
	rddgui_xml_path = (xmlpath != 0 ? xmlpath : RDDGUI_GLADE_XML_PATH);

	init_options();

	if ((rc = init_windows()) != RDD_OK) {
		return rc;
	}

	return RDD_OK;
}
