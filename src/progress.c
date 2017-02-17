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


#ifndef lint
static char copyright[] =
"@(#) Copyright (c) 2002\n\
	Netherlands Forensic Institute.  All rights reserved.\n";
#endif /* not lint */

/*
 * Periodic progress reporting.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <sys/time.h>

#include "rdd.h"
#include "rdd_internals.h"
#include "error.h"
#include "progress.h"

#define INIT_POLL_BYTES  1048576

int
rdd_progress_init(RDD_PROGRESS *p, rdd_count_t size, unsigned secs)
{
	memset(p, 0, sizeof(*p));

	p->input_size = size;
	p->period = (double) secs;
	p->start_time = rdd_gettime();
	p->last_time = p->start_time;
	p->poll_delta = INIT_POLL_BYTES;
	p->curpos = 0;
	p->last_pos = 0;

	return RDD_OK;
}

int
rdd_progress_update(RDD_PROGRESS *p, rdd_count_t pos)
{
	p->curpos = pos;
	return RDD_OK;
}

int
rdd_progress_poll(RDD_PROGRESS *p, RDD_PROGRESS_INFO *info)
{
	double now;
	double speed;

	if (p->curpos - p->last_pos < p->poll_delta) {
		return RDD_EAGAIN; /* too early to report progress */
	}

	now = rdd_gettime();
	speed = p->curpos / (now - p->start_time);        /* bytes/sec */
	p->poll_delta = p->period * speed;
	if ((now - p->last_time) < p->period) {
		return RDD_EAGAIN;
	}
	p->last_time = now;
	p->last_pos = p->curpos;

	info->pos = p->curpos;
	info->speed = speed;
	if (p->input_size == RDD_WHOLE_FILE) {
		info->fraction = -1.0;
	} else {
		info->fraction = ((double) p->curpos) / ((double) p->input_size);
	}

	return RDD_OK;
}
