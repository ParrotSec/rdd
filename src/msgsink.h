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



#ifndef __msgsink_h__
#define __msgsink_h__

typedef void (*rdd_msgsink_put_fun)(
		struct _RDD_MSGSINK *sink, const char *fmt, ...);
typedef void (*rdd_msgsink_close_fun)(struct _RDD_MSGSINK *sink);

typedef struct _RDD_MSGSINK_OPS {
	rdd_msgsink_put_fun put;
	rdd_msgsink_close_fun close;
} RDD_MSGSINK_OPS;

typedef struct _RDD_MSGSINK {
	void            *state;
	RDD_MSGSINK_OPS *ops;
} RDD_MSG_SINK;

RDD_MSGSINK *rdd_sink_open(RDD_MSGSINK_OPS *ops, unsigned size);

void rdd_sink_put(RDD_MSGSINK *sink, const char *fmt, ...);

void rdd_sink_close(RDD_MSGSINK *sink);

#endif /* __msgsink_h__ */
