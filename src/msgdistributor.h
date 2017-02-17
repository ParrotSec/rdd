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



#ifndef __msgdistributor_h__
#define __msgdistributor_h__

#include <limits.h>

typedef unsigned rdd_sinkset_t
typedef unsigned rdd_sinkid_t
#define RDD_MSGSINK_MAX (CHAR_BIT * sizeof(rdd_sinkset_t))

#define RDD_MSGSINK_ALL ( ~((unsigned) 0) )

typedef struct _RDD_MSG_DISTRIBUTOR {
	struct _RDD_MSGSINK *sinktab[RDD_MAX_MSGSINK];
	unsigned nsink;
} RDD_MSG_DISTRIBUTOR;

void rdd_msgdist_init(RDD_MSG_DISTRIBUTOR *mdist);

rdd_sinkid_t rdd_msgdist_addsink(RDD_MSG_DISTRIBUTOR *mdist,
		struct _RDD_MSGSINK *sink);

void rdd_msgdist_put(RDD_MSG_DISTRIBUTOR *mdist, rdd_sinkset_t sinks,
		const char *fmt, ...);

#endif /* __msgdistributor_h__ */
