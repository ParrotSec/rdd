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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <stddef.h>

#include "rdd.h"
#include "alignedbuf.h"

int
rdd_new_alignedbuf(RDD_ALIGNEDBUF *buf, unsigned bufsize, unsigned align)
{
	ptrdiff_t unaligned;
	ptrdiff_t aligned;

	if (align <= 0) return RDD_BADARG;

	bufsize += align;  /* for buffer alignment below */
	bufsize += align;  /* for read-count alignment in unix_read() */

	memset(buf, 0, sizeof(*buf));

	if ((buf->unaligned = malloc(bufsize)) == 0) {
		return RDD_NOMEM;
	}

	unaligned = buf->unaligned - (unsigned char *) 0;

	if ((unaligned % align) == 0) {
		aligned = unaligned;
	} else {
		aligned = unaligned + align - (unaligned % align);
	}

	buf->aligned = (unsigned char *) aligned;
	buf->align = align;
	buf->asize = bufsize - (aligned - unaligned);

	return RDD_OK;
}

int
rdd_free_alignedbuf(RDD_ALIGNEDBUF *buf)
{
	free(buf->unaligned);
	memset(buf, 0, sizeof(*buf));

	return RDD_OK;
}

unsigned
rdd_abuf_get_size(RDD_ALIGNEDBUF *buf)
{
	return buf->asize;
}

unsigned
rdd_abuf_get_alignment(RDD_ALIGNEDBUF *buf)
{
	return buf->align;
}
