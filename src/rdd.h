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



#ifndef __rdd_h__
#define __rdd_h__

#include <sys/types.h>

#include "rsysint.h"

rsys_decl_ints(RDD)

typedef RDD_UINT64 rdd_count_t;

#define RDD_CHECKSUM_MAGIC   0xdefd
#define RDD_CHECKSUM_VERSION 0x0100

typedef RDD_UINT32 rdd_checksum_t;	/*  = 32 bits */

typedef enum {
	RDD_ADLER32 = 0x1,
	RDD_CRC32 = 0x2
} rdd_checksum_algorithm_t;

typedef struct _RDD_CHECKSUM_FILE_HEADER {
	RDD_UINT16 magic;
	RDD_UINT16 version;
	RDD_UINT16 flags;
	RDD_UINT16 reserved;
	RDD_UINT32 blocksize;
	off_t      offset;
	off_t      imagesize;
} RDD_CHECKSUM_FILE_HEADER;

#define RDD_COUNT_MAX	18446744073709551615ULL

/* rdd error codes */
#define RDD_OK        0		/* no error */
#define RDD_NOMEM     1		/* out of memory */
#define RDD_BADARG    2		/* bad function argument */
#define RDD_ECOMPRESS 3		/* (de)compression error */
#define RDD_EWRITE    4		/* write error */
#define RDD_ECLOSE    5		/* close error */
#define RDD_EEXISTS   6		/* file already exists */
#define RDD_EOPEN     7		/* cannot open file */
#define RDD_ECONNECT  8		/* cannot connect */
#define RDD_ETELL     9		/* cannot determine current file position */
#define RDD_ESEEK    10		/* seek error */
#define RDD_EREAD    11		/* read error */
#define RDD_ESPACE   12		/* insufficient space in buffer */
#define RDD_ESYNTAX  13		/* syntax error */
#define RDD_ERANGE   14		/* number out of range */
#define RDD_EAGAIN   15		/* try again later */
#define RDD_NOTFOUND 16		/* not found */
#define RDD_ABORTED  17		/* operation has been aborted */

#define RDD_WHOLE_FILE ((rdd_count_t) ~(0ULL))

#endif /* __rdd_h__ */
