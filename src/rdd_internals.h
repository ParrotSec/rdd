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



#ifndef __rdd_internals_h__
#define __rdd_internals_h__

#include <stdarg.h>
#include <stdlib.h>
#include <sys/types.h>

#include "rsysint.h"

rsys_decl_ints(RDD_HASH)

typedef RDD_HASH_UINT16 UINT2;
typedef RDD_HASH_UINT32 UINT4;

#define streq(s1, s2)  (strcmp(s1, s2) == 0)

#define RDD_MAX_FILENAMESIZE  256

#define RDD_SECTOR_SIZE   512

#define RDD_NO   0
#define RDD_YES  1

void    rdd_init(void);

void    rdd_set_quiet(int q);

void   *rdd_malloc(size_t sz);

void    rdd_free(void *p);

int     rdd_buf2hex(const unsigned char *buf, unsigned bufsize,
		    char *hexbuf, unsigned hexbuflen);

char   *rdd_ctime(void);

double  rdd_gettime(void);

void    rdd_cons_open(void);
void    rdd_cons_close(void);
void    rdd_cons_printf(char *fmt, ...);
void    rdd_cons_vprintf(char *fmt, va_list ap);
int     rdd_ask(char *fmt, ...);
void    rdd_quit_if(int quit_answer, char *fmt, ...);

char   *rdd_strsize(rdd_count_t sz);

void    rdd_catch_signals(void);

int     rdd_device_size(const char *path, rdd_count_t *size);

int     rdd_strerror(int rc, char *buf, unsigned bufsize);

#endif /* __rdd_internals_h__ */
