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



#ifndef __rsysint_h__
#define __rsysint_h__

/** \brief This header file allows a module to define
 *  integer types of known size with names that have
 *  a module-specific prefix.
 *
 *  Usage:
 *
 *  ==================================
 *  #include "rsystypes.h"
 *
 *  rsys_decl_ints(YOUR_PREFIX)
 *  ==================================
 *
 *  Do NOT add a semicolon to the macro invocation!
 */

#if defined(_WIN32) || defined(__WIN32__)
#include <windows.h>

/* Windows defines integer types that are exactly N bits wide
 * (N = 16, 32, 64).
 */
#define rsys_decl_ints(prefix) \
typedef WORD    prefix##_UINT16; \
typedef DWORD   prefix##_UINT32; \
typedef DWORD64 prefix##_UINT64;

#elif defined(__STDC__) && defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L

/* C99 defines integer types that are exactly N bits wide (N = 16, 32, 64).
 */
#include <inttypes.h>

#define rsys_decl_ints(prefix) \
typedef uint16_t prefix##_UINT16; \
typedef uint32_t prefix##_UINT32; \
typedef uint64_t prefix##_UINT64;

#elif defined(HAVE_INTTYPES_H) && defined(HAVE_UINT16_T) && defined(HAVE_UINT32_T) && defined(HAVE_UINT64_T)

#include <inttypes.h>

#define rsys_decl_ints(prefix) \
typedef uint16_t prefix##_UINT16; \
typedef uint32_t prefix##_UINT32; \
typedef uint64_t prefix##_UINT64;

#elif defined(HAVE_SYS_TYPES_H) && defined(HAVE_U_INT16_T) && defined(HAVE_U_INT32_T) && defined(HAVE_U_INT64_T)

#include <sys/types.h>

#define rsys_decl_ints(prefix) \
typedef u_int16_t prefix##_UINT16; \
typedef u_int32_t prefix##_UINT32; \
typedef u_int64_t prefix##_UINT64;

#else

/* not Windows, not standard C */
#error Configuration problem: unknown integer sizes

#endif /* Windows, standard C, other */

#endif /* __rsysint_h__ */
