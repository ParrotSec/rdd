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



#ifndef __copier_h__
#define __copier_h__

/** @file
 *  \brief Generic copier interface.
 *
 *  Copier objects, or copiers, implement a data copy algorithm.
 *  All copiers implement the interface that is defined here.
 */

struct _RDD_COPIER;
struct _RDD_COPY_OPS;

typedef struct _RDD_COPIER {
	struct _RDD_COPY_OPS *ops;
	void                 *state;
} RDD_COPIER;

typedef struct _RDD_COPIER_RETURN {
	rdd_count_t nbyte;
	rdd_count_t nlost;
	rdd_count_t nread_err;
	rdd_count_t nsubst;
} RDD_COPIER_RETURN;
	
typedef int (*rdd_copy_exec_fun)(RDD_COPIER *c,
				RDD_READER *reader, 
				RDD_FILTERSET *fset,
				RDD_COPIER_RETURN *ret);

typedef int (*rdd_copy_free_fun)(RDD_COPIER *c);

/** Each copier must supply an \c RDD_COPY_OPS structure that
 *  contains its specific copy routines.
 */
typedef struct _RDD_COPY_OPS {
	rdd_copy_exec_fun exec;	/**< copy data */
	rdd_copy_free_fun free;	/**< release the copier and its resources */
} RDD_COPY_OPS;

/** \brief Read error callback type.
 */
typedef void (*rdd_readerrhandler_t)(rdd_count_t offset, unsigned nbyte,
					void *env);
/** \brief Substitution callback type.
 */
typedef void (*rdd_substhandler_t)(rdd_count_t offset, unsigned nbyte,
					void *env);
/** \brief Progress callback type.
 */
typedef int (*rdd_proghandler_t)(rdd_count_t ncopied, void *env);

/** \brief Simple copier configuration parameters.
 */
typedef struct _RDD_SIMPLE_PARAMS {
	rdd_proghandler_t    progressfun; /**< progress callback */
	void                *progressenv; /**< progress callback environment */
} RDD_SIMPLE_PARAMS;

/** \brief Robust copier configuration parameters.
 */
typedef struct _RDD_ROBUST_PARAMS {
	unsigned             minblocklen; /**< minimum block length (during retries) */
	unsigned             maxblocklen; /**< maximum block length */
	unsigned             nretry;      /**< retry a failed read \c nretry times */
	unsigned             maxsubst;    /**< give up after \c maxsubst substitutions */
	rdd_readerrhandler_t readerrfun;  /**< read-error callback */
	void                *readerrenv;  /**< read-error callback environment */
	rdd_substhandler_t   substfun;    /**< data-block substitution callback */
	void                *substenv;    /**< substitution callback environment */
	rdd_proghandler_t    progressfun; /**< progress callback */
	void                *progressenv; /**< progress callback environment */
} RDD_ROBUST_PARAMS;

/* Constructors
 */
/** \brief Allocates a copier object and space for its implementation-specific
 *  state.
 *  \param c output value: will be set to a pointer to the new copier object.
 *  \param ops a pointer to a copiers implementation-specific copy routines.
 *  \param statesize the size in bytes of the copier's state.
 *  \return Returns \c RDD_OK on success.  Returns \c RDD_NOMEM if there
 *  is insufficient memory to create the object.
 *
 *  This is a utility routine that does \b not belong to the copy interface.
 *  It is used to prevent code duplication in copier implementations, which
 *  must all allocate a copier object and some implementation-specific state.
 *  This routine allocates the object and that state. The state buffer is
 *  zeroed. Initializing it with sensible values is, of course, a job left to
 *  the copier implementation.
 */
int rdd_new_copier(RDD_COPIER **c, RDD_COPY_OPS *ops, unsigned statesize);

/** \brief Creates a new simple copier.
 *  \param c output value: will be set to a pointer to the new simple copier object.
 *  \param params the copier's parameters
 *  \return Returns \c RDD_OK on success.  Returns \c RDD_NOMEM if there
 *  is insufficient memory to create the object.
 *
 *  A simple copier reads data from its reader (see \c rdd_copy_exec())
 *  until it reached end-of-file or until it encounters any error,
 *  including a read error.
 *
 *  The parameters \c params specify a callback function and its
 *  environment. This function is called periodically and can be
 *  used to report or track progress.
 */
int rdd_new_simple_copier(RDD_COPIER **c, RDD_SIMPLE_PARAMS *params);

/** \brief Creates a new robust copier.
 *  \param c output value: will be set to a pointer to the new robust copier object.
 *  \param offset byte offset; where to start copying
 *  \param count the maximum number of bytes to copy
 *  \param params the copier's error-handling parameters
 *  \return Returns \c RDD_OK on success.  Returns \c RDD_NOMEM if there
 *  is insufficient memory to create the object.
 *
 *  A robust copier behaves like a simple copier as long as no errors
 *  occur and if the \c offset and \c count arguments are both set to zero.
 *
 *  The \c offset and \c count arguments are used to read a contiguous
 *  segment from the input stream supplied to \c rdd_copy_exec():
 *  \c offset bytes from the input stream are skipped before the copier
 *  starts copying data and copying stops when \c count bytes have been
 *  copied or when end-of-file is encountered.
 *
 *  The parameters \c params specify the copier's behavior when
 *  read errors occur. A robust copier will enter a retry phase when
 *  a read fails. In that phase it reduces the amount of data it reads
 *  at a time and it will retry reads that fail.
 */
int rdd_new_robust_copier(RDD_COPIER **c,
		rdd_count_t offset, rdd_count_t count,
		RDD_ROBUST_PARAMS *params);

/* Generic routines
 */

/** \brief Generic copy routine that instructs a copier to start copying.
 *  \param c a pointer to the copier object.
 *  \param r a reader object from which the copier will read its source data.
 *  \param fset a filter set; the copier will push the data it reads from
 *  the reader to all filters in the filter set.
 *  \return Returns \c RDD_OK on success. 
 *
 *  Every copier reads, or tries to read, data from reader \c r.
 *  The data it reads, or the data that it substitutes, is passed
 *  to the filter set \c fset. The current copier implementation
 *  differ in how they handle read errors.  A simple copier will
 *  give up after the first read error, but a robust copier will
 *  retry and eventually substitute data if a read fails repeatedly.
 */
int rdd_copy_exec(RDD_COPIER *c, RDD_READER *r, RDD_FILTERSET *fset,
					    RDD_COPIER_RETURN *ret);

/** \brief Deallocates the copier object and releases its resources.
 *  \param c a pointer to the copier object.
 *  \return Returns \c RDD_OK on success. 
 */
int rdd_copy_free(RDD_COPIER *c);

#endif /* __copier_h__ */
