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



#ifndef __filterset_h__
#define __filterset_h__

/** @file
 *  \brief Filter collection module.
 *
 *  This header file defines routines that allow a client to
 *  create a collection of filters ---a filter set--- and to pass data to all
 *  filters in such a filter set with a single function call.
 */

/** \brief Representation of a filter node.
 *
 * A filter set is implemented as a linked list of filters.
 * This structure defines the representation of a list node.
 */
typedef struct _RDD_FSET_NODE {
	char                   *name;	/**< filter name */
	RDD_FILTER             *filter;	/**< the filter */
	struct _RDD_FSET_NODE *next;	/**< list link */
} RDD_FSET_NODE;

/** \brief Representation of a filter collection.
 *
 * A filter set is implemented as a linked list of \c RDD_FSET_NODE nodes.
 * This structure defines the list structure that gives access to
 * the list nodes.
 */
typedef struct _RDD_FILTERSET {
	RDD_FSET_NODE  *head;	/**< head of the filter list */
	RDD_FSET_NODE **tail;	/**< tail of the filter list */
} RDD_FILTERSET;

/** \brief Representation of a filter cursor.
 *
 * A filter cursor is used to visit all filters in a filter set.
 * The cursor keeps track of the current position in the filter set.
 */
typedef struct _RDD_FSET_CURSOR {
	RDD_FSET_NODE *current;
} RDD_FSET_CURSOR;

/** \brief Initializes a filter set.
 *  \param fset a pointer to the filter set that is to be initialized
 *  \return Returns \c RDD_OK on success.
 */
int rdd_fset_init(RDD_FILTERSET *fset);

/** \brief Adds a named filter to a filter set.
 *  \param fset the filter set
 *  \param name the name that will be associated with the filter that is
 *         added to the filter set
 *  \param f the filter that is added
 *  \return Returns \c RDD_OK on success (the filter has been added
 *  to the filter set). Returns \c RDD_EEXISTS if
 *  the filter set already contains a filter named \c name. In this
 *  case the filter is \b not added to the filter set.
 */
int rdd_fset_add(RDD_FILTERSET *fset, const char *name, RDD_FILTER *f);

/** \brief Looks up a filter by name in a filter set.
 *  \param fset the filter set
 *  \param name the name
 *  \param f output value: the filter that is associated with \c name
 *  \return Returns \c RDD_OK on success (filter set \c fset
 *  contains a filter named \c name). Returns \c RDD_NOTFOUND if
 *  filter set \c fset contains no filter named \c name.
 */
int rdd_fset_get(RDD_FILTERSET *fset, const char *name, RDD_FILTER **f);

/** \brief Opens a cursor that can be used to iterate over a filter set.
 *  \param fset the filter set
 *  \param c the cursor
 *  \return Returns \c RDD_OK on success.
 *
 *  A filter cursor is used to visit all filters in a filter set.
 *  The order in which filters are visited is not defined. A filter
 *  set must not be modified (no insertions or deletions) while
 *  it is being visited by a filter cursor.
 */
int rdd_fset_open_cursor(RDD_FILTERSET *fset, RDD_FSET_CURSOR *c);

/** \brief Retrieves the filter stored at a filter cursor's current position
 *  and advances the filter cursor.
 *  \param c the filter cursor
 *  \param f output value: the filter stored at the current position
 *  \return Returns \c RDD_OK on success. Returns \c RDD_NOTFOUND
 *  if the cursor has already visited all filters.
 */
int rdd_fset_cursor_next(RDD_FSET_CURSOR *c, RDD_FILTER **f);

/** \brief Closes a filter cursor.
 *  \param c the filter cursor
 *  \return Returns \c RDD_OK on success.
 */
int rdd_fset_cursor_close(RDD_FSET_CURSOR *c);

/** \brief Pushes a data buffer into all filters in a filter set.
 *  \param fset the filter set
 *  \param buf the data buffer
 *  \param nbyte the size in bytes of the data buffer
 *  \return Returns \c RDD_OK on success.
 *
 *  This function passes data buffer \c buf to each filter in the filter
 *  set by calling \c rdd_filter_push(f, buf, nbyte) for each filter \c f
 *  in the filter set.
 */
int rdd_fset_push(RDD_FILTERSET *fset, const unsigned char *buf, unsigned nbyte);

/** \brief Closes all filters in a filter set.
 *  \param fset the filter set
 *  \return Returns \c RDD_OK on success.
 *
 *  This function closes all filters in the filters by calling
 *  \c rdd_filter_close(f) for each filter \c f in the filter set.
 */
int rdd_fset_close(RDD_FILTERSET *fset);

/** \brief Destroys all resources associated with a filter set.
 *  \param fset the filter set
 *  \return Returns \c RDD_OK on success.
 *
 *  This function will also destroy all filters stored in the filter set
 *  by calling \c rdd_filter_free() for each filter.
 */
int rdd_fset_clear(RDD_FILTERSET *fset);

#endif /* __filterset_h__ */
