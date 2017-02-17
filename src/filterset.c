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

#if defined(HAVE_CONFIG_H)
#include <config.h>
#endif

#include <assert.h>
#include <memory.h>
#include <stdio.h>
#include <string.h>

#include "rdd.h"
#include "rdd_internals.h"
#include "writer.h"
#include "filter.h"
#include "filterset.h"

#define is_stream_filter(fltr)  ((fltr)->block_size <= 0)
#define is_block_filter(fltr)  ((fltr)->block_size > 0)

int
rdd_fset_init(RDD_FILTERSET *fset)
{
	fset->head = 0;
	fset->tail = &fset->head;

	return RDD_OK;
}

int
rdd_fset_add(RDD_FILTERSET *fset, const char *name, RDD_FILTER *f)
{
	RDD_FSET_NODE *node = 0;
	char *filtername = 0;
	int rc = RDD_OK;

	if (name == 0 || strlen(name) < 1 || f == 0) return RDD_BADARG;

	rc = rdd_fset_get(fset, name, 0);
	if (rc == RDD_OK) {
		return RDD_EEXISTS;	/* already in list */
	} else if (rc != RDD_NOTFOUND) {
		return rc;
	}

	/* Create new list node.
	 */
	if ((node = calloc(1, sizeof(*node))) == 0) {
		rc = RDD_NOMEM;
		goto error;
	}
	if ((filtername = malloc(strlen(name) + 1)) == 0) {
		rc = RDD_NOMEM;
		goto error;
	}
	strcpy(filtername, name);

	node->name = filtername;
	node->filter = f;
	node->next = 0;

	/* Append new node to list.
	 */
	*(fset->tail) = node;
	fset->tail = &node->next;

	return RDD_OK;

error:
	if (filtername != 0) free(filtername);
	if (node != 0) free(node);
	return rc;
}

int
rdd_fset_get(RDD_FILTERSET *fset, const char *name, RDD_FILTER **f)
{
	RDD_FSET_NODE *node;

	/* Linear search.
	 */
	for (node = fset->head; node != 0; node = node->next) {
		if (strcmp(node->name, name) == 0) {
			if (f != 0) *f = node->filter;
			return RDD_OK;
		}
	}

	if (f != 0) *f = 0;
	return RDD_NOTFOUND;
}

int
rdd_fset_open_cursor(RDD_FILTERSET *fset, RDD_FSET_CURSOR *c)
{
	c->current = fset->head;
	return RDD_OK;
}

int
rdd_fset_cursor_next(RDD_FSET_CURSOR *c, RDD_FILTER **f)
{
	if (c->current == 0) {
		if (f != 0) *f = 0;
		return RDD_NOTFOUND;
	}

	if (f != 0) *f = c->current->filter;
	c->current = c->current->next;
	return RDD_OK;
}

int
rdd_fset_cursor_close(RDD_FSET_CURSOR *c)
{
	c->current = 0;
	return RDD_OK;
}

int
rdd_fset_push(RDD_FILTERSET *fset, const unsigned char *buf, unsigned nbyte)
{
	RDD_FSET_NODE *node;
	int rc;

	for (node = fset->head; node != 0; node = node->next) {
		rc = rdd_filter_push(node->filter, buf, nbyte);
		if (rc != RDD_OK) {
			return rc;
		}
	}

	return RDD_OK;
}

int
rdd_fset_close(RDD_FILTERSET *fset)
{
	RDD_FSET_NODE *node;
	int rc;

	for (node = fset->head; node != 0; node = node->next) {
		rc = rdd_filter_close(node->filter);
		if (rc != RDD_OK) {
			return rc;
		}
	}

	return RDD_OK;
}

int
rdd_fset_clear(RDD_FILTERSET *fset)
{
	RDD_FSET_NODE *node;
	RDD_FSET_NODE *next;
	int rc;

	for (node = fset->head; node != 0; node = next) {
		next = node->next;
		free(node->name);
		node->name = 0;
		if ((rc = rdd_filter_free(node->filter)) != RDD_OK) {
			return rc;
		}
		free(node);
	}

	memset(fset, 0, sizeof(*fset));

	return RDD_OK;
}
