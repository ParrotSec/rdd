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



#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>

#include "rdd.h"
#include "rdd_internals.h"
#include "reader.h"
#include "writer.h"
#include "filter.h"
#include "filterset.h"
#include "copier.h"

int
rdd_new_copier(RDD_COPIER **self, RDD_COPY_OPS *ops, unsigned statesize)
{
	RDD_COPIER *c = 0;
	unsigned char *state = 0;
	int rc;

	if (self == 0 || ops == 0) return RDD_BADARG;

	if ((c = calloc(1, sizeof(RDD_COPIER))) == 0) {
		rc = RDD_NOMEM;
		goto error;
	}
	if ((state = calloc(1, statesize)) == 0) {
		rc = RDD_NOMEM;
		goto error;
	}
	c->state = state;
	c->ops = ops;

	*self = c;
	return RDD_OK;

error:
	*self = 0;
	if (state != 0) free(state);
	if (c != 0) free(c);
	return rc;
}

int
rdd_copy_exec(RDD_COPIER *c, RDD_READER *r, RDD_FILTERSET *fset,
					    RDD_COPIER_RETURN *ret)
{
	RDD_COPY_OPS *ops = c->ops;

	return (*ops->exec)(c, r, fset, ret);
}

int
rdd_copy_free(RDD_COPIER *c)
{
	RDD_COPY_OPS *ops = c->ops;
	int rc;

	if (ops->free != 0) {
		rc = (*ops->free)(c);
		if (rc != RDD_OK) {
			return rc;
		}
	}

	free(c->state);
	c->state = 0;
	free(c);

	return RDD_OK;
}
