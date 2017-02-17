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

/*
 * Rdd copies data from one (special) file to another (regular) file.
 * In client-server mode, the data stream will cross a TCP connection.
 * Rdd will not read from stdin, because it cannot seek on stdin.
 * Error messages are sent to a log stream.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "rdd.h"
#include "rdd_internals.h"
#include "commandline.h"
#include "reader.h"
#include "writer.h"
#include "filter.h"
#include "filterset.h"
#include "copier.h"
#include "error.h"
#include "netio.h"
#include "alignedbuf.h"

#define KNOWN_INPUT_SIZE(s)   ((s)->count != RDD_WHOLE_FILE)

typedef enum _read_mode_t { READ_OK, READ_ERROR, READ_RECOVERY } read_mode_t;

typedef struct _RDD_ROBUST_COPIER {
	read_mode_t mode;
	rdd_count_t offset;		/* start reading at this position */
	rdd_count_t count;		/* number of bytes to read */
	unsigned    minblocklen;
	unsigned    maxblocklen;
	unsigned    curblocklen;
	unsigned    recovery_threshold;	/* determines recovery completion */

	int         verbose;

	unsigned    nretry;
	unsigned    maxsubst;

	rdd_count_t nbyte;		/* bytes read so far */
	rdd_count_t nlost;		/* bytes discarded so far */
	unsigned    nread_err;	/* number of persistent read errors */
	unsigned    nsubst;

	unsigned    nok;		/* only valid in READ_RECOVERY mode */
	unsigned    ntry;		/* only valid in READ_ERROR mode */

	rdd_readerrhandler_t  readerrfun;
	void                 *readerrenv;
	rdd_substhandler_t    substfun;
	void                 *substenv;
	rdd_proghandler_t     progressfun;
	void                 *progressenv;

	RDD_ALIGNEDBUF readbuf;
} RDD_ROBUST_COPIER;

static int robust_exec(RDD_COPIER *c, RDD_READER *r, 
				      RDD_FILTERSET *fset,
				      RDD_COPIER_RETURN *ret);
static int robust_free(RDD_COPIER *c);

static RDD_COPY_OPS robust_ops = {
	robust_exec,
	robust_free
};

int
rdd_new_robust_copier(RDD_COPIER **self,
		rdd_count_t offset, rdd_count_t count,
		RDD_ROBUST_PARAMS *p)
{
	RDD_COPIER *c = 0;
	RDD_ROBUST_COPIER *state = 0;
	int rc = RDD_OK;

	if (p->maxblocklen <= 0) return RDD_BADARG;
	if (p->minblocklen <= 0) return RDD_BADARG;
	if (p->minblocklen > p->maxblocklen) return RDD_BADARG;

	rc = rdd_new_copier(&c, &robust_ops, sizeof(RDD_ROBUST_COPIER));
	if (rc != RDD_OK) {
		goto error;
	}
	state = (RDD_ROBUST_COPIER *) c->state;

	state->mode = READ_OK;
	state->offset = offset;
	state->count = count;
	state->minblocklen = p->minblocklen;
	state->maxblocklen = p->maxblocklen;
	state->curblocklen = p->maxblocklen;
	state->recovery_threshold =
		(p->maxblocklen + p->minblocklen - 1) / p->minblocklen;

	state->readerrfun = p->readerrfun;
	state->readerrenv = p->readerrenv;
	state->substfun = p->substfun;
	state->substenv = p->substenv;
	state->progressfun = p->progressfun;
	state->progressenv = p->progressenv;
	state->verbose = 1;

	state->nretry = p->nretry;
	state->maxsubst = p->maxsubst;

	state->nbyte = 0;
	state->nlost = 0;
	state->nread_err = 0;
	state->nsubst = 0;

	state->nok = 0;
	state->ntry = 0;

	/* Allocate a sector-aligned buffer.  Alignment is required
	 * when rdd access a raw device (Linux: /dev/raw/raw1, ...).
	 * It never hurts, so we always do this.
	 */
	rc = rdd_new_alignedbuf(&state->readbuf, p->maxblocklen,
				RDD_SECTOR_SIZE);
	if (rc != RDD_OK) {
		goto error;
	}

#if 0
	progress_init(&state->progress, state->count, 10);
	rdd_copy_set_progress_handler(state, progress_update, &state->progress);
#endif

	*self = c;
	return RDD_OK;

error:
	*self = 0;
	if (state != 0) free(state);
	if (c != 0) free(c);
	return rc;
}

static void
handle_eof(RDD_ROBUST_COPIER *state)
{
	if (KNOWN_INPUT_SIZE(state)) {
		/* If we know the input size, then we should never hit EOF.
		 */
		error("unexpected end-of-file after %llu bytes "
		    "(expected %s bytes)",
		    state->nbyte, rdd_strsize(state->count));
	}
}

static void
handle_read_ok(RDD_ROBUST_COPIER *state, unsigned rsize, unsigned nread)
{
	/* Read appears to have succeeded.  Make sure it really did.
	 */
	if (KNOWN_INPUT_SIZE(state) && nread != rsize) {
		bug("rdd: read fewer bytes (%u) than expected (%u)",
			nread, rsize);
	}

	/* Read really succeeded, so process what we got.
	 */
	switch (state->mode) {
	case READ_OK:
		if (nread >= state->curblocklen
		&& state->curblocklen < state->maxblocklen) {
			unsigned oldsize = state->curblocklen;
			state->curblocklen *= 2;
			if (state->curblocklen > state->maxblocklen) {
				state->curblocklen = state->maxblocklen;
			}
			if (state->verbose) {
				errlognl("increasing block size %u -> %u: "
					"offset %llu bytes",
					oldsize, state->curblocklen,
					state->offset + state->nbyte);
			}
		}
		break;
	case READ_ERROR:
		state->mode = READ_RECOVERY;
		state->nok = 0;
		if (state->verbose) {
			errlognl("entered READ_RECOVERY mode, "
				"block size %u bytes, offset %llu bytes",
				state->curblocklen,
				state->offset + state->nbyte);
		}
		break;
	case READ_RECOVERY:
		if (++state->nok >= state->recovery_threshold) {
			state->mode = READ_OK;
			if (state->verbose) {
				errlognl("entered READ_OK mode, "
					"block size %u bytes, "
					"offset %llu bytes",
					state->curblocklen,
					state->offset + state->nbyte);
			}
		}
		break;
	}
}

/* Handles a read error; returns
 * - RDD_EAGAIN if the caller should retry the read;
 * - RDD_EREAD if the block is dropped (caller should not retry);
 * - RDD_ABORTED if a fatal system error occurred.
 * retry the read.
 */
static int
handle_read_error(RDD_ROBUST_COPIER *state, RDD_READER *reader,
		unsigned char *buf, unsigned rsize)
{
	int rc = RDD_EAGAIN;

	state->nread_err++;

	switch (state->mode) {
	case READ_OK:
	case READ_RECOVERY:
		state->mode = READ_ERROR;
		state->curblocklen = state->minblocklen;
		state->ntry = 0;
		if (state->verbose) {
			errlognl("entered READ_ERROR mode, "
				"block size %u bytes, offset %llu bytes",
				state->curblocklen,
				state->offset + state->nbyte);
		}
		break;
	case READ_ERROR:
		if (++state->ntry >= state->nretry) {
			/* Reached maximum retry count, so there is no hope
			 * left for this block.  Tell caller to skip this
			 * block.
			 */
			errlognl("read error: offset %llu bytes, count %u bytes",
				state->offset + state->nbyte, rsize);

			rc = rdd_reader_skip(reader, rsize);
			if (rc != RDD_OK) {
				errlognl("cannot skip bad data block, aborting");
				return RDD_ABORTED;
			}

			state->mode = READ_RECOVERY;
			state->nok = 0;
			if (state->verbose) {
				errlognl("entered READ_RECOVERY mode, "
					"block size %u bytes, "
					"offset %llu bytes",
					state->curblocklen,
					state->offset + state->nbyte);
			}

			rc = RDD_EREAD;
		}
		break;
	}

	return rc;
}

/* Below follows the key copy routine.  Most complexity results
 * from the need to handle (disk) read errors properly.  In general
 * rdd makes no attempt to recover from TCP errors or disk-write errors.
 *
 * There are three states: READ_OK, READ_ERROR, READ_RECOVERY.
 * In state READ_OK, rdd reads at full speed and tries to double
 * the current read-block size until the default block size
 * is reached.
 *
 * State READ_ERROR is entered whenever a read error occurs.
 * In this state, rdd repeatedly tries to read a minimum-sized
 * block.  Variable ntry is valid in this state only.
 *
 * In state READ_RECOVERY, rdd recovers from a previous read
 * error.  This state is used to prevent rdd from increasing
 * its block size too quickly after a previous read error.
 * Variable nok is valid in this state only.
 */
static int
robust_exec(RDD_COPIER *c, RDD_READER *reader, RDD_FILTERSET *fset,
					       RDD_COPIER_RETURN *ret)
{
	RDD_ROBUST_COPIER *s = (RDD_ROBUST_COPIER *) c->state;
	RDD_READER *areader = 0;
	RDD_UINT32 rsize;
	unsigned nread;
	unsigned char *buf = 0;
	int aborted = 0;
	int rc = RDD_OK;

	ret->nbyte = 0;
	ret->nlost = 0;
	ret->nread_err = 0;
	ret->nsubst = 0;

	if ((rc = rdd_open_atomic_reader(&areader, reader)) != RDD_OK) {
		return rc;
	}

	if (s->offset > 0) {
		if ((rc = rdd_reader_skip(areader, s->offset)) != RDD_OK) {
			return rc;
		}
	}

	while (s->nbyte < s->count) {
		if (s->nbyte + s->curblocklen < s->count) {
			/* Read a full block. */
			rsize = s->curblocklen;
		} else {
			/* Read the last block. */
			rsize = (RDD_UINT32) (s->count - s->nbyte);
		}

		buf = s->readbuf.aligned;
		nread = 0;
		rc = rdd_reader_read(areader, buf, rsize, &nread);
		if (rc == RDD_OK && nread == 0) {
			handle_eof(s);
			break;
		} else if (rc == RDD_OK && nread > 0) {
			handle_read_ok(s, rsize, nread);
			rc = rdd_fset_push(fset, buf, nread);
			if (rc != RDD_OK) {
				return rc;
			}
			s->nbyte += nread;
		} else if (rc == RDD_EREAD) {
			/* Read failure.  When the read is fatal,
			 * substitute zeroes and apply the filters.
			 */
			rc = handle_read_error(s, areader, buf, rsize);

			if (s->readerrfun != 0) {
				(*s->readerrfun)(s->offset + s->nbyte,
					       rsize, s->readerrenv);
			}

			switch (rc) {
			case RDD_EREAD:
				if (s->maxsubst > 0
				&&  (s->nsubst+1) >= s->maxsubst){
					return RDD_ABORTED;
				}

				/* Substitute a zero-filled block for the
				 * block that we have failed to read.
				 */
				memset(buf, 0, rsize);
				s->nlost += rsize;  /* XXX to subst handler */
				rc = rdd_fset_push(fset, buf, rsize);
				if (rc != RDD_OK) {
					return rc;
				}

				if (s->substfun != 0) {
					(*s->substfun)(s->offset + s->nbyte,
						      rsize, s->substenv);
				}

				s->nbyte += rsize;
				s->nsubst++;
				break;
			case RDD_EAGAIN:
				break;
			default:
				return rc;
			}
		} else {
			return RDD_EREAD;
		}


		if (s->progressfun != 0) {
			rc = (*s->progressfun)(s->nbyte, s->progressenv);
			if (rc == RDD_ABORTED) {
				aborted = 1;
				break;
			} else if (rc != RDD_OK) {
				return rc;
			}
		}
	}

	if (s->progressfun != 0) {
		rc = (*s->progressfun)(s->nbyte, s->progressenv);
		if (rc == RDD_ABORTED) {
			aborted = 1;
		} else if (rc != RDD_OK) {
			return rc;
		}
	}

	if ((rc = rdd_fset_close(fset)) != RDD_OK) {
		return rc;
	}

	/* Close the atomic reader that was stacked on top of
	 * the input reader. The caller must close its own
	 * readers.
	 */
	if ((rc = rdd_reader_close(areader, 0)) != RDD_OK) {
		return rc;
	}
	
	ret->nbyte = s->nbyte;
	ret->nlost = s->nlost;
	ret->nread_err = s->nread_err;
	ret->nsubst = s->nsubst;

	return aborted ? RDD_ABORTED : RDD_OK;
}

static int
robust_free(RDD_COPIER *c)
{
	RDD_ROBUST_COPIER *state = (RDD_ROBUST_COPIER *) c->state;

	return rdd_free_alignedbuf(&state->readbuf);
}
