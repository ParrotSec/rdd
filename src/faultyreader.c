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
"@(#) Copyright (c) 2002-2004\n\
	Netherlands Forensic Institute.  All rights reserved.\n";
#endif /* not lint */


#if defined(HAVE_CONFIG_H)
#include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "rdd.h"
#include "reader.h"

#define MAX_LINE   128
#define MAX_FAULT    8

typedef unsigned short rngstate_t[3];
typedef unsigned long seed_t;

typedef struct _RDDFAULT {
	rdd_count_t   meanpos;	/* mean read-error position (block offset) */
	rdd_count_t   sigmapos;	/* stddev of read-error position (blocks) */
	rngstate_t rngpos;	/* state of random-number generator */
	seed_t     pos_seed;
	double     errprob;	/* probability of occurrence of this fault */
	rngstate_t rngerr;	/* state of random-number generator */
	seed_t     err_seed;
} RDDFAULT;

typedef struct _RDD_FAULTY_READER {
	RDD_READER *parent;
	RDDFAULT    faults[MAX_FAULT];
	unsigned    nfault;
} RDD_FAULTY_READER;

/* Forward declarations
 */
static int rdd_faulty_read(RDD_READER *r, unsigned char *buf, unsigned nbyte,
			unsigned *nread);
static int rdd_faulty_tell(RDD_READER *r, rdd_count_t *pos);
static int rdd_faulty_seek(RDD_READER *r, rdd_count_t pos);
static int rdd_faulty_close(RDD_READER *r, int recurse);

static RDD_READ_OPS faulty_read_ops = {
	rdd_faulty_read,
	rdd_faulty_tell,
	rdd_faulty_seek,
	rdd_faulty_close
};

/* Returns a random number in [0.0, 1.0).
 */
static double
uniform_random(rngstate_t state)
{
	return 0.0;
}

#if 0
/* Returns a number drawn from a normal distribution with mean
 * mean and standard deviation sigma.
 */
static double
gauss_random(rngstate_t state)
{
	return 0.0;
}
#endif

static int
fault_compare(const void *p1, const void *p2)
{
	const RDDFAULT *f1 = p1;
	const RDDFAULT *f2 = p2;

	if (f1->meanpos < f2->meanpos) {
		return -1;
	} else if (f1->meanpos > f2->meanpos) {
		return 1;
	} else {
		return 0;
	}
}

static void
fault_init(RDDFAULT *f,
	rdd_count_t meanpos, rdd_count_t sigmapos, seed_t pos_seed,
	double errprob, seed_t err_seed)
{
	memset(f, '\000', sizeof(*f));
	f->meanpos = meanpos;
	f->sigmapos = sigmapos;
	f->pos_seed = pos_seed;
	f->errprob = errprob;
	f->err_seed = err_seed;
}

/* Reads fault specifications from a configuration file.
 */
static int
read_faults(FILE *fp, RDD_FAULTY_READER *state)
{
	char line[MAX_LINE];
	unsigned lineno;
	rdd_count_t pos;
	double probability;

	for (lineno = 1; fgets(line, MAX_LINE, fp) != NULL; lineno++) {
		if (strlen(line) >= MAX_LINE - 1) {
			return RDD_ESYNTAX; /* line too long */
		}
		if (sscanf(line, "%llu %lf", &pos, &probability) != 2) {
			return RDD_ESYNTAX; /* bad item count on line */
		}

		if (state->nfault >= MAX_FAULT) {
			return RDD_ESPACE; /* too many lines */
		}
		fault_init(&state->faults[state->nfault], pos,
				0, 0, probability, 0);
		state->nfault++;
	}
	if (! feof(fp)) {
		return RDD_ESYNTAX;
	}

	return RDD_OK;
}

/* Reads a list of fault specification from the configuration file.
 */
int
rdd_open_faulty_reader(RDD_READER **self, RDD_READER *parent, char *path)
{
	RDD_READER *r = 0;
	RDD_FAULTY_READER *state = 0;
	FILE *fp = 0;
	int rc = RDD_OK;

	rc = rdd_new_reader(&r, &faulty_read_ops, sizeof(RDD_FAULTY_READER));
	if (rc != RDD_OK) {
		goto error;
	}

	state = (RDD_FAULTY_READER *) r->state;

	state->parent = parent;

	if ((fp = fopen(path, "r")) == NULL) {
		rc = RDD_EOPEN;
		goto error;
	}
	if ((rc = read_faults(fp, state)) != RDD_OK) {
	       goto error;
	}	       
	if (fclose(fp) == EOF) {
		rc = RDD_ECLOSE;
		goto error;
	}

	/* Sort fault specifications by mean fault position.
	 */
	qsort(state->faults, state->nfault, sizeof(RDDFAULT), &fault_compare);

	*self = r;
	return RDD_OK;

error:
	*self = 0;
	if (fp != NULL) fclose(fp);
	if (state != 0) free(state);
	if (r != 0) free(r);
	return rc;
}

/* Simulates a faulty reader.
 * 
 * The algorithm is as follows.  For each user-specified fault
 * we have a location of occurrence and a (fixed) probability
 * of occurrence.  For each fault covered by the read request,
 * we check if the fault 'occurs' this time.  If none of the
 * covered faults occur, we pass the request to the parent reader.
 * Otherwise we select the fault with the lowest position and let
 * it occur.
 *
 * If a fault occurs, we still execute a partial read
 * up to the location of the fault.  This allows us to check
 * whether rdd's saving and restoring of the current file position
 * works all right: flt_read will return -1, but it will also
 * have modified the file position.
 */
int
rdd_faulty_read(RDD_READER *self, unsigned char *buf, unsigned nbyte,
		unsigned *nread)
{
	RDD_FAULTY_READER *state = self->state;
	rdd_count_t pos;
	RDDFAULT *f;
	unsigned i;
	int rc;

	if ((rc = rdd_reader_tell(state->parent, &pos)) != RDD_OK) {
		return rc;
	}

	for (i = 0; i < state->nfault; i++) {
		f = &state->faults[i];

		if ((f->meanpos >= pos && f->meanpos < (pos + nbyte))
			/* The read request covers the fault.  */
		&&  (uniform_random(f->rngerr) < f->errprob))
			/* The fault occurs. */
		{
			rc = rdd_reader_read(state->parent, buf, nbyte, nread);
			if (rc != RDD_OK) {
				return rc; /* Hmm, true read error */
			}

			if (f->meanpos < (pos + *nread)) {
				/* The read result covers the fault. */
				return RDD_EREAD;
			} else {
				return RDD_OK;
			}
		}
	}

	/* No fault occurred; forward the read request to the parent reader.
	 */ 
	return rdd_reader_read(state->parent, buf, nbyte, nread);
}

int
rdd_faulty_tell(RDD_READER *self, rdd_count_t *pos)
{
	RDD_FAULTY_READER *state = self->state;

	return rdd_reader_tell(state->parent, pos);
}

int
rdd_faulty_seek(RDD_READER *self, rdd_count_t pos)
{
	RDD_FAULTY_READER *state = self->state;

	return rdd_reader_seek(state->parent, pos);
}

int
rdd_faulty_close(RDD_READER *self, int recurse)
{
	RDD_FAULTY_READER *state = self->state;

	if (recurse) {
		return rdd_reader_close(state->parent, 1);
	} else {
		return RDD_OK;
	}
}
