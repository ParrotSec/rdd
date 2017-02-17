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



#ifndef __filter_h__
#define __filter_h__

/** @file
 *  \brief Generic filter interface.
 *
 * A filter is an object that reads a data stream.  A filter can
 *  perform computations using the data stream's contents, but it
 *  is _not_ allowed to modify the data stream that is passed to it.
 *  The data that is sent to one filter may later be passed to another
 *  filter.
 *
 *  Two types of filters are distinguished: stream filters and block
 *  filters.  Both filters receive their input through successive
 *  calls to their input() routine.  Block filters must also supply
 *  a block size B and a block() routine.  The block routine is called
 *  after every B bytes of input data.  These B bytes, however, may be
 *  passed to the filter through multiple calls to the filter's input()
 *  routine.
 */
struct _RDD_FILTER;
struct _RDD_FILTER_OPS;

typedef int (*rdd_fltr_input_fun)(struct _RDD_FILTER *f,
				const unsigned char *buf, unsigned nbyte);

typedef int (*rdd_fltr_block_fun)(struct _RDD_FILTER *f, unsigned nbyte);

typedef int (*rdd_fltr_close_fun)(struct _RDD_FILTER *f);

typedef int (*rdd_fltr_rslt_fun)(struct _RDD_FILTER *f,
				unsigned char *buf, unsigned pos);

typedef int (*rdd_fltr_free_fun)(struct _RDD_FILTER *f);

typedef struct _RDD_FILTER_OPS {
	rdd_fltr_input_fun  input;	/* used to pass data to the filter */
	rdd_fltr_block_fun  block;	/* used to mark block boundaries */
	rdd_fltr_close_fun  close;	/* used to mark end of input */
	rdd_fltr_rslt_fun   get_result; /* used to obtain final result */
	rdd_fltr_free_fun   free;       /* deallocate filter state */
} RDD_FILTER_OPS;

typedef struct _RDD_FILTER {
	void           *state;
	RDD_FILTER_OPS *ops;
	unsigned        blocksize;	/* zero for stream filters */
	unsigned        pos;		/* position in current block */
} RDD_FILTER;

typedef void (*rdd_fltr_error_fun)(rdd_count_t pos,
				rdd_checksum_t expected, 
				rdd_checksum_t computed, void *env);

/* Constructors
 */
int rdd_new_filter(RDD_FILTER **f, RDD_FILTER_OPS *ops,
		unsigned statesize, unsigned blocksize);

int rdd_new_md5_streamfilter(RDD_FILTER **f);

int rdd_new_sha1_streamfilter(RDD_FILTER **f);

int rdd_new_write_streamfilter(RDD_FILTER **f, RDD_WRITER *writer);

int rdd_new_md5_blockfilter(RDD_FILTER **f,
		unsigned blocksize, const char *outpath, int overwrite);

int rdd_new_stats_blockfilter(RDD_FILTER **f,
		unsigned blocksize, const char *outpath, int overwrite);

int rdd_new_adler32_blockfilter(RDD_FILTER **f,
		unsigned blocksize, const char *outpath, int overwrite);

int rdd_new_crc32_blockfilter(RDD_FILTER **f,
		unsigned blocksize, const char *outpath, int overwrite);

int rdd_new_verify_adler32_blockfilter(RDD_FILTER **f, FILE *fp,
	unsigned blocksize, int swap, rdd_fltr_error_fun err, void *env);

int rdd_new_verify_crc32_blockfilter(RDD_FILTER **f, FILE *fp,
	unsigned blocksize, int swap, rdd_fltr_error_fun err, void *env);

/* Generic routines
 */
/** \brief Pushes a data buffer into a filter.
 *  \param f the filter
 *  \param buf the data buffer
 *  \param nbyte the size in bytes of data buffer \c buf
 *  \return Returns \c RDD_OK on success.
 *
 *  This function pushes buffer \c buf into filter \c f. The filter
 *  must not modify buffer \c buf. The filter will process the buffer
 *  as it sees fit.
 */
int rdd_filter_push(RDD_FILTER *f, const unsigned char *buf, unsigned nbyte);

/** \brief Closes a filter for input.
 *  \param f the filter
 *  \return Returns \c RDD_OK on success.
 *
 *  This function must be called exactly once after the last data buffer
 *  has been pushed into the filter (with \c rdd_filter_push()).
 */
int rdd_filter_close(RDD_FILTER *f);

/** \brief Obtains a filter's result.
 *  \param f the filter
 *  \param buf the client's result buffer
 *  \param nbyte the size of the client's result buffer
 *  \return Returns \c RDD_OK on success.
 *
 *  This function copies a filter's result value to a client buffer.
 *  A result is simply an array of bytes. The interpretation of the
 *  result bytes is filter-specific. Not all filters compute a result.
 */
int rdd_filter_get_result(RDD_FILTER *f, unsigned char *buf, unsigned nbyte);

/** \brief Deallocates a filter and its resources.
 *  \param f the filter
 *  \return Returns \c RDD_OK on success.
 *
 *  This function destroys a filter. No operations can be performed on
 *  a filter after this function has been called.
 */
int rdd_filter_free(RDD_FILTER *f);

#endif /* __filter_h__ */
