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



#ifndef __progres_h__
#define __progres_h__

/** @file
 *  \brief Progress class; used to track copy speed and progres.
 */

typedef struct _RDD_PROGRESS {
	double period;		/**< progress reporting interval (seconds) */
	rdd_count_t input_size; /**< size of input file or RDD_WHOLE_FILE */
	double start_time;	/**< time at which copying started */
	double last_time;	/**< time of last poll */
	rdd_count_t poll_delta;	/**< poll every poll_delta bytes */
	rdd_count_t curpos;	/**< current position in bytes */
	rdd_count_t last_pos;	/**< position of last successful poll */
} RDD_PROGRESS;

typedef struct _RDD_PROGRESS_INFO {
	rdd_count_t pos;	/* bytes */
	double speed;		/* bytes/s */
	double fraction;
} RDD_PROGRESS_INFO;

/** \brief Initializes a progress object.
 *  \param p a pointer to the progress object (allocated by the client).
 *  \param size the number of bytes to be copied (or RDD_WHOLE_FILE).
 *  \param secs the progress update interval in seconds.
 *  \return Returns RDD_OK on success.
 */
int rdd_progress_init(RDD_PROGRESS *p, rdd_count_t size, unsigned secs);

/** \brief Tells the progress object how much data has been copied so far.
 *  \param p a pointer to the progress object.
 *  \param pos the current position in the input stream (in bytes).
 *  \return Returns RDD_OK on success.
 *
 *  Successive calls to \c rdd_progress_update should pass monotonically
 *  nondecreasing \c pos values.
 */
int rdd_progress_update(RDD_PROGRESS *p, rdd_count_t pos);

/** \brief Obtains progress information from a progress object.
 *  \param p a pointer to the progress object.
 *  \param info a pointer to the progress information
 *  \return Returns RDD_OK on success. Returns RDD_EAGAIN if no new
 *  progress information is available; new information is made available
 *  at approximately the rate specified by the user's update interval.
 *
 *  If \c rdd_progress_update() returns \c RDD_OK then \c *info
 *  will contain new progress information. Field \c info->pos will
 *  be set to the last position passed to \c rdd_progress_update().
 *  Field \c info->speed will be set to the average copying speed in
 *  bytes per second.  The value of \c info->fraction
 *  (the fraction of work completed) can be computed only if the input
 *  size is known. If \c RDD_WHOLE_FILE was passed to \c rdd_progress_init()
 *  as the input size then \c info->fraction will invalid and will
 *  be set to a negative number.
 */
int rdd_progress_poll(RDD_PROGRESS *p, RDD_PROGRESS_INFO *info);

#endif /* __progres_h__ */
