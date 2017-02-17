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



#ifndef __alignedbuf_h__
#define __alignedbuf_h__

/** @file
 */

/** \brief Aligned-buffer descriptor.
 *
 *  RDD_ALIGNEDBUF contains two pointer members. Member \c unaligned
 *  contains a pointer to a buffer allocated with \c malloc().
 *  Member \c aligned points to a location within the same buffer,
 *  but has been aligned to a user-specified byte count.
 *  The following equations should always hold:\n
 *  (1) <tt> 0 <= aligned - unaligned < user_alignment </tt>;\n
 *  (2) <tt> (aligned % align) == 0</tt>.
 */
typedef struct RDD_ALIGNEDBUF {
	unsigned char *unaligned;	/*<< actual buffer */
	unsigned char *aligned;		/*<< aligned buffer */
	unsigned asize;			/*<< aligned buffer size */
	unsigned align;			/*<< alignment in bytes */
} RDD_ALIGNEDBUF;

/** \brief Allocates a buffer of \c sz bytes and returns
 *  two pointers in \c buf: a pointer to the buffer and
 *  a pointer that has been aligned to \c align bytes.
 *
 * \param buf pointer to an \c RDD_ALIGNEDBUF structure allocated by
 * the client.
 * \param sz size in bytes of the data buffer that will be allocated;
 * there will be at least \c sz bytes of free space in the aligned buffer.
 * \param align alignment in bytes.
 * \return Returns \c RDD_OK on success. Returns \c RDD_NOMEM if
 * there is insufficient memory to allocate the buffer. Returns
 * \c RDD_BADARG if a bad alignment argument is given.
 */  
int rdd_new_alignedbuf(RDD_ALIGNEDBUF *buf, unsigned sz, unsigned align);

/** \brief Deallocates the data buffer associated with \c buf and
 *  invalidates both pointer fields in \c buf.
 *
 *  \param buf pointer to an \c RDD_ALIGNEDBUF structure that was
 *  allocated by the client and initialized by calling
 *  \c rdd_new_aligned_buf().
 *  \return Always returns RDD_OK.
 */
int rdd_free_alignedbuf(RDD_ALIGNEDBUF *buf);

/** \brief Returns the size in bytes of an aligned buffer.
 *
 *  \param buf pointer to an \c RDD_ALIGNEDBUF structure that was
 *  allocated by the client and initialized by calling
 *  \c rdd_new_aligned_buf().
 *  \return The size in bytes of the aligned buffer
 */
unsigned rdd_abuf_get_size(RDD_ALIGNEDBUF *buf);

/** \brief Returns the alignment in bytes of an aligned buffer.
 *
 *  \param buf pointer to an \c RDD_ALIGNEDBUF structure that was
 *  allocated by the client and initialized by calling
 *  \c rdd_new_aligned_buf().
 *  \return the alignment in bytes of the aligned buffer
 */
unsigned rdd_abuf_get_alignment(RDD_ALIGNEDBUF *buf);

#endif /* __alignedbuf_h__ */
