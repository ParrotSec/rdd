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



#ifndef __reader_h__
#define __reader_h__

/** @file
 *  \brief Generic reader interface.
 *
 *  This header file defines rdd's uniform reader interface.
 *  The rdd package contains multiple implementations of this
 *  interface (see the files named <tt>*reader.c</tt>).
 */

/** Forward declarations.
 */
struct _RDD_READER;
struct _RDD_READ_OPS;

typedef int (*rdd_rd_read_fun)(struct _RDD_READER *r,
				unsigned char *buf, unsigned nbyte,
				unsigned *nread);

typedef int (*rdd_rd_tell_fun)(struct _RDD_READER *r, rdd_count_t *pos);

typedef int (*rdd_rd_seek_fun)(struct _RDD_READER *r, rdd_count_t pos);

typedef int (*rdd_rd_close_fun)(struct _RDD_READER *r, int recurse);

/** All reader implementations provide a structure of type \c RDD_READ_OPS.
 *  This structure contains pointers to the routines that implement
 *  the interface.
 */
typedef struct _RDD_READ_OPS {
	rdd_rd_read_fun  read;
	rdd_rd_tell_fun  tell;
	rdd_rd_seek_fun  seek;
	rdd_rd_close_fun close;
} RDD_READ_OPS;

/** A reader object consists of a pointer to implementation-defined state and
 *  a pointer to the routines that implement the uniform interface.
 */
typedef struct _RDD_READER {
	void         *state;	/**< implementation-specific state */
	RDD_READ_OPS *ops;	/**< implementation's operation table */
} RDD_READER;

/** \brief Allocates and partially initializes a reader object.
 *  \param r output value: a new reader object.
 *  \param ops pointers to implementation-specific reader functions.
 *  \param statesize size in bytes of implementation-specific state.
 *  \return Returns \c RDD_OK on success. Returns \c RDD_NOMEM when
 *  there is insufficient memory to allocate the reader object or its state
 *  buffer.
 *
 *  \c rdd_new_reader allocates a reader object and initializes its
 *  \c ops field to argument \ops. The \c state field is set to point
 *  to a new buffer (allocated with \c malloc()) with size \c statesize.
 *  The state buffer is zeroed. 
 */  
int rdd_new_reader(RDD_READER **r, RDD_READ_OPS *ops, unsigned statesize);

/** Constructors
 */

/** \brief Instantiates a reader that reads from an open file descriptor.
 *  \param r output value: a new reader object.
 *  \param fd the open file descriptor that the reader will read from.
 *  \return Returns \c RDD_OK on success.
 *
 *  A file descriptor reader is a simple reader that simply reads
 *  bytes from a file descriptor.
 */
int rdd_open_fd_reader(RDD_READER **r, int fd);

/** \brief Instantiates a reader that reads from an open file descriptor
 *  that refers to a raw block device.
 *  \param r output value: a new reader object.
 *  \param fd the open file descriptor that the reader will read from.
 *  \return Returns \c RDD_OK on success.
 *
 *  A file descriptor reader is a simple reader that simply reads
 *  bytes from a file descriptor.
 */
int rdd_open_raw_reader(RDD_READER **r, int fd);

/** \brief Instantiates a reader that reads from a reader that expects
 *  aligned accesses and aligned user buffers.
 *  \param r output value: a new reader object.
 *  \param parent output value: the parent reader.
 *  \param align alignment in bytes.
 *  \return Returns \c RDD_OK on success.
 *
 *  A file descriptor reader is a simple reader that simply reads
 *  bytes from a file descriptor.
 */
int rdd_open_aligned_reader(RDD_READER **r, RDD_READER *parent, unsigned align);

/** \brief Instantiates a reader that reads from a file.
 *  \param r output value: a new reader object.
 *  \param path the name of the file that the reader will read from.
 *  \param raw true iff \c path refers to a raw-device file
 *  \return Returns \c RDD_OK on success.
 *
 *  A file reader opens a file and reads from it.
 */
int rdd_open_file_reader(RDD_READER **r, const char *path, int raw);

/** \brief Instantiates a reader that does not move the file pointer
 *  when a read error occurs.
 *  \param r output value: a new reader object.
 *  \param p an existing parent reader.
 *
 * An atomic reader adds predictability to an existing reader \c p.
 * All read requests received by \c r are forwarded to \c p. If a
 * read on \c p fails with error code \c RDD_EREAD, then \c r will
 * restore the file position to the same value it had before the
 * read was issued.
 *
 * \b Note: the parent reader \c p \b MUST implement the \c seek()
 * and \c tell() operations.
 */
int rdd_open_atomic_reader(RDD_READER **r, RDD_READER *p);

/** \brief Instantiates a reader that decompresses zlib-compressed data.
 *  \param r output value: a new reader object.
 *  \param p an existing parent reader.
 *
 *  A zlib reader adds transparent decompression to an existing
 *  parent reader \c p that reads zlib-compressed data.
 *
 *  \b Note: a zlib reader does not implement the \c seek() routine.
 */
int rdd_open_zlib_reader(RDD_READER **r, RDD_READER *p);

int rdd_open_cdrom_reader(RDD_READER **r, const char *path);

/** \brief Instantiates a reader that simulates read errors.
 *  \param r output value: a new reader object.
 *  \param p an existing parent reader.
 *  \param specfile a file that specifies the file positions at which
 *  read errors should be simulated by this reader.
 */
int rdd_open_faulty_reader(RDD_READER **r, RDD_READER *p, char *specfile);

#if 0
int rdd_open_aligned_reader(RDD_READER **r, RDD_READER *p,
		unsigned alignment, unsigned bufsize);
#endif

/* Generic dispatch routines
 */
/** \brief Generic read routine.
 *  \param r pointer to the reader object.
 *  \param buf pointer to the target buffer; the size of this buffer
 *             must be at least \c nbyte bytes.
 *  \param nbyte the number of bytes to read
 *  \param nread output value: the number of bytes actually read;
 *         the value in \c *read is valid only if \c RDD_OK is returned.
 *  \return Returns RDD_OK if the read succeeds. If the read succeeds,
 *  \c *nread will be equal to \c nbyte except when there are fewer
 *  than \c nbyte bytes left until the end of the file is reached.
 *  In that case \c *nread will be equal to the number of bytes left.
 *  If \c *nread equals \c 0, then end-of-file has been reached.
 */
int rdd_reader_read(RDD_READER *r, unsigned char *buf, unsigned nbyte,
		unsigned *nread);

/** \brief Returns the current file position in bytes.
 *  \param r  pointer to the reader object.
 *  \param pos output value: the current file position in bytes.
 *  The value in \c *pos is valid only if \c RDD_OK is returned.
 *  \return Returns RDD_OK on success.
 */
int rdd_reader_tell(RDD_READER *r, rdd_count_t *pos);

/** \brief Updates the current file position.
 *  \param r  pointer to the reader object.
 *  \param pos the new (absolute) file position in bytes.
 *  \return Returns RDD_OK on success.
 *
 *  \b Note: not all readers implement the \c seek() routine.
 */
int rdd_reader_seek(RDD_READER *r, rdd_count_t pos);

/** \brief Moves the file pointer \c skip bytes forward.
 *  \param r  pointer to the reader object.
 *  \param skip the number of bytes to move forward.
 *  \return Returns RDD_OK on success.
 *
 *  \b Note: not all readers implement the \c skip() routine.
 */
int rdd_reader_skip(RDD_READER *r, rdd_count_t skip);

/** \brief Closes and deallocates the reader object.
 *  \param r  pointer to the reader object.
 *  \param recurse recursive-close flag
 *  \return Returns RDD_OK on success.
 *
 *  All resources associated with the reader are released.
 *  If this reader is stacked on top of other readers, then
 *  those readers will also be closed iff \c recurse is nonzero.
 */
int rdd_reader_close(RDD_READER *r, int recurse);

#endif /* __reader_h__ */
