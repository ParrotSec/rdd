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



#ifndef __writer_h__
#define __writer_h__

/** @file
 *  \brief Generic writer interface.
 *
 * Uniform writer interface. An implementation of this interface
 * must supply a constructor and implement all \c RDD_WRITE_OPS (see
 * the structure definition below).
 * 
 * <h3>Writer types</h3>
 *
 * There are two types of writers: <em>bottom writers</em> and
 * <em>stackable writers</em>.
 * A stackable writer receives input, optionally transforms it in some way,
 * and passes the transformed data on to a lower-level parent writer.  The
 * parent writer is passed to the stackable writer at the time the stackable
 * writer is constructed.  The zlib writer is a stackable writer.
 *
 * A bottom writer receives input, optionally transforms it in some way,
 * and passes the transformed data on to some output device (e.g. a
 * file descriptor), but not to another writer.  A bottom writer may
 * well use other writer types in its implementation, but that does
 * <strong>not</strong> make it a stackable writer.
 *
 *
 * <h3>Constructors</h3>
 *
 * Each constructor must be listed in this header file.
 * Once a writer has been constructed, it should be accessed
 * through the generic writer routines, \c rdd_writer_write() and
 * \c rdd_writer_close().
 */

struct _RDD_WRITER;
struct _RDD_WRITE_OPS;

/** Values of type \c rdd_write_mode_t determine the behavior
 *  of writers that try to write to an existing file.
 */
typedef enum _rdd_write_mode_t {
	RDD_NO_OVERWRITE = 0,	/**< do not overwrite existing files */
	RDD_OVERWRITE = 1,	/**< truncate and overwrite existing files */
	RDD_OVERWRITE_ASK = 2	/**< ask before overwriting existing files */
} rdd_write_mode_t;

typedef int (*rdd_wr_write_fun)(struct _RDD_WRITER *w,
				const unsigned char *buf, unsigned nbyte);

typedef int (*rdd_wr_close_fun)(struct _RDD_WRITER *w);

/** All writer implementations provide a structure of type \c RDD_WRITE_OPS.
 *  This structure contains pointers to the routines that implement
 *  the interface.
 */
typedef struct _RDD_WRITE_OPS {
	rdd_wr_write_fun write;	/**< writes data to the output channel */
	rdd_wr_close_fun close;	/**< closes the writer */
} RDD_WRITE_OPS;

/** Writer object. A writer object consists of a pointer to a state
 *  buffer and a pointer to an operation table.
 */
typedef struct _RDD_WRITER {
	void          *state;	/**< implementation-specific writer state */
	RDD_WRITE_OPS *ops;	/**< implementation-specific writer routines */
} RDD_WRITER;

/** \brief Allocates and partially initializes a new writer object.
 *  \param w output value: a new writer object.
 *  \param ops pointers to implementation-specific writer functions.
 *  \param statesize size in bytes of implementation-specific state.
 *  \return Returns \c RDD_OK on success. Returns \c RDD_NOMEM when
 *  there is insufficient memory to allocate the writer object or its state
 *  buffer.
 *
 *  \c rdd_new_writer() allocates a writer object and initializes its
 *  \c ops field to argument \ops. The \c state field is set to point
 *  to a new buffer (allocated with \c malloc()) with size \c statesize.
 *  The state buffer is zeroed. 
 */  
int rdd_new_writer(RDD_WRITER **w, RDD_WRITE_OPS *ops, unsigned statesize);

/* Constructor routines that create writers of specific types
 */

/** \brief Creates a writer that compresses its input before writing it.
 *  \param w output value: the new writer object
 *  \param parent: all compressed output is written to \c parent
 *  \return Returns \c RDD_OK on success.
 *
 *  A zlib writer is stacked on top of a parent writer. Any data
 *  written to the zlib writer is written through to the parent
 *  writer in compressed zlib format.
 */
int rdd_open_zlib_writer(RDD_WRITER **w, RDD_WRITER *parent);

/** \brief Creates a writer that writes to an open file descriptor.
 *  \param w output value: the new writer object
 *  \param fd the open file descriptor that the new writer will write to
 *  \return Returns \c RDD_OK on success.
 */
int rdd_open_fd_writer(RDD_WRITER **w, int fd);

/** \brief Creates a writer that writes to a file.
 *  \param w output value: the new writer object
 *  \param path the name of the file that the new writer will write to
 *  \return Returns \c RDD_OK on success.
 *
 *  Routine \c rdd_open_file_writer() will create file \c path if
 *  it does not exist. It will fail if the directory in which \c
 *  path must be created does not exist.  If \c path already exists
 *  then \c rdd_open_file_writer() will silently truncate the existing
 *  file.
 */
int rdd_open_file_writer(RDD_WRITER **w, const char *path);

/** \brief Creates a writer that writes to a TCP server.
 *  \param w output value: the new writer object
 *  \param host the name of the server host
 *  \param port the TCP port number on the server host
 *  \return Returns \c RDD_OK on success.
 *
 *  Routine \c rdd_open_tcp_writer() connects to a TCP server that runs
 *  on \c host and listens to TCP port \c port.  Any data written to
 *  the TCP writer is passed on to the server process at the other
 *  end of the TCP connection.
 */
int rdd_open_tcp_writer(RDD_WRITER **w, const char *host, unsigned port);

/** \brief Creates a writer that does not blindly overwrite existing files.
 *  \param w output value: the new writer object
 *  \param path the name of the file that the new writer will write to
 *  \param overwrite indicates what to do when \c path exists
 *  \return Returns \c RDD_OK on success.
 *
 *  A safe writer behaves almost exactly like a file writer. The key
 *  difference is that a safe writer will only overwrite an existing
 *  file if \c overwrite equals \c RDD_OVERWRITE. Otherwise
 *  \c rdd_open_safe_writer() will fail.
 */
int rdd_open_safe_writer(RDD_WRITER **w, const char *path,
			rdd_write_mode_t overwrite);

/** \brief Creates a writer that can split its output over multiple files.
 *  \param w output value: the new writer object
 *  \param basepath template for output file names
 *  \param maxlen maximum number of bytes that will be written
 *  \param splitlen maximum size in bytes of each output file
 *  \param overwrite indicates what to do when an output file already exists
 *  \return Returns \c RDD_OK on success.
 *
 *  Routine \c rdd_open_part_writer() splits the data stream it receives
 *  over a sequence of output files. The first \c splitlen bytes are
 *  written to output file number one, the next \c splitlen bytes to
 *  output file number two, and so on.  The name of each output file
 *  consists of:
 *  - the directory part of \c basepath;
 *  - the output file's sequence number;
 *  - a dash;
 *  - the base name of \c basepath.
 */
int rdd_open_part_writer(RDD_WRITER **w,
	const char *basepath, rdd_count_t maxlen, rdd_count_t splitlen,
	rdd_write_mode_t overwrite);


/* Generic writer routines
 */

/** \brief Writes a data buffer to the output channel associated with a writer.
 *  \param w a pointer to the writer object.
 *  \param buf a pointer to the data buffer.
 *  \param nbyte the number of bytes to write
 *  \return Returns \c RDD_OK on success.
 *
 *  Routine \c rdd_writer_write() writes the first \c nbyte bytes
 *  in buffer \c buf to an output channel. The identity and the
 *  nature of the output channel is determined by the type of writer
 *  object is used and by the arguments that were passed to the writer's
 *  constructor.
 *
 *  When rdd_writer_write() returns, data buffer \c buf can safely be
 *  reused.
 */
int rdd_writer_write(RDD_WRITER *w, const unsigned char *buf, unsigned nbyte);

/** \brief Closes a writer AND all writers that are below it in the
 *  writer stack.
 *  \param w a pointer to the writer object.
 *
 * When writer \c w is closed its resources are released and 
 * no further writes can be issued to writer \c w. At present,
 * all writers stacked below \c w are closed as well.  This behavior
 * may change in the future.
 */
int rdd_writer_close(RDD_WRITER *w);

RDD_WRITER *rdd_test_get_writer(int argc, char **argv);

#endif /* __writer_h__ */
