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



#ifndef __msgprinter_h__
#define __msgprinter_h__

/** @file
 *  \brief Generic printer interface.
 *
 * Uniform printer interface. An implementation of this interface
 * must supply a constructor and implement all \c RDD_MSGPRINTER_OPS (see
 * the structure definition below).
 * 
 * <h3>Printer types</h3>
 *
 * There are two types of writers: <em>bottom printers</em> and
 * <em>stackable printers</em>.
 * A stackable printer receives input, optionally transforms it in some way,
 * and passes the transformed data on to a lower-level parent printer.  The
 * parent printer is passed to the stackable printer at the time the stackable
 * printer is constructed.  The broadcast printer is a stackable writer.
 *
 * A bottom printer receives input, optionally transforms it in some way,
 * and passes the transformed data on to some output device (e.g. a
 * file stream), but not to another printer.  A bottom printer may
 * well use other printer types in its implementation, but that does
 * <strong>not</strong> make it a stackable printer.
 *
 *
 * <h3>Constructors</h3>
 *
 * Each constructor must be listed in this header file.
 * Once a printer has been constructed, it should be accessed
 * through the generic printer routines, \c rdd_mp_close(),
 * \c rdd_mp_print(), or one of the routines that are layered
 * on top of \c rdd_mp_print().
 */

#include <stdarg.h>
#include <stdio.h>

/** Values of type \c rdd_message_t specify the type of
 *  message that is passed to a printer instance.  The
 *  message type is used to format or display the message in an
 *  appropriate manner.
 */
typedef enum _rdd_message_t {
	RDD_MSG_INFO  = 0x1,	/*<< informative message */
	RDD_MSG_ERROR = 0x2,	/*<< error message */
	RDD_MSG_DEBUG = 0x4,	/*<< debug message */
	RDD_MSG_WARN  = 0x8	/*<< warning message */
} rdd_message_t;

/** Values of type \c rdd_mp_flags_t determine the behavior
 *  of a printer's \c close operation.  If \c RDD_MP_RECURSE
 *  is set, then a (stackable) printer will automatically
 *  close all parent printers.  If \c RDD_MP_READONLY is
 *  specified, then a printer that writes its messages to an
 *  output file will make that output file read-only when the
 *  printer is closed.
 */
typedef enum _rdd_mp_flags_t {
	RDD_MP_RECURSE  = 0x1,  /*<< close all children */
	RDD_MP_READONLY = 0x2   /*<< make output read-only */
} rdd_mp_flags_t;

struct _RDD_MSGPRINTER;

typedef void (*rdd_mp_print_fun)(struct _RDD_MSGPRINTER *printer,
			rdd_message_t type, int errcode, const char *msg);
typedef int (*rdd_mp_close_fun)(struct _RDD_MSGPRINTER *printer,
			unsigned flags);

/** All printer implementations provide a structure of type \c RDD_WRITE_OPS.
 *  This structure contains pointers to the routines that implement
 *  the interface.
 */
typedef struct _RDD_MSGPRINTER_OPS {
	rdd_mp_print_fun print;		/*<< prints a message */
	rdd_mp_close_fun close;		/*<< closes the printer instance */
} RDD_MSGPRINTER_OPS;

/** Printer object. A printer object consists of a print buffer
 *  (\c printbuf), a pointer to an operation table (\c ops),
 *  a pointer to a state buffer (\c state), and a message mask.
 */
typedef struct _RDD_MSGPRINTER {
	char                printbuf[1024];	/*<< print buffer */
	RDD_MSGPRINTER_OPS *ops;		/*<< operation table */
	void               *state;		/*<< printer state */
	RDD_UINT32          mask;		/*<< message mask */
} RDD_MSGPRINTER;

/** \brief Allocates and partially initializes a new printer object.
 *  \param printer output value: a new printer object.
 *  \param ops pointers to implementation-specific printer functions.
 *  \param statesize size in bytes of implementation-specific state.
 *  \return Returns \c RDD_OK on success. Returns \c RDD_NOMEM when
 *  there is insufficient memory to allocate the writer object or its state
 *  buffer.
 *
 *  \c rdd_mp_open_printer() allocates a writer object and initializes its
 *  \c ops field to argument \ops. The \c state field is set to point
 *  to a new buffer (allocated with \c malloc()) with size \c statesize.
 *  The state buffer is zeroed.  The mask is set so that it allows all
 *  message types to be printed.
 */  
int rdd_mp_open_printer(RDD_MSGPRINTER **printer, RDD_MSGPRINTER_OPS *ops,
		unsigned statesize);

/* Constructor routines that create writers of specific types
 */

/** \brief Opens a broadcast printer. A broadcast printer is a stackable
 *  printer that prints all its messages to all its parent printers.
 */
int rdd_mp_open_bcast_printer(RDD_MSGPRINTER **printer,
		unsigned nprinter, RDD_MSGPRINTER **printers);

/** \brief Opens a stream printer. A stream printer prints all its
 *  messages to a standard I/O file stream (\c stream).
 */
int rdd_mp_open_stdio_printer(RDD_MSGPRINTER **printer, FILE *stream);

/** \brief Opens a log printer.  A log printer is a stackable printer
 *  that prepends to each message a timestamp.  The resulting, concatenated
 *  message is forwarded to parent printer \c next.
 */
int rdd_mp_open_log_printer(RDD_MSGPRINTER **printer, RDD_MSGPRINTER *next);

/** \brief Opens a file printer.  A file printer prints all its messages
 *  to a named output file.
 */
int rdd_mp_open_file_printer(RDD_MSGPRINTER **printer, const char *path);

/** \brief Closes a printer instance.
 */
int rdd_mp_close(RDD_MSGPRINTER *printer, unsigned flags);

/** \brief Retrieves a printer's current message mask.
 */
RDD_UINT32 rdd_mp_get_mask(RDD_MSGPRINTER *printer);

/** \brief Sets a printer's current message mask to value \c mask.
 */
void rdd_mp_set_mask(RDD_MSGPRINTER *printer, RDD_UINT32 mask);

/** \brief Formats and prints a message.
 */
void rdd_mp_print(RDD_MSGPRINTER *printer,
		rdd_message_t type, int errcode, const char *fmt, ...);

/** \brief Formats and prints a message for a varargs routine.
 */
void rdd_mp_vmessage(RDD_MSGPRINTER *printer,
		rdd_message_t type, const char *fmt, va_list ap);

/** \brief Formats and prints a message.
 */
void rdd_mp_message(RDD_MSGPRINTER *printer,
		rdd_message_t type, const char *fmt, ...);

/** \brief Formats and prints a Unix error message.  The value of
 *  \c unix_errno must be one of the values defined in <errno.h>.
 *  This routine will append the error message that corresponds to
 *  \c unix_errno to the user's message and print the resulting,
 *  concatenated message.
 */
void rdd_mp_unixmsg(RDD_MSGPRINTER *printer,
		rdd_message_t type, int unix_errno, const char *fmt, ...);

/** \brief Formats and prints an RDD error message.  The value of
 *  \c rdd_errno must be one of the values defined in rdd.h.
 *  This routine will append the error message that corresponds to
 *  \c rdd_errno to the user's message and print the resulting,
 *  concatenated message.
 */
void rdd_mp_vrddmsg(RDD_MSGPRINTER *printer,
		rdd_message_t type, int rdd_errno, const char *fmt, va_list ap);

/** \brief Formats and prints an RDD error message.  The value of
 *  \c rdd_errno must be one of the values defined in rdd.h.
 *  This routine will append the error message that corresponds to
 *  \c rdd_errno to the user's message and print the resulting,
 *  concatenated message.
 */
void rdd_mp_rddmsg(RDD_MSGPRINTER *printer,
		rdd_message_t type, int rdd_errno, const char *fmt, ...);

#endif /* __msgprinter_h__ */
