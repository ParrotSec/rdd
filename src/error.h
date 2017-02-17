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



#ifndef __error_h__
#define __error_h__

/** @file
 *  \brief Module that handles messages (errors, warnings, etc.).
 */

#include <stdarg.h>
#include <stdio.h>

/** \brief Sets the program name that is used in future error messages.
 *  \param name the program's name
 *
 *  This function must be called before any routine that produces
 *  a message.
 */
void set_progname(char *name);

/** \brief Sets the log file.
 *  \param fp a valid file pointer (open for writing)
 *
 *  This function sets the log file. All messages produced by this
 *  module are sent to the console or, if there is no console,
 *  to the standard error stream (\c stderr). If a valid log file 
 *  (not \c NULL) is specified then all messages are also written
 *  to that log file.
 */
void set_logfile(FILE *fp);

/** \brief Reports a bug and aborts program execution.
 *  \param fmt a printf-style message format string
 *
 *  The format string must be followed by its arguments,
 *  just like a printf-style format string. This function
 *  prints the message and then calls \c abort() to terminate
 *  the program.
 */
void bug(char *fmt, ...);

/** \brief Prints an error message and terminates the program.
 *  \param fmt a printf-style message format string
 *
 *  The format string must be followed by its arguments,
 *  just like a printf-style format string. This function
 *  prints the message and then calls \c exit() to terminate
 *  the program.
 */
void error(char *fmt, ...);

/** \brief Reports an warning message and terminates the program.
 *  \param fmt a printf-style message format string
 *
 *  The format string must be followed by its arguments,
 *  just like a printf-style format string. This function
 *  prints the message. It does \b not terminate the program.
 */
void warn(char *fmt, ...);

/** \brief Prints a Unix error message.
 *  \param fmt a printf-style message format string
 *
 *  The format string must be followed by its arguments,
 *  just like a printf-style format string. This function
 *  prints the message and then calls \c exit() to terminate
 *  the program. The message is followed by the error message that
 *  corresponds with the current value of Unix error variable \c errno.
 */
void unix_error(char *fmt, ...);

/** \brief Prints a Unix warning message.
 *  \param fmt a printf-style message format string
 *
 *  The format string must be followed by its arguments,
 *  just like a printf-style format string. This function
 *  prints the message. The message is followed by the error message that
 *  the program. The message is followed the error message that
 *  corresponds with the current value of Unix error variable \c errno.
 *  This function does \b not terminate the program.
 */
void unix_warn(char *fmt, ...);

/** \brief Prints a message.
 */
void errlog(char *fmt, ...);

/** \brief Appends a newline to a message and then prints that message.
 */
void errlognl(char *fmt, ...);

/** \brief Prints an rdd error message and terminates the program.
 *  \param errcode an rdd error code
 *  \param fmt a printf-style message format string
 *
 *  The format string \c fmt must be followed by its arguments,
 *  just like a printf-style format string. This function
 *  prints the message and then calls \c exit() to terminate
 *  the program. The message is followed by the error message that
 *  corresponds with rdd error code \c rc.
 */
void rdd_error(int errcode, char *fmt, ...);

#endif /* __error_h__ */
