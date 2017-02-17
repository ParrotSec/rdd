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
 * TCP support
 *
 * TODO: add checksumming.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include "rdd.h"
#include "rdd_internals.h"
#include "error.h"
#include "msgprinter.h"
#include "reader.h"
#include "writer.h"
#include "netio.h"

#if !defined(HAVE_SOCKLEN_T)
typedef int socklen_t;
#endif

/* Holds a 64-bit number in network format.
 */
struct netnum {
	unsigned lo;
	unsigned hi;
};

static int net_verbose;

static void
pack_netnum(struct netnum *packed, rdd_count_t num)
{
	packed->hi = htonl((num >> 32) & 0xffffffff);
	packed->lo = htonl(num & 0xffffffff);
}

static void
unpack_netnum(struct netnum *packed, rdd_count_t *num)
{
	rdd_count_t lo, hi;

	hi = (rdd_count_t) ntohl(packed->hi);
	lo = (rdd_count_t) ntohl(packed->lo);
	*num = (hi << 32) | lo;
}

/* Before any data is sent from the client to the server, the
 * client sends some metadata to the server.  The following information
 * is sent:
 * - length of output file name including terminating null byte (64 bits)
 * - file size (64 bits)
 * - block size (64 bits)
 * - output file name, including terminating null byte
 *
 * These items are transmitted by rdd_send_info and received by
 * rdd_recv_info.
 */
int
rdd_send_info(RDD_WRITER *writer, char *file_name,
		rdd_count_t file_size,
		rdd_count_t block_size,
		rdd_count_t split_size,
		unsigned flags)
{
	struct netnum hdr[5];
	unsigned flen;
	int rc;

	flen = strlen(file_name) + 1;
	if (flen > RDD_MAX_FILENAMESIZE) {
		return RDD_ERANGE;
	}

	pack_netnum(&hdr[0], (rdd_count_t) flen);
	pack_netnum(&hdr[1], file_size);
	pack_netnum(&hdr[2], block_size);
	pack_netnum(&hdr[3], split_size);
	pack_netnum(&hdr[4], (rdd_count_t) flags);

	rc = rdd_writer_write(writer,
			(const unsigned char *) hdr, sizeof hdr);
	if (rc != RDD_OK) {
		return rc;
	}

	rc = rdd_writer_write(writer, (unsigned char *) file_name, flen);
	if (rc != RDD_OK) {
		return rc;
	}

	/* TODO: add header checksum */

	return RDD_OK;
}

/* Reads exactly buflen bytes into buffer buf using reader.
 */
static int
receive(RDD_READER *reader, unsigned char *buf, unsigned buflen)
{
	unsigned nread = 0;
	int rc;

	rc = rdd_reader_read(reader, buf, buflen, &nread);
	if (rc != RDD_OK) {
		return rc;
	}
	if (nread != buflen) {
		return RDD_ESYNTAX;
	}

	return RDD_OK;
}

/* Receives a copy request header from an rdd client and extracts
 * all information from that header.
 */
int
rdd_recv_info(RDD_READER *reader, char **filename,
		rdd_count_t *file_size,
		rdd_count_t *block_size,
		rdd_count_t *split_size,
		unsigned *flagp)
{
	struct netnum hdr[5];
	rdd_count_t flen;
	rdd_count_t flags;
	int rc;

	rc = receive(reader, (unsigned char *) &hdr, sizeof hdr);
	if (rc != RDD_OK) {
		return rc;
	}

	/* TODO: verify header checksum */

	unpack_netnum(&hdr[0], &flen);
	unpack_netnum(&hdr[1], file_size);
	unpack_netnum(&hdr[2], block_size);
	unpack_netnum(&hdr[3], split_size);
	unpack_netnum(&hdr[4], &flags);

	*flagp = (unsigned) flags;

	if (flen > RDD_MAX_FILENAMESIZE) {
		return RDD_ERANGE;
	}
	if (flen <= 1) {
		return RDD_ESYNTAX;
	}
	if ((*filename = malloc(flen)) == 0) {
		return RDD_NOMEM;
	}
	rc = receive(reader, (unsigned char *) *filename, flen);
	if (rc != RDD_OK) {
		return rc;
	}
	if ((*filename)[flen-1] != '\0') {
		return RDD_ESYNTAX;
	}

	return RDD_OK;
}

int
rdd_init_server(RDD_MSGPRINTER *printer, unsigned port, int *server_sock)
{
	struct sockaddr_in addr;
	int sock = -1;
	int on = 1;

	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		rdd_mp_unixmsg(printer, RDD_MSG_ERROR, errno, 
			"cannot create TCP socket");
		goto error;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(port);

	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
		rdd_mp_unixmsg(printer, RDD_MSG_ERROR, errno, 
			"cannot set socket option SO_REUSEADDR");
		goto error;
	}
	if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		rdd_mp_unixmsg(printer, RDD_MSG_ERROR, errno, 
			"cannot bind TCP socket to local port %u", port);
		goto error;
	}
	if (listen(sock, 5) < 0) {
		rdd_mp_unixmsg(printer, RDD_MSG_ERROR, errno, 
			"cannot listen to TCP socket");
		goto error;
	}

	*server_sock = sock;
	return RDD_OK;

error:
	if (sock != -1) (void) close(sock);
	*server_sock = -1;
	return RDD_EOPEN;
}

int
rdd_await_connection(RDD_MSGPRINTER *printer, int server_sock,
	int *client_sock)
{
	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	int clsock = -1;

	if ((clsock = accept(server_sock, (struct sockaddr *)&addr, &len)) < 0) {
		rdd_mp_unixmsg(printer, RDD_MSG_ERROR, errno, 
			"cannot accept client connection");
		goto error;
	}

	if (net_verbose) {
		rdd_mp_message(printer, RDD_MSG_INFO, 
			"Accepted inbound connection from %s",
			inet_ntoa(addr.sin_addr));
	}

	*client_sock = clsock;
	return RDD_OK;

error:
	if (clsock != -1) (void) close(clsock);
	*client_sock = -1;
	return RDD_EOPEN;
}
