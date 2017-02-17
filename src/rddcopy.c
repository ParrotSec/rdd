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


/*
 * This program, rdd, copies data from one file to another. It is
 * more robust with respect to read errors than most Unix utilities.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "rdd.h"
#include "rdd_internals.h"

/* PLEASE keep the includes for crypto.h and zlib.h in this
 * order (crypto.h first); zlib.h introduces a typedef (free_func)
 * that conflicts with a parameter name in crypto.h.  This problem
 * occurs only in older versions.
 */
#if defined(HAVE_LIBCRYPTO) && defined(HAVE_OPENSSL_CRYPTO_H)
#include <openssl/crypto.h>
#endif
#if defined(HAVE_LIBZ)
#include <zlib.h>
#else
#error Sorry, need libz to compile
#endif

#include "numparser.h"
#include "reader.h"
#include "commandline.h"
#include "error.h"
#include "writer.h"
#include "filter.h"
#include "filterset.h"
#include "copier.h"
#include "netio.h"
#include "progress.h"
#include "msgprinter.h"

#define DEFAULT_BLOCK_LEN	    262144	/* bytes */
#define DEFAULT_MIN_BLOCK_SIZE	     32768	/* bytes */
#define DEFAULT_HIST_BLOCK_SIZE	    262144	/* bytes */
#define DEFAULT_CHKSUM_BLOCK_SIZE    32768	/* bytes */
#define DEFAULT_BLOCKMD5_SIZE         4096	/* bytes */

#define DEFAULT_NRETRY               1
#define DEFAULT_RECOVERY_LEN	     4	/* read blocks */
#define DEFAULT_MAX_READ_ERR	     0	/* 0 = infinity */
#define DEFAULT_RDD_SERVER_PORT       4832

#define RDD_MAX_DIGEST_LENGTH       20		/* bytes */

/* Mode bits
 */
typedef enum _rdd_copy_mode_t {
	RDD_LOCAL  = 0x1,	/* read file, write file */
	RDD_CLIENT = 0x2,	/* read file, write network */
	RDD_SERVER = 0x4	/* read network, write file */
} rdd_copy_mode_t;

#define ALL_MODES (RDD_LOCAL|RDD_CLIENT|RDD_SERVER)

/* rdd's command-line arguments
 */
typedef struct _rdd_copy_opts {
	int       compress;		/* compression enabled? */
	int       quiet;		/* batch mode (no questions)? */
	char     *infile;		/* input file (source of copy) */
	char     *logfile;		/* log file */
	char     *outpath;		/* output file or its prefix */
	char     *simfile;		/* read-fault simulation config file */
	char     *crc32file;		/* output file for CRC32 checksums */
	char     *adler32file;		/* output file for Adler32 checksums */
	char     *histfile;		/* output file for histogram stats */
	char     *blockmd5file;		/* output file for blockwise MD5 */
	int       verbose;		/* Be verbose? */
	int       raw;			/* Reading from a raw device? */
	unsigned  mode;			/* local, client, or server mode */
	int       inetd;		/* read from file desc. 0? */
	char     *server_host;		/* host name of rdd server */
	unsigned  server_port;		/* TCP port of rdd server */
	int       force_overwrite;	/* output overwrites existing files */
	int       md5;			/* MD5-hash all data? */
	int       sha1;			/* SHA1-hash all data? */
	unsigned  nretry;		/* Max. # read retries for bad blocks */
	rdd_count_t  blocklen;		/* default copy-block size */
	rdd_count_t  adler32len;	/* block size for Adler32 */
	rdd_count_t  crc32len;		/* block size for CRC32 */
	rdd_count_t  histblocklen;	/* histogramming block size */
	rdd_count_t  blockmd5len;	/* block size for block-wise MD5 */
	rdd_count_t  minblocklen;	/* unit of data loss */
	rdd_count_t  offset;		/* start copying here */
	rdd_count_t  count;		/* copy this many bytes */
	rdd_count_t  splitlen;		/* create new output file every splitlen bytes */
	rdd_count_t  progresslen;	/* progress reporting interval (s) */
	rdd_count_t  max_read_err;	/* Max. # read errors allowed */
} rdd_copy_opts;

static rdd_copy_opts  opts;

static char* usage_message = "\n"
	"\trdd-copy [local options] infile [outfile]\n"
	"\trdd-copy -C [client options] <local file> <remote file>\n"
	"\trdd-copy -S [server options]\n";

static RDD_OPTION opttab[] = {
	{"-?", "--help", 0, ALL_MODES,
	 	"Print this message", 0, 0},
	{"-C", "--client", 0, 0,
	 	"Run rdd as a network client", 0, 0},
	{"-F", "--fault-simulation", "<file>", RDD_LOCAL|RDD_CLIENT,
	 	"simulate read errors specified in <file>", 0, 0},
	{"-M", "--max-read-err", "<count>", RDD_LOCAL|RDD_CLIENT,
	 	"Give up after <count> read errors", 0, 0},
	{"-P", "--progress", "<sec>", ALL_MODES,
	 	"Report progress every <sec> seconds", 0, 0},
	{"-S", "--server", 0, 0, 
	 	"Run rdd as a network server", 0, 0},
	{"-V", "--version", 0, ALL_MODES,
         	"Report version number and exit", 0, 0},
	{"-b", "--block-size", "<count>[kKmMgG]", RDD_LOCAL|RDD_CLIENT,
	 	"Read blocks of <count> [KMG]byte at a time", 0, 0},
	{"-c", "--count", "<count>[kKmMgG]", ALL_MODES,
	 	"Read at most <count> [KMG]bytes", 0, 0},
	{"-f", "--force", 0, RDD_LOCAL|RDD_SERVER,
	 	"Ruthlessly overwrite existing files", 0, 0},
	{"-i", "--inetd", 0, RDD_SERVER, 
	 	"rdd is started by (x)inetd", 0, 0},
	{"-l", "--log-file", "<file>", ALL_MODES,
		"Log messages in <file>", 0, 0},
	{"-m", "--min-block-size", "<count>[kKmMgK]", RDD_LOCAL|RDD_CLIENT,
	 	"Minimum read-block size is <count> [KMG]byte", 0, 0},
	{"-n", "--nretry", "<count>", RDD_LOCAL|RDD_CLIENT,
	 	"Retry failed reads <count> times", 0, 0},
	{"-o", "--offset", "<count>[kKmMgG]", ALL_MODES,
	 	"Skip <count> [KMG] input bytes", 0, 0},
	{"-p", "--port", "<portnum>", RDD_CLIENT|RDD_SERVER,
	 	"Set server port to <port>", 0, 0},
	{"-q", "--quiet", 0, ALL_MODES,
	 	"Do not ask questions", 0, 0},
	{"-r", "--raw", 0, RDD_LOCAL|RDD_CLIENT,
	 	"Read from a raw device (/dev/raw/raw[0-9])", 0, 0},
	{"-s", "--split", "<count>[kKmMgG]", RDD_LOCAL|RDD_CLIENT,
	 	"Split output, all files < <count> [KMG]bytes", 0, 0},
	{"-v", "--verbose", 0, ALL_MODES,
	 	"Be verbose", 0, 0},
	{"-z", "--compress", 0, RDD_CLIENT,
	 	"Compress data sent across the network", 0, 0},
	{"-H", "--histogram", "<file>", ALL_MODES,
	 	"Store histogram-derived stats in <file>", 0, 0},
	{"-h", "--histogram-block-size", "<size>", ALL_MODES,
	 	"Histogramming block size", 0, 0},
	{"--checksum", "--adler32", "<file>", ALL_MODES,
	 	"Compute and store Adler32 checksums in <file>", 0, 0},
	{"--checksum-block-size", "--adler32-block-size", "<size>", ALL_MODES,
	 	"Adler32 uses <size>-byte blocks", 0, 0},
	{"--crc32", "--crc32", "<file>", ALL_MODES,
	 	"Compute and store CRC32 checksums in <file>", 0, 0},
	{"--crc32-block-size", "--crc32-block-size", "<size>", ALL_MODES,
	 	"CRC32 uses <size>-byte blocks", 0, 0},
	{"--md5", "--md5", 0, ALL_MODES,
	 	"Compute and print MD5 hash", 0, 0},
	{"--sha", "--sha1", 0, ALL_MODES,
	 	"Compute and print SHA1 hash", 0, 0},
	{"--block-md5-size", "--block-md5-size", "<size>", ALL_MODES,
	 	"block-wise MD5 block size", 0, 0},
	{"--block-md5", "--block-md5", "<file>", ALL_MODES,
	 	"Store block-wise MD5 hash values in <file>", 0, 0},
	{0, 0, 0, 0, 0, 0, 0} /* sentinel */
};

static RDD_MSGPRINTER *the_printer;

static void
fatal_rdd_error(int rdd_errno, char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	rdd_mp_vrddmsg(the_printer, RDD_MSG_ERROR, rdd_errno, fmt, ap);
	va_end(ap);
	exit(EXIT_FAILURE);
}

static void
logmsg(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	rdd_mp_vmessage(the_printer, RDD_MSG_INFO, fmt, ap);
	va_end(ap);
}

/* Wrappers around the number-parsing routines.
 */
static rdd_count_t
scan_size(char *str, unsigned flags)
{
	rdd_count_t sz;
	int rc;

	if ((rc = rdd_parse_bignum((const char *) str, flags, &sz)) != RDD_OK) {
		fatal_rdd_error(rc, "bad number %s", str);
	}
	return sz;
}

static unsigned
scan_uint(char *str)
{
	unsigned n;
	int rc;

	if ((rc = rdd_parse_uint((const char *) str, &n)) != RDD_OK) {
		fatal_rdd_error(rc, "%s", str);
	}
	return n;
}

static unsigned
scan_tcp_port(char *str)
{
	unsigned port;
	int rc;

	if ((rc = rdd_parse_tcp_port((const char *) str, &port)) != RDD_OK) {
		fatal_rdd_error(rc, "%s", str);
	}
	return port;
}

static void
init_options(void)
{
	memset(&opts, 0, sizeof opts);

	opts.mode = RDD_LOCAL;
	opts.server_port = DEFAULT_RDD_SERVER_PORT;
	opts.nretry = DEFAULT_NRETRY;
	opts.max_read_err = DEFAULT_MAX_READ_ERR;
	opts.blocklen = DEFAULT_BLOCK_LEN;
	opts.minblocklen = DEFAULT_MIN_BLOCK_SIZE;
	opts.histblocklen = DEFAULT_HIST_BLOCK_SIZE;
	opts.adler32len = DEFAULT_CHKSUM_BLOCK_SIZE;
	opts.crc32len = DEFAULT_CHKSUM_BLOCK_SIZE;
	opts.blockmd5len = DEFAULT_BLOCKMD5_SIZE;
}


/* Split host.dom.topdom:/tmp/d.img in host.dom.topdom and /tmp/d.img
 */
static void
split_host_file(const char *host_file, char **host, char **file)
{
	char *p;
	const char *h;
	const char *f;
	int hlen, flen;

	p = strchr(host_file, ':');
       	if (p == 0) {			/* no ':' in host_file */
		h = "localhost";
		hlen = strlen(h);
		f = host_file;
		flen = strlen(f);

	} else if (p == host_file) {	/* host_file starts with ':' */
		h = "localhost";
		hlen = strlen(h);
		f = p + 1;
		flen = strlen(f);
	} else {
		h = host_file;
		hlen = p - host_file;
		f = p + 1;
		flen = strlen(f);
	}
	if (flen == 0) {
		error("missing file name in target %s", host_file);
	}

	*host = rdd_malloc(hlen + 1);
	memcpy(*host, h, hlen);
	(*host)[hlen] = '\000';

	*file = rdd_malloc(flen + 1);
	memcpy(*file, f, flen);
	(*file)[flen] = '\000';
}

static void
process_options(void)
{
	char *arg;

	if (rdd_opt_set("help")) rdd_opt_usage();

	if (rdd_opt_set("version")) {
		fprintf(stdout, "%s version %s\n", PACKAGE, VERSION);
		exit(EXIT_SUCCESS);
	}

	opts.compress = rdd_opt_set("compress");
	opts.quiet = rdd_opt_set("quiet");
	rdd_set_quiet(opts.quiet);
#if !defined(HAVE_LIBZ)
	error("rdd not configured with compression support");
#endif

	opts.raw = rdd_opt_set("raw");
#if !defined(__linux) || !defined(RDD_RAW)
	if (opts.raw) {
		error("rdd not configured with raw-device support");
	}
#endif
	opts.inetd = rdd_opt_set("inetd");
	opts.verbose = rdd_opt_set("verbose");

	opts.raw = rdd_opt_set("raw");
	if (opts.raw && opts.mode == RDD_SERVER) {
		error("raw-device input cannot be used in server mode");
	}

	opts.md5 = rdd_opt_set("md5");
	opts.sha1 = rdd_opt_set("sha1");
	
	opts.force_overwrite = rdd_opt_set("force");

	if (rdd_opt_set_arg("fault-simulation", &arg)) {
		opts.simfile = arg;
	}
	if (rdd_opt_set_arg("log-file", &arg)) {
		opts.logfile = arg;
	}
	if (rdd_opt_set_arg("adler32", &arg)) {
		opts.adler32file = arg;
	}
	if (rdd_opt_set_arg("adler32-block-size", &arg)) {
		opts.adler32len= scan_size(arg, RDD_POSITIVE);
		if (opts.adler32file == 0) {
			error("missing Adler-32 output file name "
			      "(use --adler32)");
		}
	}
	if (rdd_opt_set_arg("crc32", &arg)) {
		opts.crc32file = arg;
	}
	if (rdd_opt_set_arg("crc32-block-size", &arg)) {
		opts.crc32len= scan_size(arg, RDD_POSITIVE);
		if (opts.crc32file == 0) {
			error("missing CRC-32 output file name "
			      "(use --crc32)");
		}
	}
	if (rdd_opt_set_arg("histogram", &arg)) {
		opts.histfile = arg;
	}
	if (rdd_opt_set_arg("histogram-block-size", &arg)) {
		opts.histblocklen = scan_size(arg, RDD_POSITIVE);
		if (opts.histfile == 0) {
			error("missing histogram output file name "
			      "(use --histogram)");
		}
	}
	if (rdd_opt_set_arg("block-md5", &arg)) {
		opts.blockmd5file = arg;
	}
	if (rdd_opt_set_arg("block-md5-size", &arg)) {
		opts.blockmd5len = scan_size(arg, RDD_POSITIVE);
		if (opts.blockmd5file == 0) {
			error("missing block-MD5 output file name "
			      "(use --block-md5)");
		}
	}
	if (rdd_opt_set_arg("progress", &arg)) {
		opts.progresslen = scan_uint(arg);
	}
	if (rdd_opt_set_arg("nretry", &arg)) {
		opts.nretry = scan_uint(arg);
	}
	if (rdd_opt_set_arg("block-size", &arg)) {
		opts.blocklen = scan_size(arg, RDD_POSITIVE);
	}
	if (rdd_opt_set_arg("min-block-size", &arg)) {
		opts.minblocklen = scan_size(arg, RDD_POSITIVE);
	}
	if (rdd_opt_set_arg("offset", &arg)) {
		opts.offset = scan_size(arg, 0);
	}
	if (rdd_opt_set_arg("count", &arg)) {
		opts.count = scan_size(arg, RDD_POSITIVE);
	}
	if (rdd_opt_set_arg("max-read-err", &arg)) {
		opts.max_read_err = scan_uint(arg);
	}
	if (rdd_opt_set_arg("split", &arg)) {
		opts.splitlen = scan_size(arg, 0);
	}
	if (rdd_opt_set_arg("port", &arg)) {
		opts.server_port = scan_tcp_port(arg);
	}
}

static void
command_line(int argc, char **argv)
{
	RDD_OPTION *od;
	unsigned i;
	char *opt;
	char *arg;

	/* Rdd operates in one of three modes (RDD_LOCAL, RDD_CLIENT, RDD_SERVER).
	 * The mode is determined by argv[1]: -C, -S, or something else.
	 */
	i = 1;
	opts.mode = RDD_LOCAL;
	if (argc > 1) {
		if (streq(argv[i], "-C") || streq(argv[i], "--client")) {
			opts.mode = RDD_CLIENT;
			i++;
		} else if (streq(argv[i], "-S") || streq(argv[i], "--server")) {
			opts.mode = RDD_SERVER;
			i++;
		}
	}

	/* Collect all other options and their arguments (if any).
	 */
	for (; i < (unsigned) argc; i++) {
		if ((od = rdd_get_opt_with_arg(argv, argc, &i, &opt, &arg)) == 0) {
			break;
		}

		/* Check whether the option is allowed in the current rdd mode.
		 */
		if (! flag_set(od->valid_modes, opts.mode)) {
			error("option %s not valid in %s mode", opt,
				opts.mode == RDD_LOCAL  ? "local" :
				opts.mode == RDD_CLIENT ? "client" :
				opts.mode == RDD_SERVER ? "server": "unknown");
		}
	}

	process_options();

	/* Figure out the names of the input and output file (if any).
	 */
	switch (opts.mode) {
	case RDD_LOCAL:
		if (argc - i == 1) {
			opts.infile = argv[i++];
		} else if (argc - i == 2) {
			opts.infile = argv[i++];
			opts.outpath = argv[i++];
		} else {
			rdd_opt_usage();
		}
		break;
	case RDD_CLIENT:
		if (argc - i == 2) {
			opts.infile = argv[i++];
			split_host_file(argv[i++],
					&opts.server_host,
					&opts.outpath);
		} else {
			rdd_opt_usage();
		}
		break;
	case RDD_SERVER:
		if (argc - i != 0) {
			rdd_opt_usage();
		}
		break;
	}


	/* Artificial Intelligence
	 */
	if (rdd_opt_set("block-size")
	&&  !rdd_opt_set("min-block-size")
	&&  opts.blocklen < opts.minblocklen) {
		opts.minblocklen = opts.blocklen;
	}


	/* Sanity checks.
	 */
	if (opts.blocklen >= (rdd_count_t) INT_MAX) {
		error("block size (%llu) too large (larger than INT_MAX)",
			opts.blocklen);
	}
	if (opts.minblocklen > opts.blocklen) {
		error("minimum block length (%llu) cannot exceed "
		      "block length (%llu)",
			opts.minblocklen, opts.blocklen);
	}
	if (opts.splitlen > 0 && opts.splitlen < opts.blocklen) {
		error("split size (%llu) must be larger than or "
		      "equal to block size (%llu)",
			opts.splitlen, opts.blocklen);
	}
	if (opts.splitlen > 0 && opts.outpath == 0) {
		error("--split requires an output file name");
	}
}

static RDD_READER *
open_disk_input(rdd_count_t *inputlen)
{
	RDD_READER *reader = 0;
	int rc;

	rc = rdd_open_file_reader(&reader, opts.infile, opts.raw);
	if (rc != RDD_OK) {
		fatal_rdd_error(rc, "cannot open %s", opts.infile);
	}
	if ((rc = rdd_reader_seek(reader, 0)) != RDD_OK) {
		fatal_rdd_error(rc, "cannot seek on %s", opts.infile);
	}

	if (opts.raw) {
		rc = rdd_open_aligned_reader(&reader, reader, RDD_SECTOR_SIZE);
		if (rc != RDD_OK) {
			fatal_rdd_error(rc, "cannot open %s for aligned access",
					opts.infile);
		}
	}

	*inputlen = RDD_WHOLE_FILE;
	if ((rc = rdd_device_size(opts.infile, inputlen)) != RDD_OK) {
		fatal_rdd_error(rc, "%s: cannot determine device size", opts.infile);
	}

	if (opts.simfile != 0) {
		rc = rdd_open_faulty_reader(&reader, reader, opts.simfile);
		if (rc != RDD_OK) {
			fatal_rdd_error(rc, "cannot initialize fault simulator");
		}
	}

	return reader;
}

static RDD_READER *
open_net_input(rdd_count_t *inputlen)
{
	RDD_READER *reader = 0;
	int server_sock = -1;
	unsigned flags;
	int fd = -1;
	int rc;

	*inputlen = RDD_WHOLE_FILE;

	/* In server mode, we read from the network */
	if (opts.inetd) {
		/* started by (x)inetd */
		fd = STDIN_FILENO;
	} else {
		rc = rdd_init_server(the_printer, opts.server_port,
				&server_sock);
		if (rc != RDD_OK) {
			fatal_rdd_error(rc, "cannot start rdd-copy server");
		}

		rc = rdd_await_connection(the_printer, server_sock, &fd);
		if (rc != RDD_OK) {
			fatal_rdd_error(rc, "no connection");
		}
	}

	rc = rdd_open_fd_reader(&reader, fd);
	if (rc != RDD_OK) {
		fatal_rdd_error(rc, "cannot open reader on server socket");
	}

	rc = rdd_recv_info(reader, &opts.outpath, inputlen,
			&opts.blocklen, &opts.splitlen, &flags);
	if (rc != RDD_OK) {
		fatal_rdd_error(rc, "bad client request");
	}

	if (opts.verbose) {
		logmsg("Received rdd request:");
		logmsg("\tfile name:   %s", opts.outpath);
		logmsg("\tfile size:   %s", rdd_strsize(*inputlen));
		logmsg("\tblock size:  %llu", opts.blocklen);
		logmsg("\tsplit size:  %llu", opts.splitlen);
	}

#if defined(DEBUG)
	logmsg("file=%s size=%llu bsize=%llu splitsize=%llu",
		opts.outpath, rdd_strsize(*filelen),
		*blocklen, *splitlen);
#endif
	if ((flags & RDD_NET_COMPRESS) != 0) {
		if ((rc = rdd_open_zlib_reader(&reader, reader)) != RDD_OK) {
			fatal_rdd_error(rc, "cannot open zlib reader");
		}
	}

	return reader;
}

/* Creates a reader stack that corresponds to the user's options.
 */
static RDD_READER *
open_input(rdd_count_t *inputlen)
{
	if (opts.mode == RDD_SERVER) {
		return open_net_input(inputlen);
	} else {
		return open_disk_input(inputlen);
	}
}

static RDD_WRITER *
open_disk_output(rdd_count_t outputsize)
{
	RDD_WRITER *writer = 0;
	rdd_write_mode_t wrmode;
	int rc;

	if (opts.outpath == 0) return 0;

	wrmode = (opts.force_overwrite ? RDD_OVERWRITE_ASK : RDD_NO_OVERWRITE);

	if (strcmp(opts.outpath, "-") == 0) {
		if (opts.splitlen > 0) {
			error("cannot split standard output stream");
		}
		rc = rdd_open_fd_writer(&writer, STDOUT_FILENO);
		if (rc != RDD_OK) {
			fatal_rdd_error(rc, "cannot write to standard output?");
		}
	} else if (opts.splitlen > 0) {
		rc = rdd_open_part_writer(&writer, opts.outpath,
				outputsize, opts.splitlen, wrmode);
		if (rc != RDD_OK) {
			fatal_rdd_error(rc, "cannot open multipart output file");
		}
	} else {
		rc = rdd_open_safe_writer(&writer, opts.outpath, wrmode);
		if (rc != RDD_OK) {
			fatal_rdd_error(rc, "cannot open output file %s",
					opts.outpath);
		}
	}

	return writer;
}

static RDD_WRITER *
open_net_output(rdd_count_t outputsize)
{
	RDD_WRITER *writer = 0;
	unsigned flags = 0;
	int rc;
	char *server = opts.server_host;
	unsigned port = opts.server_port;

	assert(opts.outpath != 0);

	rc = rdd_open_tcp_writer(&writer, server, port);
	if (rc != RDD_OK) {
		fatal_rdd_error(rc, "cannot connect to %s:%u", server, port);
	}

	flags = (opts.compress ? RDD_NET_COMPRESS : 0);
	rc = rdd_send_info(writer, opts.outpath, outputsize,
			opts.blocklen, opts.splitlen, flags);
	if (rc != RDD_OK) {
		fatal_rdd_error(rc, "cannot send header to %s:%u", server, port);
	}

	if (opts.compress) {
		/* Stack a zlib writer on top of the TCP writer.
		 */
		rc = rdd_open_zlib_writer(&writer, writer);
		if (rc != RDD_OK) {
			fatal_rdd_error(rc, "cannot compress network traffic "
					    "to %s:%u", server, port);
		}
	}

	return writer;
}
/** Creates a writer stack that corresponds to the user's options.
 *  The outputsize argument contains the size of the output in
 *  bytes if that size is known or RDD_WHOLE_FILE if is not known.
 */
static RDD_WRITER *
open_output(rdd_count_t outputsize)
{
	if (opts.mode == RDD_CLIENT) {
		return open_net_output(outputsize);
	} else {
		return open_disk_output(outputsize);
	}
}

static void
open_logfile(void)
{
	RDD_MSGPRINTER *log_printer = 0;
	RDD_MSGPRINTER *bcast_printer = 0;
	RDD_MSGPRINTER *printers[2];
	unsigned nprinter = 0;
	int rc = RDD_OK;

	/* Keep the current (stderr) printer only if the user
	 * specified the verbose flag or if the user did not
	 * specify a log file.
	 */
	if (the_printer != 0 && (opts.verbose || opts.logfile == 0)) {
		printers[nprinter++] = the_printer;
	}

	/* If the user specified a log file then create a printer for
	 * it and add that printer to the printer list.
	 */
	if (opts.logfile != 0) {
		rc = rdd_mp_open_file_printer(&log_printer, opts.logfile);
		if (rc != RDD_OK) {
			fatal_rdd_error(rc, "cannot open log file (%s)",
					opts.logfile);
		}

		rc = rdd_mp_open_log_printer(&log_printer, log_printer);
		if (rc != RDD_OK) {
			fatal_rdd_error(rc, "cannot stack log printer");
		}

		printers[nprinter++] = log_printer;
	}

	/* Create a broadcast printer and make it the current printer.
	 */
	rc = rdd_mp_open_bcast_printer(&bcast_printer, nprinter, printers);
	if (rc != RDD_OK) {
		fatal_rdd_error(rc, "cannot open bcast printer");
	}
	the_printer = bcast_printer;
}

static void
close_printer(void)
{
	int rc;

	if (the_printer == 0) return;

	rc = rdd_mp_close(the_printer, RDD_MP_RECURSE|RDD_MP_READONLY);
	if (rc != RDD_OK) {
		/* Cannot trust the_printer any more...
		 */
		fprintf(stderr, "cannot close message printer\n");
		exit(EXIT_FAILURE);
	}

	the_printer = 0;
}

#define bool2str(b)   ((b) ? "yes" : "no")
#define str2str(s)    ((s) == 0? "<none>" : (s))

static void
log_header(char **argv, int argc)
{
	char cmdline[1024];
	char *p;
	int i;

	logmsg("");
	logmsg("%s", rdd_ctime());
	logmsg("%s version %s", PACKAGE, VERSION);
	logmsg("Copyright (c) 2002 Nederlands Forensisch Instituut");
#if defined(__linux) && defined(RDD_RAW)
	logmsg("Compile-time flag RDD_RAW is set");
#endif
#if defined(RDD_TRACE)
	logmsg("Compile-time flag RDD_TRACE is set");
#endif
#if defined(HAVE_LIBZ)
	logmsg("zlib version %s", zlibVersion());
	logmsg("Copyright (c) 1995-2002 Jean-loup Gailly and Mark Adler");
#endif
#if defined(HAVE_LIBCRYPTO)
	logmsg("openssl version %s", OPENSSL_VERSION_TEXT);
	logmsg("Copyright (c) 1995-1998 Eric Young");
#else
	logmsg("NOT using openssl");
#endif

	p = cmdline;
	snprintf(p, sizeof cmdline, "%s", argv[0]);
	cmdline[(sizeof cmdline) - 1] = '\000';
	p += strlen(argv[0]);
	for (i = 1; i < argc; i++) {
		snprintf(p, (sizeof cmdline) - (p - cmdline), " %s", argv[i]);
		cmdline[(sizeof cmdline) - 1] = '\000';
		p += 1 + strlen(argv[i]);
	}
	logmsg("%s", cmdline);
}

static void
log_params(rdd_copy_opts *opts)
{
	logmsg("========== Parameter settings ==========");
	logmsg("mode: %s",
		opts->mode == RDD_LOCAL ? "local" :
		opts->mode == RDD_CLIENT ? "client" :
		"server");
	logmsg("verbose: %s",                 bool2str(opts->verbose));
	logmsg("quiet: %s",                   bool2str(opts->quiet));
	logmsg("server host: %s",             str2str(opts->server_host));
	logmsg("server port: %u",             opts->server_port);
	logmsg("input file: %s",              str2str(opts->infile));
	logmsg("log file: %s",                str2str(opts->logfile));
	logmsg("output file: %s",             str2str(opts->outpath));
	logmsg("CRC32 file: %s",              str2str(opts->crc32file));
	logmsg("Adler32 file: %s",            str2str(opts->adler32file));
	logmsg("Statistics file: %s",         str2str(opts->histfile));
	logmsg("Block MD5 file: %s",          str2str(opts->blockmd5file));
	logmsg("raw-device input: %s",        bool2str(opts->raw));
	logmsg("compress network data: %s",   bool2str(opts->compress));
	logmsg("use (x)inetd: %s",            bool2str(opts->inetd));
	logmsg("force overwrite: %s",         bool2str(opts->force_overwrite));
	logmsg("compute MD5: %s",             bool2str(opts->md5));
	logmsg("compute SHA1: %s",            bool2str(opts->sha1));
	logmsg("max #retries: %u",            opts->nretry);
	logmsg("block size: %llu",            opts->blocklen);
	logmsg("minimum block size: %llu",    opts->minblocklen);
	logmsg("Adler32 block size: %llu",    opts->adler32len);
	logmsg("CRC32 block size: %llu",      opts->crc32len);
	logmsg("statistics block size: %llu", opts->histblocklen);
	logmsg("MD5 block size: %llu",        opts->blockmd5len);
	logmsg("input offset: %llu",          opts->offset);
	logmsg("input count: %llu",           opts->count);
	logmsg("segment size: %llu",          opts->splitlen);
	logmsg("progress reporting interval: %llu", opts->progresslen);
	logmsg("max #errors to tolerate: %llu",     opts->max_read_err);
	logmsg("========================================");
	logmsg("");
}

static void
handle_read_error(rdd_count_t offset, unsigned nbyte, void *env)
{
	logmsg("read error: offset %llu bytes, count %u bytes",
		offset, nbyte);
}

static void
handle_substitution(rdd_count_t offset, unsigned nbyte, void *env)
{
	logmsg("input dropped: offset %llu bytes, count %u bytes",
		offset, nbyte);
}

static int
handle_progress(rdd_count_t pos, void *env)
{
	RDD_PROGRESS *p = (RDD_PROGRESS *) env;
	RDD_PROGRESS_INFO info;
	double megabytes_per_sec;
	double gigabytes_done;
	double perc_done;
#if 0
	double secs_left;
#endif
	int rc;

	if ((rc = rdd_progress_update(p, pos)) != RDD_OK) {
		fatal_rdd_error(rc, "cannot update progress object");
	}

	rc = rdd_progress_poll(p, &info);
	if (rc == RDD_EAGAIN) {
		return RDD_OK;
	} else if (rc != RDD_OK) {
		fatal_rdd_error(rc, "cannot obtain progress information");
	}

	/* The poll succeeded.  Print progress information.
	 */
	gigabytes_done = (double) info.pos / (double) (1 << 30);
	megabytes_per_sec = info.speed / (double) (1 << 20);

	if (info.fraction >= 0.0) {
		/* If we know the input size, we can give a more
		 * detailed progress report.
		 */
		perc_done = 100.0 * info.fraction;
#if 0
		secs_left = ((double)(p->input_size - pos)) / speed;
#endif
		fprintf(stderr, "%.3f GB done (%6.2f%%), "
			"average speed %.3f MB/s "
#if 0
			"(%.0f seconds remaining)"
#endif
			"\n", 
			gigabytes_done, perc_done, megabytes_per_sec
#if 0
			, secs_left
#endif
			);
	} else {
		/* Unknown input size, so we cannot make any
		 * predictions.
		 */
		fprintf(stderr, "%.3f GB done, average speed %.3f MB/s\n", 
			gigabytes_done, megabytes_per_sec);
	}

	return RDD_OK;
}

static void
add_filter(RDD_FILTERSET *fset, const char *name, RDD_FILTER *f)
{
	int rc;

	if ((rc = rdd_fset_add(fset, name, f)) != RDD_OK) {
		fatal_rdd_error(rc, "cannot install %s filter", name);
	}
}

static void
install_filters(RDD_FILTERSET *fset, RDD_WRITER *writer)
{
	RDD_FILTER *f = 0;
	int rc;

	if ((rc = rdd_fset_init(fset)) != RDD_OK) {
		fatal_rdd_error(rc, "cannot create filter fset");
	}

	if (writer != 0) {
		rc = rdd_new_write_streamfilter(&f, writer);
		if (rc != RDD_OK) {
			fatal_rdd_error(rc, "cannot create write filter");
		}
		add_filter(fset, "write", f);
	}

	if (opts.md5) {
		rc = rdd_new_md5_streamfilter(&f);
		if (rc != RDD_OK) {
			fatal_rdd_error(rc, "cannot create MD5 filter");
		}
		add_filter(fset, "MD5 stream", f);
	}

	if (opts.sha1) {
		rc = rdd_new_sha1_streamfilter(&f);
		if (rc != RDD_OK) {
			fatal_rdd_error(rc, "cannot create SHA-1 filter");
		}
		add_filter(fset, "SHA-1 stream", f);
	}

	if (opts.blockmd5file != 0) {
		rc = rdd_new_md5_blockfilter(&f, opts.blockmd5len,
						opts.blockmd5file,
						opts.force_overwrite);
		if (rc != RDD_OK) {
			fatal_rdd_error(rc, "cannot create MD5 block filter");
		}
		add_filter(fset, "MD5 block", f);
	}

	if (opts.histfile != 0) {
		rc = rdd_new_stats_blockfilter(&f,
				opts.histblocklen, opts.histfile,
				opts.force_overwrite);
		if (rc != RDD_OK) {
			fatal_rdd_error(rc, "cannot create statistics filter");
		}
		add_filter(fset, "statistical block", f);
	}

	if (opts.adler32file != 0) {
		rc = rdd_new_adler32_blockfilter(&f,
				opts.adler32len, opts.adler32file,
				opts.force_overwrite);
		if (rc != RDD_OK) {
			fatal_rdd_error(rc, "cannot create Adler32 filter");
		}
		add_filter(fset, "Adler32 block", f);
	}

	if (opts.crc32file != 0) {
		rc = rdd_new_crc32_blockfilter(&f,
				opts.crc32len, opts.crc32file,
				opts.force_overwrite);
		if (rc != RDD_OK) {
			fatal_rdd_error(rc, "cannot create CRC-32 filter");
		}
		add_filter(fset, "CRC-32 block", f);
	}
}

static RDD_COPIER *
create_copier(rdd_count_t input_size, RDD_PROGRESS *progress)
{
	RDD_COPIER *copier = 0;
	rdd_count_t count = 0;
	int rc;

	/* Process the offset option.
	 */
	if (opts.offset > input_size) {
		error("offset %llu larger than input file size (%s)",
			opts.offset, rdd_strsize(input_size));
	}

	/* Process the count option.
	 */
	if (input_size == RDD_WHOLE_FILE) {
		count = RDD_WHOLE_FILE;
	} else {
		count = input_size - opts.offset;
	}
	if (opts.count > 0) {
	       	if (opts.count <= count) {
			count = opts.count; /* Use user-specified count */
		} else {
			logmsg("User count (%llu) too large; ignored", opts.count);
		}
	}
	if (opts.verbose) {
		logmsg("input size: %s", rdd_strsize(input_size));
		logmsg("read size: %s", rdd_strsize(count));
	}


	if (opts.mode == RDD_SERVER) {
		RDD_SIMPLE_PARAMS p;

		memset(&p, 0, sizeof p);
		if (progress != 0) {
			p.progressfun = handle_progress;
			p.progressenv = progress;
		}

		rc = rdd_new_simple_copier(&copier, &p);
		if (rc != RDD_OK) {
			fatal_rdd_error(rc, "cannot create simple copier");
		}
	} else {
		RDD_ROBUST_PARAMS p;

		memset(&p, 0, sizeof p);
		p.minblocklen = opts.minblocklen;
		p.maxblocklen = opts.blocklen;
		p.nretry = opts.nretry;
		p.maxsubst = opts.max_read_err;
		p.readerrfun = handle_read_error;
		p.substfun = handle_substitution;
		if (progress != 0) {
			p.progressfun = handle_progress;
			p.progressenv = progress;
		}

		rc = rdd_new_robust_copier(&copier,
				opts.offset, count, &p);
		if (rc != RDD_OK) {
			fatal_rdd_error(rc, "cannot create robust copier");
		}
	}

	return copier;
}

static void
log_hash_result(RDD_FILTERSET *fset, const char *hash_name,
		const char *filter_name, unsigned mdsize)
{
	unsigned char md[RDD_MAX_DIGEST_LENGTH];
	char hexdigest[2*RDD_MAX_DIGEST_LENGTH + 1];
	RDD_FILTER *f = 0;
	int rc;

	memset(md, 0, mdsize);

	if (mdsize > (sizeof md)) {
		fatal_rdd_error(RDD_ESPACE, "digest size exceeds buffer size");
	}

	if ((rc = rdd_fset_get(fset, filter_name, &f)) != RDD_OK) {
		fatal_rdd_error(rc, "cannot find %s filter", filter_name);
	}

	if ((rc = rdd_filter_get_result(f, md, mdsize)) != RDD_OK) {
		fatal_rdd_error(rc, "cannot get result for %s filter",
				filter_name);
	}

	rc = rdd_buf2hex(md, mdsize, hexdigest, sizeof hexdigest);
	if (rc != RDD_OK) {
		fatal_rdd_error(rc, "cannot convert binary digest");
	}

	logmsg("%s: %s", hash_name, hexdigest);
}

int
main(int argc, char **argv)
{
	double start, end;
	RDD_READER *reader;
	RDD_WRITER *writer;
	RDD_PROGRESS progress;
	RDD_COPIER_RETURN copier_ret;
	RDD_COPIER *copier;
	RDD_FILTERSET filterset;
	RDD_MSGPRINTER *printer = 0;
	rdd_count_t input_size;
	int rc;

	set_progname(argv[0]);
	rdd_cons_open();
	rdd_init();

	/* Setup initial printer (stderr).
	 */
	rc = rdd_mp_open_stdio_printer(&printer, stderr);
	if (rc != RDD_OK) {
		fprintf(stderr, "cannot open stderr message printer\n");
		exit(EXIT_FAILURE);
	}
#if 0
	rc = rdd_mp_open_log_printer(&printer, printer);
	if (rc != RDD_OK) {
		exit(EXIT_FAILURE);
	}
#endif
	the_printer = printer;

	init_options();
	rdd_opt_init(opttab, usage_message);
	command_line(argc, argv);

	open_logfile();

	rdd_catch_signals();

	log_header(argv, argc);
	log_params(&opts);

	if (!opts.md5 && !opts.sha1) {
	       rdd_quit_if(RDD_NO, "Continue without hashing (yes/no)?");
	}
	if (opts.logfile == 0) {
		rdd_quit_if(RDD_NO, "Continue without logging (yes/no)?");
	}

	reader = open_input(&input_size);
	writer = open_output(RDD_WHOLE_FILE);
	install_filters(&filterset, writer);

	if (opts.progresslen > 0) {
		rc = rdd_progress_init(&progress, input_size, opts.progresslen);
		if (rc != RDD_OK) {
			fatal_rdd_error(rc, "cannot initialize progress object");
		}
		copier = create_copier(input_size, &progress);
	} else {
		copier = create_copier(input_size, 0);
	}

	start = rdd_gettime();
	rc = rdd_copy_exec(copier, reader, &filterset, &copier_ret);
	if (rc != RDD_OK) {
		fatal_rdd_error(rc, "copy failed");
	}
	end = rdd_gettime();

	rdd_mp_message(the_printer, RDD_MSG_INFO, "=== done ***");
	rdd_mp_message(the_printer, RDD_MSG_INFO, "seconds: %.3f", end - start);
	rdd_mp_message(the_printer, RDD_MSG_INFO, "bytes written: %llu", 
						  copier_ret.nbyte);
	rdd_mp_message(the_printer, RDD_MSG_INFO, "bytes lost: %llu", 
						  copier_ret.nlost);
	rdd_mp_message(the_printer, RDD_MSG_INFO, "read errors: %lu", 
						  copier_ret.nread_err);
	rdd_mp_message(the_printer, RDD_MSG_INFO, "zero-block substitutions: "
						  "%lu", copier_ret.nsubst);

	if (opts.md5) {
		log_hash_result(&filterset, "MD5", "MD5 stream", 16);
	} else {
		logmsg("MD5: <none>");
	}
	if (opts.sha1) {
		log_hash_result(&filterset, "SHA-1", "SHA-1 stream", 20);
	} else {
		logmsg("SHA1: <none>");
	}

	if ((rc = rdd_copy_free(copier)) != RDD_OK) {
		fatal_rdd_error(rc, "cannot clean up copier");
	}
	if ((rc = rdd_fset_clear(&filterset)) != RDD_OK) {
		fatal_rdd_error(rc, "cannot clean up filters");
	}

	if (writer != 0) {
		if ((rc = rdd_writer_close(writer)) != RDD_OK) {
			fatal_rdd_error(rc, "cannot clean up writer");
		}
	}

	if ((rc = rdd_reader_close(reader, 1)) != RDD_OK) {
		fatal_rdd_error(rc, "cannot clean up reader");
	}

	close_printer();

	if (copier_ret.nread_err > 0) {
		logmsg("%u read errors occurred", copier_ret.nread_err);
		exit(EXIT_FAILURE);
	}

	logmsg("no read errors");


	rdd_cons_close();

	return 0;
}
