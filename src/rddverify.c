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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>

#if defined(HAVE_LIBCRYPTO) && defined(HAVE_OPENSSL_MD5_H) && defined(HAVE_OPENSSL_SHA_H)
#include <openssl/md5.h>
#include <openssl/sha.h>
#else
/* Use local versions to allow stand-alone compilation.
 */
#include "md5.h"
#include "sha1.h"
#endif /* HAVE_LIBCRYPTO */

#if defined(HAVE_LIBCRYPTO) && defined(HAVE_OPENSSL_CRYPTO_H)
#include <openssl/crypto.h>
#else
#error "Sorry, we need the openssl crypto lib to compile"
#endif

#if defined(HAVE_LIBZ)
#include <zlib.h>
#else
#error "Sorry, we need zlib to compile"
#endif

#include "rdd.h"
#include "reader.h"
#include "writer.h"
#include "filter.h"
#include "filterset.h"
#include "msgprinter.h"
#include "rdd_internals.h"
#include "error.h"
#include "commandline.h"

/* Types of verication checks to perform.
 */
#define VFY_MD5      0x1
#define VFY_SHA1     0x2
#define VFY_ADLER32  0x4
#define VFY_CRC32    0x8

#define READ_SIZE	262144	/* bytes */
#define bool2str(b)   ((b) ? "yes" : "no")

static struct verifier_opts {
	char       **files;		/* input files */
	unsigned     nfile;		/* #input files */
	char        *crc32file;		/* output file for CRC32 checksums */
	char        *adler32file;	/* output file for Adler32 checksums */
	int          verbose;		/* Be verbose? */
	int          md5;		/* MD5-hash all data? */
	int          sha1;		/* SHA1-hash all data? */
	rdd_count_t  progresslen;	/* progress reporting interval (s) */
	char        *md5digest;
	char        *sha1digest;
} opts;

typedef rdd_checksum_t (*checksum_fun)(rdd_checksum_t, const unsigned char *, size_t);

static char *usage_message = "rdd-verify [local options] file1 ... \n";

static RDD_OPTION opttab[] = {
	{"-?", "--help", 0, 0,
	 	"Print this message", 0, 0},
	{"-V", "--version", 0, 0,
         	"Report version number and exit", 0, 0},
	{"-v", "--verbose", 0, 0,
	 	"Be verbose", 0, 0},
	{"--checksum", "--adler32", "<file>", 0,
	 "verify Adler32 checksums in <file> against input files", 0, 0},
	{"--crc", "--crc32", "<file>", 0,
	 "verify CRC32 checksums in <file> against input files", 0, 0},
	{"--md5", "--md5", "<md5 digest>", 0,
	 	"verify MD5 hash", 0, 0},
	{"--sha", "--sha1", "<sha-1 digest>", 0,
	 	"verify SHA1 hash", 0, 0},
	{0, 0, 0, 0, 0, 0, 0} /* sentinel */
};

static RDD_MSGPRINTER *the_printer;

static void
process_options(void)
{
	char *arg;

	if (rdd_opt_set("help")) {
		rdd_opt_usage();
	}

	if (rdd_opt_set("version")) {
		fprintf(stderr, "%s version %s\n", PACKAGE, VERSION);
		exit(EXIT_SUCCESS);
	}

	opts.verbose = rdd_opt_set("verbose");
	if (rdd_opt_set_arg("md5",&arg)) {
		opts.md5 = 1;
		opts.md5digest = arg;
	}
	if (rdd_opt_set_arg("sha1", &arg)) {
		opts.sha1 = 1;
		opts.sha1digest = arg;
	}
	if (rdd_opt_set_arg("adler32", &arg)) {
		opts.adler32file = arg;
	}
	if (rdd_opt_set_arg("crc32", &arg)) {
		opts.crc32file = arg;
	}
	if ((!opts.md5) && (!opts.sha1)
	&&  (opts.adler32file == NULL) && (opts.crc32file == NULL)) {
		error("Nothing to do. No options given");
	}
}

static void
command_line(int argc, char **argv)
{
	RDD_OPTION *od;
	unsigned i;
	char *opt;
	char *arg;

	for (i = 1; i < (unsigned) argc; i++) {
		if ((od = rdd_get_opt_with_arg(argv, argc, &i, &opt, &arg)) == 0) {
			break;
		}
	}

	process_options();

	if (argc - i < 1) {
		rdd_opt_usage();
	}

	opts.files = &argv[i];
	opts.nfile = argc - i;
}

static u_int16_t
swap16(u_int16_t n)
{
	return ((n << 8) & 0xff00) | ((n >> 8) & 0x00ff);
}

static u_int32_t
swap32(u_int32_t n)
{
	return
	  ((n << 24) & 0xff000000)
	| ((n <<  8) & 0x00ff0000)
	| ((n >>  8) & 0x0000ff00)
	| ((n >> 24) & 0x000000ff)
	;
}

static u_int64_t
swap64(u_int64_t n)
{
	u_int64_t lo_swapped, hi_swapped;
	u_int32_t lo, hi;

	lo = (u_int32_t) (n & 0xffffffff);
	hi = (u_int32_t) ((n >> 32) &  0xffffffff);

	lo_swapped = (u_int64_t) swap32(lo);
	hi_swapped = (u_int64_t) swap32(hi);

	return (lo_swapped << 32) | hi_swapped;
}

static RDD_READER *
open_image_file(const char *path)
{
	RDD_READER *reader = 0;
	int rc;
       
	if ((rc = rdd_open_file_reader(&reader, path, 0)) != RDD_OK) {
		rdd_error(rc, "cannot open %s", path);
	}
	
	return reader;
}

static void
close_image_file(const char *path, RDD_READER *reader)
{
	int rc;

	if ((rc = rdd_reader_close(reader, 1)) != RDD_OK) {
		rdd_error(rc, "cannot close %s", path);
	}
}

static void
swap_header(RDD_CHECKSUM_FILE_HEADER *hdr)
{
	hdr->magic = swap16(hdr->magic);
	hdr->version = swap16(hdr->version);
	hdr->flags = swap16(hdr->flags);
	hdr->reserved = swap16(hdr->reserved);
	hdr->blocksize = swap32(hdr->blocksize);
	hdr->offset = swap64(hdr->offset);
	hdr->imagesize = swap64(hdr->imagesize);
}

static void
check_header(char *path, RDD_CHECKSUM_FILE_HEADER *header, int type, int *swap)
{
	if (header->magic != RDD_CHECKSUM_MAGIC) {
		swap_header(header);
		*swap = 1;
	} else {
		*swap = 0;
	}

	if (header->magic != RDD_CHECKSUM_MAGIC) {
		error("%s: header magic value is incorrect; "
		      "expected %04x, got %04x",
		      path, RDD_CHECKSUM_MAGIC, header->magic);
	}
	
	if (header->version != RDD_CHECKSUM_VERSION) {
		error("%s: header version is incorrect; "
		      "expected %04x, got %04x",
		      path, RDD_CHECKSUM_VERSION, header->version);
	}
	
	if ((header->flags & type) != type) {
		error("%s: the type found in the file is wrong; "
		      "expected %04x got %04x",
		      path, type, header->flags);
	}
}

static FILE *
open_checksum_file(char *path, int type, RDD_CHECKSUM_FILE_HEADER *hdr, int *swap)
{
	FILE *fp;

	if ((fp = fopen(path, "rb")) == NULL) {
		unix_error("cannot open checksum file %s", path);
	}

	if (fread(hdr, sizeof(*hdr), 1, fp) < 1) {
		unix_error("cannot read header from %s", path);
	}

	check_header(path, hdr, type, swap);

	return fp;
}

static void
close_checksum_file(const char *path, FILE *fp)
{
	if (fp == NULL) {
		return;
	}
	if (fgetc(fp) != EOF) {
		warn("unprocessed data in %s", path);
	}
	if (fclose(fp) == EOF) {
		unix_error("cannot close %s", path);
	}
}

static void
verify_file(RDD_FILTERSET *filters, const char *path)
{
	RDD_READER *reader = 0;
	unsigned char buf[READ_SIZE];
	unsigned nread;
	int rc;
	
	reader = open_image_file(path);

	while (1) {
		rc = rdd_reader_read(reader, buf, READ_SIZE, &nread);
		if (rc != RDD_OK) {
			rdd_error(rc, "%s: read error", path);
		}
		if (nread == 0) break;	/* EOF */
		
		if ((rc = rdd_fset_push(filters, buf, nread)) != RDD_OK) {
			rdd_error(rc, "cannot push buffer into filter");
		}
	}
	if ((rc = rdd_fset_close(filters)) != RDD_OK) {
		rdd_error(rc, "cannot close filters");
	}

	close_image_file(path, reader);
}

static void
add_filter(RDD_FILTERSET *fset, const char *name, RDD_FILTER *f)
{
	int rc;

	if ((rc = rdd_fset_add(fset, name, f)) != RDD_OK) {
		rdd_error(rc, "cannot install %s filter", name);
	}
}

static void
handle_checksum_error(rdd_count_t pos,
	rdd_checksum_t expected, rdd_checksum_t computed, void *env)
{
	char *algorithm = (char *) env;

	errlognl("%s checksum error; block offset %llu; "
		"expected 0x%08x, got 0x%08x",
		algorithm, pos, expected, computed);
}

static void
get_checksum_result(RDD_FILTERSET *fset, const char *name, unsigned *num_error)
{
	RDD_FILTER *f = 0;
	int rc;

	*num_error = 0;

	if ((rc = rdd_fset_get(fset, name, &f)) != RDD_OK) {
		rdd_error(rc, "cannot find %s filter", name);
	}

	rc = rdd_filter_get_result(f,
			(unsigned char *) num_error, sizeof(*num_error));
	if (rc != RDD_OK) {
		rdd_error(rc, "cannot get result for %s filter", name);
	}
}

static void
get_hash_result(RDD_FILTERSET *fset, const char *name,
		unsigned char *md, unsigned mdsize)
{
	RDD_FILTER *f = 0;
	int rc;

	memset(md, 0, mdsize);

	if ((rc = rdd_fset_get(fset, name, &f)) != RDD_OK) {
		rdd_error(rc, "cannot find %s filter", name);
	}
	if ((rc = rdd_filter_get_result(f, md, mdsize)) != RDD_OK) {
		rdd_error(rc, "cannot get result for %s filter", name);
	}
}

static int
equal_digest(char *md1, char *md2, unsigned mdlen)
{
	unsigned i;

	for (i = 0; i < mdlen; i++) {
		if (tolower(md1[i]) != tolower(md2[i])) {
			return 0;
		}
	}

	return 1;
}

static int
verify_files(char **files, unsigned nfile,
		FILE* adler32file, rdd_count_t a32len, int a32swap,
		FILE* crc32file, rdd_count_t crc32len, int crc32swap)
{
	RDD_FILTERSET filters;
	RDD_FILTER *f = 0;
	unsigned num_error;
	int broken = 0;
	int rc;
	unsigned i;

	if ((rc = rdd_fset_init(&filters)) != RDD_OK) {
		rdd_error(rc, "cannot initialize filter set");
	}

	if (opts.md5) {
		rc = rdd_new_md5_streamfilter(&f);
		if (rc != RDD_OK) {
			rdd_error(rc, "cannot create MD5 filter");
		}
		add_filter(&filters, "MD5 stream", f);
	}

	if (opts.sha1) {
		rc = rdd_new_sha1_streamfilter(&f);
		if (rc != RDD_OK) {
			rdd_error(rc, "cannot create SHA-1 filter");
		}
		add_filter(&filters, "SHA-1 stream", f);
	}

	if (adler32file != 0) {
		rc = rdd_new_verify_adler32_blockfilter(&f, adler32file,
							a32len, a32swap,
							handle_checksum_error,
							"Adler32");
		if (rc != RDD_OK) {
			rdd_error(rc, "cannot create Adler32 verification filter");
		}
		add_filter(&filters, "Adler32 verification block", f);
	}

	if (crc32file != 0) {
		rc = rdd_new_verify_crc32_blockfilter(&f, crc32file,
							crc32len, crc32swap,
							handle_checksum_error,
							"CRC-32");
		if (rc != RDD_OK) {
			rdd_error(rc, "cannot create CRC-32 verification filter");
		}
		add_filter(&filters, "CRC-32 verification block", f);
	}

	/* Run verification.
	 */
	for (i = 0; i < nfile; i++) {
		if (opts.verbose) {
			errlognl("verifying %s ...", files[i]);
		}
		verify_file(&filters, files[i]);
	}

	/* Check results.
	 */
	if (adler32file != 0) {
		get_checksum_result(&filters, "Adler32 verification block",
					&num_error);
		if (num_error > 0) {
			broken |= VFY_ADLER32;
		}
	}

	if (crc32file != 0) {
		get_checksum_result(&filters, "CRC-32 verification block",
					&num_error);
		if (num_error > 0) {
			broken |= VFY_CRC32;
		}
	}

	if (opts.sha1) {
		unsigned char md[20];
		char hexmd[2*20 + 1];
		int rc;

		get_hash_result(&filters, "SHA-1 stream", md, sizeof md);
		rc = rdd_buf2hex(md, sizeof md, hexmd, sizeof hexmd);
		if (rc != RDD_OK) {
			rdd_error(rc, "cannot print SHA-1 digest");
		}

		if (opts.verbose) {
			errlognl("Found SHA1 digest: [%s]", hexmd);
		}

		if (! equal_digest(hexmd, opts.sha1digest, 2*SHA_DIGEST_LENGTH)) {
			errlognl("SHA1 values do not match:");
			errlognl("\texpected: %s", opts.sha1digest);
			errlognl("\tfound:    %s", hexmd);
			broken |= VFY_SHA1;
		}
	}

	if (opts.md5) {
		unsigned char md[16];
		char hexmd[2*16 + 1];
		int rc;

		get_hash_result(&filters, "MD5 stream", md, sizeof md);
		rc = rdd_buf2hex(md, sizeof md, hexmd, sizeof hexmd);
		if (rc != RDD_OK) {
			rdd_error(rc, "cannot print MD5 digest");
		}

		if (opts.verbose) {
			errlognl("Found MD5 digest: [%s]", hexmd);
		}

		if (! equal_digest(hexmd, opts.md5digest, 2*MD5_DIGEST_LENGTH)) {
			errlognl("MD5 values do not match:");
			errlognl("\texpected: %s", opts.md5digest);
			errlognl("\tfound:    %s", hexmd);
			broken |= VFY_MD5;
		}
	}

	if ((rc = rdd_fset_clear(&filters)) != RDD_OK) {
		rdd_error(rc, "cannot clean up filter set");
	}

	return broken;
}

int
main(int argc, char** argv)
{
	RDD_CHECKSUM_FILE_HEADER adler32hdr;
	RDD_CHECKSUM_FILE_HEADER crc32hdr;
	FILE *adler32file = NULL;
	FILE *crc32file = NULL;
	int adler32swap = 0;
	int crc32swap = 0;
	int res;
	int i;
	
	rdd_opt_init(opttab, usage_message);

	set_progname(argv[0]);
	set_logfile(stderr);
	memset(&opts, '\000', sizeof opts);
	command_line(argc, argv);

	memset(&adler32hdr, 0, sizeof adler32hdr);
	memset(&crc32hdr, 0, sizeof crc32hdr);

	if (opts.adler32file) {
		adler32file = open_checksum_file(opts.adler32file,
						 RDD_ADLER32, &adler32hdr,
						 &adler32swap);
	}
	if (opts.crc32file) {
		crc32file = open_checksum_file(opts.crc32file,
					       RDD_CRC32, &crc32hdr,
					       &crc32swap);
	}

	errlognl("");
	errlognl("%s", rdd_ctime());
	errlognl("%s version %s (Internal rev $Rev: 252 $)", PACKAGE, VERSION);
	errlognl("Copyright (c) 2002 Nederlands Forensisch Instituut");
#if defined(HAVE_LIBZ)
	errlognl("zlib version %s", zlibVersion());
	errlognl("Copyright (c) 1995-2002 Jean-loup Gailyy and Mark Adler");
#endif
#if defined(HAVE_LIBCRYPTO)
	errlognl("openssl version %s", OPENSSL_VERSION_TEXT);
	errlognl("Copyright (c) 1995-1998 Eric Young");
#endif
	errlog("%s", argv[0]);
	for (i = 1; i < argc; i++) {
		errlog(" %s", argv[i]);
	}
	errlognl("");
	errlognl("");

	if (opts.verbose) {
		errlognl("verbose: %s", bool2str(opts.verbose));
	}

	res = verify_files(opts.files, opts.nfile,
			adler32file, adler32hdr.blocksize, adler32swap,
			crc32file, crc32hdr.blocksize, crc32swap);

	if (res == 0) {
		errlognl("Verification complete: NO ERRORS");
	} else {
		errlognl("Verification complete: FAILURE DETECTED");
		      
		if ((res & VFY_ADLER32) != 0) {
			errlognl("Adler32 verification failed");
		}
		if ((res & VFY_CRC32) != 0) {
			errlognl("CRC32 verification failed");
		}
		if ((res & VFY_SHA1) != 0) {
			errlognl("SHA1 verification failed");
		}
		if ((res & VFY_MD5) != 0) {
			errlognl("MD5 verification failed");
		}
	}

	close_checksum_file(opts.crc32file, crc32file);
	close_checksum_file(opts.adler32file, adler32file);

	return (res == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
}
