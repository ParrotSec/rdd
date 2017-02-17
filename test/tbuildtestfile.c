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


/* This is a simple program to build a testfile to be used by several
 * rdd unit tests.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#if defined(HAVE_OPENSSL_BLOWFISH_H)
#include <openssl/blowfish.h>
#else
#error OpenSSL Blowfish algorithm not available
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rdd.h"

#define BLOWFISH_BLOCKSIZE 8  /* bytes (64 bits) */
#define NULL_BUFSIZE 524288

static void
print_buf(unsigned char *buf, unsigned n)
{
	unsigned i;

	for (i = 0; i < n; i++){
		printf("buffer item %02i = 0x%X\n", i, buf[i]);
	}

}

/* Writes some null-butes to a file.
 */
static void
write_null(FILE *outfile)
{

	unsigned char buf[NULL_BUFSIZE];
	
	memset(buf, 0, NULL_BUFSIZE);
	fwrite(buf, 1, NULL_BUFSIZE, outfile);
}

/* Writes some printable characters to a file.
 */
static void
write_text(FILE *outfile)
{
	unsigned char buf[] = "Dit is een stukje standaardtekst in het"
		"Nederlands. De entropie van dit fragment zou niet erg hoog "
		"mogen zijn. Dat zie je......";
	int i;
	
	for (i = 0; i < 4096; i++){
		fwrite(buf, 1, 128, outfile);
	}
}

static void
write_encrypted(FILE *outfile)
{
	unsigned char inbuf[BLOWFISH_BLOCKSIZE];
	unsigned char outbuf[BLOWFISH_BLOCKSIZE];
	const char *keydata = "rdd";
	BF_KEY key;
	int i;

	/* Write some 'random' data to a file. The random() library function
	 * can be platform or implementation dependent, so we prefer to use
	 * encryption to obtain reproducible random data.
	 *
	 * The user key is "rdd". The initial input is a buffer filled
	 * with null bytes.  The output of each encryption round is 
	 * used as input for the next round.
	 */ 

	memset(inbuf, 0, sizeof inbuf);
	memset(outbuf, 1, sizeof outbuf);

	BF_set_key(&key, strlen(keydata), (unsigned char *) keydata);

	for (i = 0; i < 65536; i++){
		BF_ecb_encrypt(inbuf, outbuf, &key, BF_ENCRYPT);
		fwrite(outbuf, 1, sizeof outbuf, outfile);
		memcpy(inbuf, outbuf, sizeof inbuf);
	}
}

int
main(void)
{
	const char *outpath = "image.img";
	FILE *outfile;

	if ((outfile = fopen(outpath, "wb")) == NULL) {
		fprintf(stderr, "cannot open output file %s.\n", outpath);
		exit(EXIT_FAILURE);
	}

	write_encrypted(outfile);
	write_text(outfile);
	write_null(outfile);

	(void) fclose(outfile);
	
	return 0;
}
