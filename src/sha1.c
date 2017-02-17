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


/* Straightforward implementation of SHA-1, based on the description
 * in FIPS 180-1 (see http://www.itl.nist.gov/div897/pubs/fip180-1.htm).
 *
 * No serious optimizations were performed.  If you want something faster,
 * check out the openssl source code.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "rdd.h"
#include "rdd_internals.h"

#if !defined(HAVE_LIBCRYPTO)

#include <string.h>

#include "sha1.h"

#define ROTL(n, w)  (((w) << (n)) | ((w) >> (32 - (n))))

#define F1(B, C, D) (((B) & (C)) | (((~(B)) & (D))))
#define F2(B, C, D) ((B) ^ (C) ^ (D))
#define F3(B, C, D) (((B) & (C)) | ((B) & (D)) | ((C) & (D)))
#define F4(B, C, D) ((B) ^ (C) ^ (D))

#define K1 0x5a827999
#define K2 0x6ed9eba1
#define K3 0x8f1bbcdc
#define K4 0xca62c1d6         

#define encode_word(p) (((p)[0]<<24) | ((p)[1]<<16) | ((p)[2]<<8) | (p)[3])

#define decode_word(w, p) do { \
	(p)[0] = (w >> 24) & 0xff; \
	(p)[1] = (w >> 16) & 0xff; \
	(p)[2] = (w >>  8) & 0xff; \
	(p)[3] = (w >>  0) & 0xff; \
} while (0)

#define decode_quad(w, p) do { \
	(p)[0] = (w >> 56) & 0xff; \
	(p)[1] = (w >> 48) & 0xff; \
	(p)[2] = (w >> 40) & 0xff; \
	(p)[3] = (w >> 32) & 0xff; \
	(p)[4] = (w >> 24) & 0xff; \
	(p)[5] = (w >> 16) & 0xff; \
	(p)[6] = (w >>  8) & 0xff; \
	(p)[7] = (w >>  0) & 0xff; \
} while (0)

void
SHA1_Init(SHA_CTX *c)
{
	c->msglen = 0;
	c->buflen = 0;
	memset(c->buf, 0, 64);
	c->H[0] = 0x67452301;
	c->H[1] = 0xefcdab89;
	c->H[2] = 0x98badcfe;
	c->H[3] = 0x10325476;
	c->H[4] = 0xc3d2e1f0;
}

/* Fold a full 512-bit chunk into the running digest value.
 */
static void
compress(SHA_CTX *c, unsigned char *buf)
{
	uint32 A, B, C, D, E;
	uint32 TEMP;
	uint32 *W;
	uint32 *H;
	unsigned t;

	c->buflen = 0;
	W = c->W;
	H = c->H;

	for (t = 0; t < 16; t++) {
		W[t] = encode_word(buf + 4*t);
	}

	for (; t < 80; t++) {
		W[t] = ROTL(1, W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);
	}

	A = H[0]; B = H[1]; C = H[2]; D = H[3]; E = H[4];

	for (t = 0; t < 20; t++) {
		TEMP = ROTL(5, A) + F1(B, C, D) + E + W[t] + K1;
		E = D; D = C; C = ROTL(30, B); B = A; A = TEMP;
	}
	for (; t < 40; t++) {
		TEMP = ROTL(5, A) + F2(B, C, D) + E + W[t] + K2;
		E = D; D = C; C = ROTL(30, B); B = A; A = TEMP;
	}
	for (; t < 60; t++) {
		TEMP = ROTL(5, A) + F3(B, C, D) + E + W[t] + K3;
		E = D; D = C; C = ROTL(30, B); B = A; A = TEMP;
	}
	for (; t < 80; t++) {
		TEMP = ROTL(5, A) + F4(B, C, D) + E + W[t] + K4;
		E = D; D = C; C = ROTL(30, B); B = A; A = TEMP;
	}

	H[0] += A; H[1] += B; H[2] += C; H[3] += D; H[4] += E;
}

void
SHA1_Update(SHA_CTX *c, unsigned char *input, unsigned len)
{
	c->msglen += 8 * len;

	/* If we don't have enough to fill a chunk, then just
	 * append the new data to the partial-chunk buffer.
	 */
	if (c->buflen + len < 64) {
		memcpy(c->buf + c->buflen, input, len);
		c->buflen += len;
		return;
	}

	/* Append to existing partial chunk and process resulting
	 * full chunk.
	 */
	if (c->buflen > 0) {
		memcpy(c->buf + c->buflen, input, 64 - c->buflen);
		input += 64 - c->buflen;
		len -= 64 - c->buflen;
		compress(c, c->buf);
	}

	/* Process all 512-bit chunks.
	 */
	while (len >= 64) {
		compress(c, input);
		input += 64;
		len -= 64;
	}

	/* Buffer all remaining input.
	 */
	if (len > 0) {
		memcpy(c->buf, input, len);
		c->buflen = len;
	}
}


/* SHA1 finalization. Ends a SHA1 message-digest operation, writing
 * the message digest and clearing the context.
 */
void
SHA1_Final(unsigned char digest[SHA_DIGEST_LENGTH], SHA_CTX *c)
{
	unsigned free_bits;
	unsigned zero_bits;
	unsigned char padbuf[64];
	unsigned padlen;

	/* Figure out how much space is left in the
	 * input buffer.
	 */
	free_bits = 512 - (c->msglen % 512);
	if (free_bits >= 65) {
		/* We have room for the '1' bit and the length field.
		 */
		zero_bits = free_bits - 65;
	} else {
		zero_bits = free_bits + 512 - 65; 
	}

	memset(padbuf, 0, 64);
	padbuf[0] = 0x80;
	padlen = 1 + (zero_bits - 7) / 8;	/* bytes */

	decode_quad(c->msglen, padbuf + padlen);
	padlen += 8;
	SHA1_Update(c, padbuf, padlen);

	decode_word(c->H[0], digest +  0);
	decode_word(c->H[1], digest +  4);
	decode_word(c->H[2], digest +  8);
	decode_word(c->H[3], digest + 12);
	decode_word(c->H[4], digest + 16);

	memset(c, 0, sizeof (*c)); /* Clear sensitive information. */
}

#endif /* HAVE_LIBCRYPTO */
