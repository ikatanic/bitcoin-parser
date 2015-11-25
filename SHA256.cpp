/* The MIT License

   Copyright (C) 2011 Zilong Tan (eric.zltan@gmail.com)

   Permission is hereby granted, free of charge, to any person obtaining
   a copy of this software and associated documentation files (the
   "Software"), to deal in the Software without restriction, including
   without limitation the rights to use, copy, modify, merge, publish,
   distribute, sublicense, and/or sell copies of the Software, and to
   permit persons to whom the Software is furnished to do so, subject to
   the following conditions:

   The above copyright notice and this permission notice shall be
   included in all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
   EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
   MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
   NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
   BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
   ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
   CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
   SOFTWARE.
*/

/*
 *  Original code is derived from the author:
 *  Allan Saddi
 */

#include "SHA256.h"
#include <string.h>

#ifdef _MSC_VER 
#pragma warning(disable:4718) // Disable a compiler optimization warning on visual studio
#endif


#define SHA256_HASH_SIZE  32	/* 256 bit */
#define SHA256_HASH_WORDS 8
#define SHA256_UNROLL 64	// This define determines how much loop unrolling is done when computing the hash; 

// Uncomment this line of code if you want this snippet to compute the endian mode of your processor at run time; rather than at compile time.
//#define RUNTIME_ENDIAN

// Uncomment this line of code if you want this routine to compile for a big-endian processor
//#define WORDS_BIGENDIAN

typedef struct 
{
	uint64_t totalLength;
	uint32_t hash[SHA256_HASH_WORDS];
	uint32_t bufferLength;
	union 
	{
		uint32_t words[16];
		uint8_t bytes[64];
	} buffer;
} sha256_ctx_t;

void sha256_init(sha256_ctx_t * sc);
void sha256_update(sha256_ctx_t * sc, const void *data, uint32_t len);
void sha256_finalize(sha256_ctx_t * sc, uint8_t hash[SHA256_HASH_SIZE]);


#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

#define Ch(x, y, z) ((z) ^ ((x) & ((y) ^ (z))))
#define Maj(x, y, z) (((x) & ((y) | (z))) | ((y) & (z)))
#define SIGMA0(x) (ROTR((x), 2) ^ ROTR((x), 13) ^ ROTR((x), 22))
#define SIGMA1(x) (ROTR((x), 6) ^ ROTR((x), 11) ^ ROTR((x), 25))
#define sigma0(x) (ROTR((x), 7) ^ ROTR((x), 18) ^ ((x) >> 3))
#define sigma1(x) (ROTR((x), 17) ^ ROTR((x), 19) ^ ((x) >> 10))

#define DO_ROUND() {							\
		t1 = h + SIGMA1(e) + Ch(e, f, g) + *(Kp++) + *(W++);	\
		t2 = SIGMA0(a) + Maj(a, b, c);				\
		h = g;							\
		g = f;							\
		f = e;							\
		e = d + t1;						\
		d = c;							\
		c = b;							\
		b = a;							\
		a = t1 + t2;						\
	}

static const uint32_t K[64] = {
	0x428a2f98L, 0x71374491L, 0xb5c0fbcfL, 0xe9b5dba5L,
	0x3956c25bL, 0x59f111f1L, 0x923f82a4L, 0xab1c5ed5L,
	0xd807aa98L, 0x12835b01L, 0x243185beL, 0x550c7dc3L,
	0x72be5d74L, 0x80deb1feL, 0x9bdc06a7L, 0xc19bf174L,
	0xe49b69c1L, 0xefbe4786L, 0x0fc19dc6L, 0x240ca1ccL,
	0x2de92c6fL, 0x4a7484aaL, 0x5cb0a9dcL, 0x76f988daL,
	0x983e5152L, 0xa831c66dL, 0xb00327c8L, 0xbf597fc7L,
	0xc6e00bf3L, 0xd5a79147L, 0x06ca6351L, 0x14292967L,
	0x27b70a85L, 0x2e1b2138L, 0x4d2c6dfcL, 0x53380d13L,
	0x650a7354L, 0x766a0abbL, 0x81c2c92eL, 0x92722c85L,
	0xa2bfe8a1L, 0xa81a664bL, 0xc24b8b70L, 0xc76c51a3L,
	0xd192e819L, 0xd6990624L, 0xf40e3585L, 0x106aa070L,
	0x19a4c116L, 0x1e376c08L, 0x2748774cL, 0x34b0bcb5L,
	0x391c0cb3L, 0x4ed8aa4aL, 0x5b9cca4fL, 0x682e6ff3L,
	0x748f82eeL, 0x78a5636fL, 0x84c87814L, 0x8cc70208L,
	0x90befffaL, 0xa4506cebL, 0xbef9a3f7L, 0xc67178f2L
};

#ifndef RUNTIME_ENDIAN

#ifdef WORDS_BIGENDIAN

#define BYTESWAP(x) (x)
#define BYTESWAP64(x) (x)

#else				/* WORDS_BIGENDIAN */

#define BYTESWAP(x) ((ROTR((x), 8) & 0xff00ff00L) |	\
		     (ROTL((x), 8) & 0x00ff00ffL))
#define BYTESWAP64(x) _byteswap64(x)

static inline uint64_t _byteswap64(uint64_t x)
{
	uint32_t a = x >> 32;
	uint32_t b = (uint32_t) x;
	return ((uint64_t) BYTESWAP(b) << 32) | (uint64_t) BYTESWAP(a);
}

#endif				/* WORDS_BIGENDIAN */

#else				/* !RUNTIME_ENDIAN */

static int littleEndian;

#define BYTESWAP(x) _byteswap(x)
#define BYTESWAP64(x) _byteswap64(x)

#define _BYTESWAP(x) ((ROTR((x), 8) & 0xff00ff00L) |	\
		      (ROTL((x), 8) & 0x00ff00ffL))
#define _BYTESWAP64(x) __byteswap64(x)

static inline uint64_t __byteswap64(uint64_t x)
{
	uint32_t a = x >> 32;
	uint32_t b = (uint32_t) x;
	return ((uint64_t) _BYTESWAP(b) << 32) | (uint64_t) _BYTESWAP(a);
}

static inline uint32_t _byteswap(uint32_t x)
{
	if (!littleEndian)
		return x;
	else
		return _BYTESWAP(x);
}

static inline uint64_t _byteswap64(uint64_t x)
{
	if (!littleEndian)
		return x;
	else
		return _BYTESWAP64(x);
}

static inline void setEndian(void)
{
	union {
		uint32_t w;
		uint8_t b[4];
	} endian;

	endian.w = 1L;
	littleEndian = endian.b[0] != 0;
}

#endif				/* !RUNTIME_ENDIAN */

static const uint8_t padding[64] = {
	0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

void sha256_init(sha256_ctx_t * sc)
{
#ifdef RUNTIME_ENDIAN
	setEndian();
#endif				/* RUNTIME_ENDIAN */

	sc->totalLength = 0LL;
	sc->hash[0] = 0x6a09e667L;
	sc->hash[1] = 0xbb67ae85L;
	sc->hash[2] = 0x3c6ef372L;
	sc->hash[3] = 0xa54ff53aL;
	sc->hash[4] = 0x510e527fL;
	sc->hash[5] = 0x9b05688cL;
	sc->hash[6] = 0x1f83d9abL;
	sc->hash[7] = 0x5be0cd19L;
	sc->bufferLength = 0L;
}

static void burnStack(int size)
{
	char buf[128];

	memset(buf, 0, sizeof(buf));
	size -= sizeof(buf);
	if (size > 0)
		burnStack(size);
}

static void SHA256Guts(sha256_ctx_t * sc, const uint32_t * cbuf)
{
	uint32_t buf[64];
	uint32_t *W, *W2, *W7, *W15, *W16;
	uint32_t a, b, c, d, e, f, g, h;
	uint32_t t1, t2;
	const uint32_t *Kp;
	int i;

	W = buf;

	for (i = 15; i >= 0; i--) {
		*(W++) = BYTESWAP(*cbuf);
		cbuf++;
	}

	W16 = &buf[0];
	W15 = &buf[1];
	W7 = &buf[9];
	W2 = &buf[14];

	for (i = 47; i >= 0; i--) {
		*(W++) = sigma1(*W2) + *(W7++) + sigma0(*W15) + *(W16++);
		W2++;
		W15++;
	}

	a = sc->hash[0];
	b = sc->hash[1];
	c = sc->hash[2];
	d = sc->hash[3];
	e = sc->hash[4];
	f = sc->hash[5];
	g = sc->hash[6];
	h = sc->hash[7];

	Kp = K;
	W = buf;

#ifndef SHA256_UNROLL
#define SHA256_UNROLL 1
#endif				/* !SHA256_UNROLL */

#if SHA256_UNROLL == 1
	for (i = 63; i >= 0; i--)
		DO_ROUND();
#elif SHA256_UNROLL == 2
	for (i = 31; i >= 0; i--) {
		DO_ROUND();
		DO_ROUND();
	}
#elif SHA256_UNROLL == 4
	for (i = 15; i >= 0; i--) {
		DO_ROUND();
		DO_ROUND();
		DO_ROUND();
		DO_ROUND();
	}
#elif SHA256_UNROLL == 8
	for (i = 7; i >= 0; i--) {
		DO_ROUND();
		DO_ROUND();
		DO_ROUND();
		DO_ROUND();
		DO_ROUND();
		DO_ROUND();
		DO_ROUND();
		DO_ROUND();
	}
#elif SHA256_UNROLL == 16
	for (i = 3; i >= 0; i--) {
		DO_ROUND();
		DO_ROUND();
		DO_ROUND();
		DO_ROUND();
		DO_ROUND();
		DO_ROUND();
		DO_ROUND();
		DO_ROUND();
		DO_ROUND();
		DO_ROUND();
		DO_ROUND();
		DO_ROUND();
		DO_ROUND();
		DO_ROUND();
		DO_ROUND();
		DO_ROUND();
	}
#elif SHA256_UNROLL == 32
	for (i = 1; i >= 0; i--) {
		DO_ROUND();
		DO_ROUND();
		DO_ROUND();
		DO_ROUND();
		DO_ROUND();
		DO_ROUND();
		DO_ROUND();
		DO_ROUND();
		DO_ROUND();
		DO_ROUND();
		DO_ROUND();
		DO_ROUND();
		DO_ROUND();
		DO_ROUND();
		DO_ROUND();
		DO_ROUND();
		DO_ROUND();
		DO_ROUND();
		DO_ROUND();
		DO_ROUND();
		DO_ROUND();
		DO_ROUND();
		DO_ROUND();
		DO_ROUND();
		DO_ROUND();
		DO_ROUND();
		DO_ROUND();
		DO_ROUND();
		DO_ROUND();
		DO_ROUND();
		DO_ROUND();
		DO_ROUND();
	}
#elif SHA256_UNROLL == 64
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
	DO_ROUND();
#else
#error "SHA256_UNROLL must be 1, 2, 4, 8, 16, 32, or 64!"
#endif

	sc->hash[0] += a;
	sc->hash[1] += b;
	sc->hash[2] += c;
	sc->hash[3] += d;
	sc->hash[4] += e;
	sc->hash[5] += f;
	sc->hash[6] += g;
	sc->hash[7] += h;
}

void sha256_update(sha256_ctx_t * sc, const void *data, uint32_t len)
{
	uint32_t bufferBytesLeft;
	uint32_t bytesToCopy;
	int needBurn = 0;

	if (sc->bufferLength) 
	{
		bufferBytesLeft = 64L - sc->bufferLength;
		bytesToCopy = bufferBytesLeft;
		if (bytesToCopy > len)
		{
			bytesToCopy = len;
		}
		memcpy(&sc->buffer.bytes[sc->bufferLength], data, bytesToCopy);
		sc->totalLength += bytesToCopy * 8L;
		sc->bufferLength += bytesToCopy;
		data = ((uint8_t *) data) + bytesToCopy;
		len -= bytesToCopy;
		if (sc->bufferLength == 64L) 
		{
			SHA256Guts(sc, sc->buffer.words);
			needBurn = 1;
			sc->bufferLength = 0L;
		}
	}

	while (len > 63L) 
	{
		sc->totalLength += 512L;

		SHA256Guts(sc, (const uint32_t *)data);
		needBurn = 1;

		data = ((uint8_t *) data) + 64L;
		len -= 64L;
	}

	if (len) 
	{
		memcpy(&sc->buffer.bytes[sc->bufferLength], data, len);
		sc->totalLength += len * 8L;
		sc->bufferLength += len;
	}

	if (needBurn)
	{
		burnStack(sizeof(uint32_t[74]) + sizeof(uint32_t *[6]) +  sizeof(int));
	}
}

void sha256_finalize(sha256_ctx_t * sc, uint8_t hash[SHA256_HASH_SIZE])
{
	uint32_t bytesToPad;
	uint64_t lengthPad;
	int i;

	bytesToPad = 120L - sc->bufferLength;
	if (bytesToPad > 64L)
	{
		bytesToPad -= 64L;
	}

	lengthPad = BYTESWAP64(sc->totalLength);

	sha256_update(sc, padding, bytesToPad);
	sha256_update(sc, &lengthPad, 8L);

	if (hash) 
	{
		for (i = 0; i < SHA256_HASH_WORDS; i++) 
		{
			*((uint32_t *) hash) = BYTESWAP(sc->hash[i]);
			hash += 4;
		}
	}
}


void computeSHA256(const void *input,uint32_t size,uint8_t destHash[32])
{
	sha256_ctx_t sc;
	sha256_init(&sc);
	sha256_update(&sc,input,size);
	sha256_finalize(&sc,destHash);
}

namespace RIPEMD160
{
  /********************************************************************/

/* macro definitions */

/* collect four bytes into one word: */
#define BYTES_TO_DWORD(strptr)                  \
            (((uint32_t) *((strptr)+3) << 24) | \
             ((uint32_t) *((strptr)+2) << 16) | \
             ((uint32_t) *((strptr)+1) <<  8) | \
             ((uint32_t) *(strptr)))

/* ROL(x, n) cyclically rotates x over n bits to the left */
/* x must be of an unsigned 32 bits type and 0 <= n < 32. */
#define ROL(x, n)        (((x) << (n)) | ((x) >> (32-(n))))

/* the five basic functions F(), G() and H() */
#define F(x, y, z)        ((x) ^ (y) ^ (z)) 
#define G(x, y, z)        (((x) & (y)) | (~(x) & (z))) 
#define H(x, y, z)        (((x) | ~(y)) ^ (z))
#define I(x, y, z)        (((x) & (z)) | ((y) & ~(z))) 
#define J(x, y, z)        ((x) ^ ((y) | ~(z)))
  
/* the ten basic operations FF() through III() */
#define FF(a, b, c, d, e, x, s)        {\
      (a) += F((b), (c), (d)) + (x);\
      (a) = ROL((a), (s)) + (e);\
      (c) = ROL((c), 10);\
   }
#define GG(a, b, c, d, e, x, s)        {\
      (a) += G((b), (c), (d)) + (x) + 0x5a827999UL;\
      (a) = ROL((a), (s)) + (e);\
      (c) = ROL((c), 10);\
   }
#define HH(a, b, c, d, e, x, s)        {\
      (a) += H((b), (c), (d)) + (x) + 0x6ed9eba1UL;\
      (a) = ROL((a), (s)) + (e);\
      (c) = ROL((c), 10);\
   }
#define II(a, b, c, d, e, x, s)        {\
      (a) += I((b), (c), (d)) + (x) + 0x8f1bbcdcUL;\
      (a) = ROL((a), (s)) + (e);\
      (c) = ROL((c), 10);\
   }
#define JJ(a, b, c, d, e, x, s)        {\
      (a) += J((b), (c), (d)) + (x) + 0xa953fd4eUL;\
      (a) = ROL((a), (s)) + (e);\
      (c) = ROL((c), 10);\
   }
#define FFF(a, b, c, d, e, x, s)        {\
      (a) += F((b), (c), (d)) + (x);\
      (a) = ROL((a), (s)) + (e);\
      (c) = ROL((c), 10);\
   }
#define GGG(a, b, c, d, e, x, s)        {\
      (a) += G((b), (c), (d)) + (x) + 0x7a6d76e9UL;\
      (a) = ROL((a), (s)) + (e);\
      (c) = ROL((c), 10);\
   }
#define HHH(a, b, c, d, e, x, s)        {\
      (a) += H((b), (c), (d)) + (x) + 0x6d703ef3UL;\
      (a) = ROL((a), (s)) + (e);\
      (c) = ROL((c), 10);\
   }
#define III(a, b, c, d, e, x, s)        {\
      (a) += I((b), (c), (d)) + (x) + 0x5c4dd124UL;\
      (a) = ROL((a), (s)) + (e);\
      (c) = ROL((c), 10);\
   }
#define JJJ(a, b, c, d, e, x, s)        {\
      (a) += J((b), (c), (d)) + (x) + 0x50a28be6UL;\
      (a) = ROL((a), (s)) + (e);\
      (c) = ROL((c), 10);\
   }

/********************************************************************/

/* function prototypes */

void MDinit(uint32_t *MDbuf);
/*
 *  initializes MDbuffer to "magic constants"
 */

void compress(uint32_t *MDbuf, uint32_t *X);
/*
 *  the compression function.
 *  transforms MDbuf using message bytes X[0] through X[15]
 */

void MDfinish(uint32_t *MDbuf,const uint8_t *strptr, uint32_t lswlen, uint32_t mswlen);
/*
 *  puts bytes from strptr into X and pad out; appends length 
 *  and finally, compresses the last block(s)
 *  note: length in bits == 8 * (lswlen + 2^32 mswlen).
 *  note: there are (lswlen mod 64) bytes left in strptr.
 */

/********************************************************************/

void MDinit(uint32_t *MDbuf)
{
   MDbuf[0] = 0x67452301UL;
   MDbuf[1] = 0xefcdab89UL;
   MDbuf[2] = 0x98badcfeUL;
   MDbuf[3] = 0x10325476UL;
   MDbuf[4] = 0xc3d2e1f0UL;

   return;
}

/********************************************************************/

void compress(uint32_t *MDbuf, uint32_t *X)
{
   uint32_t aa = MDbuf[0],  bb = MDbuf[1],  cc = MDbuf[2],
         dd = MDbuf[3],  ee = MDbuf[4];
   uint32_t aaa = MDbuf[0], bbb = MDbuf[1], ccc = MDbuf[2],
         ddd = MDbuf[3], eee = MDbuf[4];

   /* round 1 */
   FF(aa, bb, cc, dd, ee, X[ 0], 11);
   FF(ee, aa, bb, cc, dd, X[ 1], 14);
   FF(dd, ee, aa, bb, cc, X[ 2], 15);
   FF(cc, dd, ee, aa, bb, X[ 3], 12);
   FF(bb, cc, dd, ee, aa, X[ 4],  5);
   FF(aa, bb, cc, dd, ee, X[ 5],  8);
   FF(ee, aa, bb, cc, dd, X[ 6],  7);
   FF(dd, ee, aa, bb, cc, X[ 7],  9);
   FF(cc, dd, ee, aa, bb, X[ 8], 11);
   FF(bb, cc, dd, ee, aa, X[ 9], 13);
   FF(aa, bb, cc, dd, ee, X[10], 14);
   FF(ee, aa, bb, cc, dd, X[11], 15);
   FF(dd, ee, aa, bb, cc, X[12],  6);
   FF(cc, dd, ee, aa, bb, X[13],  7);
   FF(bb, cc, dd, ee, aa, X[14],  9);
   FF(aa, bb, cc, dd, ee, X[15],  8);
                             
   /* round 2 */
   GG(ee, aa, bb, cc, dd, X[ 7],  7);
   GG(dd, ee, aa, bb, cc, X[ 4],  6);
   GG(cc, dd, ee, aa, bb, X[13],  8);
   GG(bb, cc, dd, ee, aa, X[ 1], 13);
   GG(aa, bb, cc, dd, ee, X[10], 11);
   GG(ee, aa, bb, cc, dd, X[ 6],  9);
   GG(dd, ee, aa, bb, cc, X[15],  7);
   GG(cc, dd, ee, aa, bb, X[ 3], 15);
   GG(bb, cc, dd, ee, aa, X[12],  7);
   GG(aa, bb, cc, dd, ee, X[ 0], 12);
   GG(ee, aa, bb, cc, dd, X[ 9], 15);
   GG(dd, ee, aa, bb, cc, X[ 5],  9);
   GG(cc, dd, ee, aa, bb, X[ 2], 11);
   GG(bb, cc, dd, ee, aa, X[14],  7);
   GG(aa, bb, cc, dd, ee, X[11], 13);
   GG(ee, aa, bb, cc, dd, X[ 8], 12);

   /* round 3 */
   HH(dd, ee, aa, bb, cc, X[ 3], 11);
   HH(cc, dd, ee, aa, bb, X[10], 13);
   HH(bb, cc, dd, ee, aa, X[14],  6);
   HH(aa, bb, cc, dd, ee, X[ 4],  7);
   HH(ee, aa, bb, cc, dd, X[ 9], 14);
   HH(dd, ee, aa, bb, cc, X[15],  9);
   HH(cc, dd, ee, aa, bb, X[ 8], 13);
   HH(bb, cc, dd, ee, aa, X[ 1], 15);
   HH(aa, bb, cc, dd, ee, X[ 2], 14);
   HH(ee, aa, bb, cc, dd, X[ 7],  8);
   HH(dd, ee, aa, bb, cc, X[ 0], 13);
   HH(cc, dd, ee, aa, bb, X[ 6],  6);
   HH(bb, cc, dd, ee, aa, X[13],  5);
   HH(aa, bb, cc, dd, ee, X[11], 12);
   HH(ee, aa, bb, cc, dd, X[ 5],  7);
   HH(dd, ee, aa, bb, cc, X[12],  5);

   /* round 4 */
   II(cc, dd, ee, aa, bb, X[ 1], 11);
   II(bb, cc, dd, ee, aa, X[ 9], 12);
   II(aa, bb, cc, dd, ee, X[11], 14);
   II(ee, aa, bb, cc, dd, X[10], 15);
   II(dd, ee, aa, bb, cc, X[ 0], 14);
   II(cc, dd, ee, aa, bb, X[ 8], 15);
   II(bb, cc, dd, ee, aa, X[12],  9);
   II(aa, bb, cc, dd, ee, X[ 4],  8);
   II(ee, aa, bb, cc, dd, X[13],  9);
   II(dd, ee, aa, bb, cc, X[ 3], 14);
   II(cc, dd, ee, aa, bb, X[ 7],  5);
   II(bb, cc, dd, ee, aa, X[15],  6);
   II(aa, bb, cc, dd, ee, X[14],  8);
   II(ee, aa, bb, cc, dd, X[ 5],  6);
   II(dd, ee, aa, bb, cc, X[ 6],  5);
   II(cc, dd, ee, aa, bb, X[ 2], 12);

   /* round 5 */
   JJ(bb, cc, dd, ee, aa, X[ 4],  9);
   JJ(aa, bb, cc, dd, ee, X[ 0], 15);
   JJ(ee, aa, bb, cc, dd, X[ 5],  5);
   JJ(dd, ee, aa, bb, cc, X[ 9], 11);
   JJ(cc, dd, ee, aa, bb, X[ 7],  6);
   JJ(bb, cc, dd, ee, aa, X[12],  8);
   JJ(aa, bb, cc, dd, ee, X[ 2], 13);
   JJ(ee, aa, bb, cc, dd, X[10], 12);
   JJ(dd, ee, aa, bb, cc, X[14],  5);
   JJ(cc, dd, ee, aa, bb, X[ 1], 12);
   JJ(bb, cc, dd, ee, aa, X[ 3], 13);
   JJ(aa, bb, cc, dd, ee, X[ 8], 14);
   JJ(ee, aa, bb, cc, dd, X[11], 11);
   JJ(dd, ee, aa, bb, cc, X[ 6],  8);
   JJ(cc, dd, ee, aa, bb, X[15],  5);
   JJ(bb, cc, dd, ee, aa, X[13],  6);

   /* parallel round 1 */
   JJJ(aaa, bbb, ccc, ddd, eee, X[ 5],  8);
   JJJ(eee, aaa, bbb, ccc, ddd, X[14],  9);
   JJJ(ddd, eee, aaa, bbb, ccc, X[ 7],  9);
   JJJ(ccc, ddd, eee, aaa, bbb, X[ 0], 11);
   JJJ(bbb, ccc, ddd, eee, aaa, X[ 9], 13);
   JJJ(aaa, bbb, ccc, ddd, eee, X[ 2], 15);
   JJJ(eee, aaa, bbb, ccc, ddd, X[11], 15);
   JJJ(ddd, eee, aaa, bbb, ccc, X[ 4],  5);
   JJJ(ccc, ddd, eee, aaa, bbb, X[13],  7);
   JJJ(bbb, ccc, ddd, eee, aaa, X[ 6],  7);
   JJJ(aaa, bbb, ccc, ddd, eee, X[15],  8);
   JJJ(eee, aaa, bbb, ccc, ddd, X[ 8], 11);
   JJJ(ddd, eee, aaa, bbb, ccc, X[ 1], 14);
   JJJ(ccc, ddd, eee, aaa, bbb, X[10], 14);
   JJJ(bbb, ccc, ddd, eee, aaa, X[ 3], 12);
   JJJ(aaa, bbb, ccc, ddd, eee, X[12],  6);

   /* parallel round 2 */
   III(eee, aaa, bbb, ccc, ddd, X[ 6],  9); 
   III(ddd, eee, aaa, bbb, ccc, X[11], 13);
   III(ccc, ddd, eee, aaa, bbb, X[ 3], 15);
   III(bbb, ccc, ddd, eee, aaa, X[ 7],  7);
   III(aaa, bbb, ccc, ddd, eee, X[ 0], 12);
   III(eee, aaa, bbb, ccc, ddd, X[13],  8);
   III(ddd, eee, aaa, bbb, ccc, X[ 5],  9);
   III(ccc, ddd, eee, aaa, bbb, X[10], 11);
   III(bbb, ccc, ddd, eee, aaa, X[14],  7);
   III(aaa, bbb, ccc, ddd, eee, X[15],  7);
   III(eee, aaa, bbb, ccc, ddd, X[ 8], 12);
   III(ddd, eee, aaa, bbb, ccc, X[12],  7);
   III(ccc, ddd, eee, aaa, bbb, X[ 4],  6);
   III(bbb, ccc, ddd, eee, aaa, X[ 9], 15);
   III(aaa, bbb, ccc, ddd, eee, X[ 1], 13);
   III(eee, aaa, bbb, ccc, ddd, X[ 2], 11);

   /* parallel round 3 */
   HHH(ddd, eee, aaa, bbb, ccc, X[15],  9);
   HHH(ccc, ddd, eee, aaa, bbb, X[ 5],  7);
   HHH(bbb, ccc, ddd, eee, aaa, X[ 1], 15);
   HHH(aaa, bbb, ccc, ddd, eee, X[ 3], 11);
   HHH(eee, aaa, bbb, ccc, ddd, X[ 7],  8);
   HHH(ddd, eee, aaa, bbb, ccc, X[14],  6);
   HHH(ccc, ddd, eee, aaa, bbb, X[ 6],  6);
   HHH(bbb, ccc, ddd, eee, aaa, X[ 9], 14);
   HHH(aaa, bbb, ccc, ddd, eee, X[11], 12);
   HHH(eee, aaa, bbb, ccc, ddd, X[ 8], 13);
   HHH(ddd, eee, aaa, bbb, ccc, X[12],  5);
   HHH(ccc, ddd, eee, aaa, bbb, X[ 2], 14);
   HHH(bbb, ccc, ddd, eee, aaa, X[10], 13);
   HHH(aaa, bbb, ccc, ddd, eee, X[ 0], 13);
   HHH(eee, aaa, bbb, ccc, ddd, X[ 4],  7);
   HHH(ddd, eee, aaa, bbb, ccc, X[13],  5);

   /* parallel round 4 */   
   GGG(ccc, ddd, eee, aaa, bbb, X[ 8], 15);
   GGG(bbb, ccc, ddd, eee, aaa, X[ 6],  5);
   GGG(aaa, bbb, ccc, ddd, eee, X[ 4],  8);
   GGG(eee, aaa, bbb, ccc, ddd, X[ 1], 11);
   GGG(ddd, eee, aaa, bbb, ccc, X[ 3], 14);
   GGG(ccc, ddd, eee, aaa, bbb, X[11], 14);
   GGG(bbb, ccc, ddd, eee, aaa, X[15],  6);
   GGG(aaa, bbb, ccc, ddd, eee, X[ 0], 14);
   GGG(eee, aaa, bbb, ccc, ddd, X[ 5],  6);
   GGG(ddd, eee, aaa, bbb, ccc, X[12],  9);
   GGG(ccc, ddd, eee, aaa, bbb, X[ 2], 12);
   GGG(bbb, ccc, ddd, eee, aaa, X[13],  9);
   GGG(aaa, bbb, ccc, ddd, eee, X[ 9], 12);
   GGG(eee, aaa, bbb, ccc, ddd, X[ 7],  5);
   GGG(ddd, eee, aaa, bbb, ccc, X[10], 15);
   GGG(ccc, ddd, eee, aaa, bbb, X[14],  8);

   /* parallel round 5 */
   FFF(bbb, ccc, ddd, eee, aaa, X[12] ,  8);
   FFF(aaa, bbb, ccc, ddd, eee, X[15] ,  5);
   FFF(eee, aaa, bbb, ccc, ddd, X[10] , 12);
   FFF(ddd, eee, aaa, bbb, ccc, X[ 4] ,  9);
   FFF(ccc, ddd, eee, aaa, bbb, X[ 1] , 12);
   FFF(bbb, ccc, ddd, eee, aaa, X[ 5] ,  5);
   FFF(aaa, bbb, ccc, ddd, eee, X[ 8] , 14);
   FFF(eee, aaa, bbb, ccc, ddd, X[ 7] ,  6);
   FFF(ddd, eee, aaa, bbb, ccc, X[ 6] ,  8);
   FFF(ccc, ddd, eee, aaa, bbb, X[ 2] , 13);
   FFF(bbb, ccc, ddd, eee, aaa, X[13] ,  6);
   FFF(aaa, bbb, ccc, ddd, eee, X[14] ,  5);
   FFF(eee, aaa, bbb, ccc, ddd, X[ 0] , 15);
   FFF(ddd, eee, aaa, bbb, ccc, X[ 3] , 13);
   FFF(ccc, ddd, eee, aaa, bbb, X[ 9] , 11);
   FFF(bbb, ccc, ddd, eee, aaa, X[11] , 11);

   /* combine results */
   ddd += cc + MDbuf[1];               /* final result for MDbuf[0] */
   MDbuf[1] = MDbuf[2] + dd + eee;
   MDbuf[2] = MDbuf[3] + ee + aaa;
   MDbuf[3] = MDbuf[4] + aa + bbb;
   MDbuf[4] = MDbuf[0] + bb + ccc;
   MDbuf[0] = ddd;

   return;
}

/********************************************************************/

void MDfinish(uint32_t *MDbuf,const uint8_t *strptr, uint32_t lswlen, uint32_t mswlen)
{
   unsigned int i;                                 /* counter       */
   uint32_t        X[16];                             /* message words */

   memset(X, 0, 16*sizeof(uint32_t));

   /* put bytes from strptr into X */
   for (i=0; i<(lswlen&63); i++) {
      /* uint8_t i goes into word X[i div 4] at pos.  8*(i mod 4)  */
      X[i>>2] ^= (uint32_t) *strptr++ << (8 * (i&3));
   }

   /* append the bit m_n == 1 */
   X[(lswlen>>2)&15] ^= (uint32_t)1 << (8*(lswlen&3) + 7);

   if ((lswlen & 63) > 55) {
      /* length goes to next block */
      compress(MDbuf, X);
      memset(X, 0, 16*sizeof(uint32_t));
   }

   /* append length in bits*/
   X[14] = lswlen << 3;
   X[15] = (lswlen >> 29) | (mswlen << 3);
   compress(MDbuf, X);

   return;
}

#define RMDsize 160

void computeRIPEMD160(const void *_message,uint32_t length,uint8_t hashcode[20])
/*
 * returns RMD(message)
 * message should be a string terminated by '\0'
 */
{
        const uint8_t *message = (const uint8_t *)_message;
        uint32_t         MDbuf[RMDsize/32];   /* contains (A, B, C, D(, E))   */
        uint32_t         X[16];               /* current 16-word chunk        */

        /* initialize */
        MDinit(MDbuf);

        /* process message in 16-word chunks */
        for (uint32_t nbytes=length; nbytes > 63; nbytes-=64) 
        {
                for (uint32_t i=0; i<16; i++) 
                {
                        X[i] = BYTES_TO_DWORD(message);
                        message += 4;
                }
                compress(MDbuf, X);
        }       /* length mod 64 bytes left */

        /* finish: */
        MDfinish(MDbuf, message, length, 0);

        for (uint32_t i=0; i<RMDsize/8; i+=4) 
        {
                hashcode[i]   = (uint8_t)(MDbuf[i>>2]);         /* implicit cast to uint8_t  */
                hashcode[i+1] = (uint8_t)(MDbuf[i>>2] >>  8);  /*  extracts the 8 least  */
                hashcode[i+2] = (uint8_t)(MDbuf[i>>2] >> 16);  /*  significant bits.     */
                hashcode[i+3] = (uint8_t)(MDbuf[i>>2] >> 24);
        }

}
};

void computeRIPEMD160(const void *_message,uint32_t length,uint8_t hashcode[20])
{
  RIPEMD160::computeRIPEMD160(_message, length, hashcode);
}

