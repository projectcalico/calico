
/* jhash.h: Jenkins hash support.
 *
 * Copyright (C) 2006. Bob Jenkins (bob_jenkins@burtleburtle.net)
 *
 * https://burtleburtle.net/bob/hash/
 *
 * These are the credits from Bob's sources:
 *
 * lookup3.c, by Bob Jenkins, May 2006, Public Domain.
 *
 * These are functions for producing 32-bit hashes for hash table lookup.
 * hashword(), hashlittle(), hashlittle2(), hashbig(), mix(), and final()
 * are externally useful functions.  Routines to test the hash are included
 * if SELF_TEST is defined.  You can use this free for any purpose.  It's in
 * the public domain.  It has no warranty.
 *
 * Copyright (C) 2009-2010 Jozsef Kadlecsik (kadlec@blackhole.kfki.hu)
 *
 * I've modified Bob's hash to be useful in the Linux kernel, and
 * any bugs present are my fault.
 * Jozsef
 */

#ifndef _LINUX_JHASH_H
#define _LINUX_JHASH_H

#include "bpf.h"

/**
 * rol32 - rotate a 32-bit value left
 * @word: value to rotate
 * @shift: bits to roll
 * 
 * # MSG FROM ALEX:
 * > I took this function from linux/tools/include/linux/bitops.h
 * > instead of including the whole dependency.
 * > bitops.h has: SPDX-License-Identifier: GPL-2.0
 */
static CALI_BPF_INLINE __u32 rol32(__u32 word, unsigned int shift)
{
	return (word << shift) | (word >> ((-shift) & 31));
}

/* An arbitrary initial parameter */
#define JHASH_INITVAL		0xdeadbeef


/* __jhash_nwords - hash exactly 3, 2 or 1 word(s) */
static CALI_BPF_INLINE __u32 __jhash_nwords(__u32 a, __u32 b, __u32 c, __u32 initval)
{
	a += initval;
	b += initval;
	c += initval;

	c ^= b; c -= rol32(b, 14);
	a ^= c; a -= rol32(c, 11);
	b ^= a; b -= rol32(a, 25);
	c ^= b; c -= rol32(b, 16);
	a ^= c; a -= rol32(c, 4);
	b ^= a; b -= rol32(a, 14);
	c ^= b; c -= rol32(b, 24);

	return c;
}

static CALI_BPF_INLINE __u32 jhash_3words(__u32 a, __u32 b, __u32 c, __u32 initval)
{
	return __jhash_nwords(a, b, c, initval + JHASH_INITVAL + (3 << 2));
}

#endif