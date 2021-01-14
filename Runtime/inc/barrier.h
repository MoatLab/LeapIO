/*-
 *   BSD LICENSE
 *
 *   Copyright (c) Intel Corporation.
 *   Copyright (c) 2017, IBM Corporation.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/** \file
 * Memory barriers
 */

/* Coperd: taken from SPDK */

#ifndef LEAP_BARRIER_H
#define LEAP_BARRIER_H


#ifdef __cplusplus
extern "C" {
#endif

/** Compiler memory barrier */
#define leap_compiler_barrier() __asm volatile("" ::: "memory")

/** Write memory barrier */
#ifdef __PPC64__
#define leap_wmb()	__asm volatile("sync" ::: "memory")
#elif defined(__aarch64__)
#define leap_wmb()	__asm volatile("dsb st" ::: "memory")
#elif defined(__i386__) || defined(__x86_64__)
#define leap_wmb()	__asm volatile("sfence" ::: "memory")
#else
#define leap_wmb()
#error Unknown architecture
#endif

/** Read memory barrier */
#ifdef __PPC64__
#define leap_rmb()	__asm volatile("sync" ::: "memory")
#elif defined(__aarch64__)
#define leap_rmb()	__asm volatile("dsb lt" ::: "memory")
#elif defined(__i386__) || defined(__x86_64__)
#define leap_rmb()	__asm volatile("lfence" ::: "memory")
#else
#define leap_rmb()
#error Unknown architecture
#endif

/** Full read/write memory barrier */
#ifdef __PPC64__
#define leap_mb()	__asm volatile("sync" ::: "memory")
#elif defined(__aarch64__)
#define leap_mb()	__asm volatile("dsb sy" ::: "memory")
#elif defined(__i386__) || defined(__x86_64__)
#define leap_mb()	__asm volatile("mfence" ::: "memory")
#else
#define leap_mb()
#error Unknown architecture
#endif

/** SMP read memory barrier. */
#ifdef __PPC64__
#define leap_smp_rmb()	__asm volatile("lwsync" ::: "memory")
#elif defined(__aarch64__)
#define leap_smp_rmb()	__asm volatile("dmb ishld" ::: "memory")
#elif defined(__i386__) || defined(__x86_64__)
#define leap_smp_rmb()	leap_compiler_barrier()
#else
#define leap_smp_rmb()
#error Unknown architecture
#endif

/** SMP write memory barrier. */
#ifdef __PPC64__
#define leap_smp_wmb()	__asm volatile("lwsync" ::: "memory")
#elif defined(__aarch64__)
#define leap_smp_wmb()	__asm volatile("dmb ishst" ::: "memory")
#elif defined(__i386__) || defined(__x86_64__)
#define leap_smp_wmb()	leap_compiler_barrier()
#else
#define leap_smp_wmb()
#error Unknown architecture
#endif

/** SMP read/write memory barrier. */
#ifdef __PPC64__
#define leap_smp_mb()	leap_mb()
#elif defined(__aarch64__)
#define leap_smp_mb()	__asm volatile("dmb ish" ::: "memory")
#elif defined(__i386__) || defined(__x86_64__)
#define leap_smp_mb()	leap_mb()
#else
#define leap_smp_mb()
#error Unknown architecture
#endif

#ifdef __cplusplus
}
#endif

#endif
