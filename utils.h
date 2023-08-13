/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef RBLCHECK_UTILS_H
#define RBLCHECK_UTILS_H

#define NOFAIL(ptr) do_nofail((ptr), __FILE__, __LINE__)

/* Portability macros */
#ifdef __GNUC__
# define NORETURN __attribute__((noreturn))
#else
# define NORETURN
#endif

/* Prototypes */
extern void *do_nofail(void *ptr, const char *file, const int line);

extern void NORETURN err_quit(const char *fmt, ...);
extern void NORETURN err_sys(const char *fmt, ...);

#endif
