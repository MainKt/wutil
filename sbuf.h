/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025, Muhammad Saheed <saheed@FreeBSD.org>
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "array.h"

#ifndef SBUF_H
#define SBUF_H

ARRAY(sbuf, char);

ARRAY_APPEND_PROTOTYPE(sbuf)

struct sbuf *sbuf_new_auto(void);
void sbuf_clear(struct sbuf *s);
int sbuf_bcat(struct sbuf *s, const void *buf, size_t len);
int sbuf_cat(struct sbuf *s, const char *str);
int sbuf_printf(struct sbuf *s, const char *fmt, ...);
int sbuf_putc(struct sbuf *s, int c);
int sbuf_finish(struct sbuf *s);
char *sbuf_data(struct sbuf *s);
ssize_t sbuf_len(struct sbuf *s);
void sbuf_delete(struct sbuf *s);

#endif /* !SBUF_H */
