/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025, Muhammad Saheed <saheed@FreeBSD.org>
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sbuf.h"

ARRAY_APPEND_DEFINITION(sbuf)

struct sbuf *
sbuf_new_auto(void)
{
	struct sbuf *s = (struct sbuf *)malloc(sizeof(*s));

	if (s == NULL)
		return (NULL);

	*s = ARRAY_INITIALIZER(sbuf);

	return (s);
}

void
sbuf_clear(struct sbuf *s)
{
	ARRAY_FREE(s);
}

int
sbuf_bcat(struct sbuf *s, const void *buf, size_t len)
{
	const char *str = (const char *)buf;

	for (size_t i = 0; i < len; i++) {
		if (!ARRAY_APPEND(sbuf, s, str[i]))
			return (1);
	}

	return (0);
}

int
sbuf_cat(struct sbuf *s, const char *str)
{
	return (sbuf_bcat(s, (void *)str, strlen(str)));
}

int
sbuf_printf(struct sbuf *s, const char *fmt, ...)
{
	char *formatted = NULL;
	va_list ap;
	int ret = 0;

	va_start(ap, fmt);
	if (vasprintf(&formatted, fmt, ap) == -1)
		return (-1);
	va_end(ap);

	ret = sbuf_cat(s, formatted);
	free(formatted);

	return (ret);
}

int
sbuf_putc(struct sbuf *s, int c)
{
	return (!ARRAY_APPEND(sbuf, s, c));
}

int
sbuf_finish(struct sbuf *s)
{
	if (sbuf_putc(s, '\0') != 0)
		return (1);
	s->len--; /* NULL terminator shouldn't be part of the length */
	return (0);
}

char *
sbuf_data(struct sbuf *s)
{
	return (s->items);
}

ssize_t
sbuf_len(struct sbuf *s)
{
	return (s->len);
}

void
sbuf_delete(struct sbuf *s)
{
	if (s == NULL)
		return;

	sbuf_clear(s);
	free(s);
}
