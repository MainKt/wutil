/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025, Muhammad Saheed <saheed@FreeBSD.org>
 */

#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <wchar.h>

#define nitems(a) (sizeof((a)) / sizeof((*a)))

size_t ssid_to_wcs(const char *ssid, wchar_t **out);
size_t ssid_extra_width(const char *ssid);
size_t display_width(const char *ssid);
char *unescape(char *s, size_t len);

#endif /* !UTILS_H */
