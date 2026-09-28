/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025, Muhammad Saheed <saheed@FreeBSD.org>
 */

#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <wchar.h>

size_t ssid_to_wcs(const char *ssid, wchar_t **out);
size_t ssid_extra_width(const char *ssid);
size_t display_width(const char *ssid);
char *unescape(char *s, size_t len);
size_t last_codepoint_pos(const char *s, size_t len);

#endif /* !UTILS_H */
