/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025, Muhammad Saheed <saheed@FreeBSD.org>
 */

#include <net/if.h>
#include <net80211/ieee80211.h>

#include <ctype.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"

static uint8_t get_unescaped_char(uint8_t *s, size_t len, size_t *advance);
static int digit_to_int(char c);

static int
digit_to_int(char c)
{
	if (c >= '0' && c <= '9')
		return (c - '0');

	c = tolower(c);
	if (c >= 'a' && c <= 'f')
		return (c - 'a' + 10);

	return (0);
}

static uint8_t
get_unescaped_char(uint8_t *s, size_t len, size_t *advance)
{
	uint8_t single_escape[] = {
		['a'] = '\a',
		['b'] = '\b',
		['f'] = '\f',
		['n'] = '\n',
		['r'] = '\r',
		['t'] = '\t',
		['v'] = '\v',
		['\\'] = '\\',
		['\''] = '\'',
		['\"'] = '\"',
		['\?'] = '\?',
		[UINT8_MAX] = 0,
	};

	if (len == 0 || *s != '\\') {
		*advance = 0;
		return ('\0');
	}

	s++, len--;
	if (len == 0)
		goto abort;

	if (single_escape[s[0]] != 0) {
		(*advance) = 2 /* \[c] */;
		return (single_escape[s[0]]);
	}

	if (s[0] >= '0' && s[0] <= '7') {
		uint32_t c = 0;

		*advance = 1 /* \ */;
		for (size_t i = 0;
		    i < 3 && i < len && s[i] >= '0' && s[i] <= '7'; i++) {
			(*advance)++;
			c = c * 8 + digit_to_int(s[i]);
		}

		if (c > UINT8_MAX)
			goto abort;

		return (c);
	}

	if (s[0] == 'x') {
		uint32_t c = 0;

		*advance = 2 /* \x */;
		for (size_t i = 1; i < len && isxdigit(s[i]); i++) {
			(*advance)++;
			size_t d = digit_to_int(s[i]);
			c = c * 16 + d;
		}

		if (*advance == 2)
			goto abort;

		if (c > UINT8_MAX)
			goto abort;

		return (c);
	}

abort:
	*advance = 1;
	return ('\\');
}

char *
unescape(char *s, size_t len)
{
	size_t j = 0;
	if (len == 0)
		return (s);
	uint8_t *bytes = (uint8_t *)s;

	for (size_t i = 0; i < len;) {
		if (bytes[i] == '\\') {
			size_t advance = 0;

			bytes[j++] = get_unescaped_char(&bytes[i], len - i,
			    &advance);
			i += advance;
		} else {
			bytes[j++] = bytes[i++];
		}
	}
	bytes[j] = '\0';

	return (s);
}

size_t
ssid_to_wcs(const char *ssid, wchar_t **out)
{
	static wchar_t wssid[IEEE80211_NWID_LEN + 1];
	size_t len = mbstowcs(NULL, ssid, 0);

	if (len == (size_t)-1 || len >= sizeof(wssid) / sizeof(*wssid))
		return (-1);
	mbstowcs(wssid, ssid, IEEE80211_NWID_LEN + 1);
	*out = wssid;

	return (len);
}

size_t
display_width(const char *ssid)
{
	wchar_t *wssid = NULL;
	size_t len = ssid_to_wcs(ssid, &wssid);

	if (len == (size_t)-1)
		return (-1);

	return (wcswidth(wssid, len));
}

size_t
ssid_extra_width(const char *ssid)
{
	wchar_t *wssid = NULL;
	size_t len = ssid_to_wcs(ssid, &wssid);
	int width = -1;

	if (len == (size_t)-1)
		return (-1);

	if ((width = wcswidth(wssid, len)) == -1)
		return (-1);

	return (width - len);
}

size_t
last_codepoint_pos(const char *s, size_t len)
{
	for (size_t i = len - 1; i != (size_t)-1; i--) {
		if ((s[i] & 0b11000000) != 0b10000000)
			return (i);
	}

	return ((size_t)-1);
}
