/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026, Muhammad Saheed <saheed@FreeBSD.org>
 */

#include <sys/param.h>

#include <atf-c.h>
#include <locale.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include "../utils.h"

ATF_TC_WITHOUT_HEAD(unescape);
ATF_TC_BODY(unescape, tc)
{
	struct {
		const char *s;
		const char *expected;
	} cases[] = {
		{ "", "" },
		{ "plain", "plain" },
		{ "a\\tb", "a\tb" },
		{ "\\\\", "\\" },
		{ "\\'\\\"\\?", "'\"?" },
		{ "\\101", "A" },
		{ "\\x41", "A" },
		{ "a\\nb\\\\c", "a\nb\\c" },
		{ "\\", "\\" },
		{ "\\z", "\\z" },
		{ "\\400", "\\400" },
		{ "\\x100", "\\x100" },
	};

	for (size_t i = 0; i < nitems(cases); i++) {
		char buf[64];
		char *unescaped = NULL;

		strlcpy(buf, cases[i].s, sizeof(buf));
		unescaped = unescape(buf, strlen(buf));

		ATF_CHECK_EQ(unescaped, buf);
		ATF_CHECK_STREQ(unescaped, cases[i].expected);
	}
}

ATF_TC_WITHOUT_HEAD(unescape_embedded_nul);
ATF_TC_BODY(unescape_embedded_nul, tc)
{
	char expected[] = { '\0', 'x' };
	char buf[] = "\\0x";
	char *unescaped = unescape(buf, strlen(buf));

	ATF_CHECK_EQ(unescaped, buf);
	ATF_CHECK_EQ(memcmp(unescaped, expected, sizeof(expected)), 0);
	ATF_CHECK_EQ(strlen(unescaped), 0);
}

ATF_TC_WITHOUT_HEAD(last_codepoint_pos);
ATF_TC_BODY(last_codepoint_pos, tc)
{
	struct {
		const char *s;
		size_t expected;
	} cases[] = {
		{ "abc", 2 },
		{ "aé", 1 },
		{ "شاهد", 6 },
		{ "", (size_t)-1 },
		{ "\x80\x80", (size_t)-1 },
	};

	for (size_t i = 0; i < nitems(cases); i++) {
		ATF_CHECK_EQ(last_codepoint_pos(cases[i].s, strlen(cases[i].s)),
		    cases[i].expected);
	}
}

ATF_TC_WITHOUT_HEAD(ssid_to_wcs);
ATF_TC_BODY(ssid_to_wcs, tc)
{
	struct {
		const char *ssid;
		size_t expected;
	} cases[] = {
		{ "", 0 },
		{ "abc", 3 },
		{ "1111111111111111111111111111111", 31 },
		{ "11111111111111111111111111111111", 32 },
		{ "111111111111111111111111111111111", (size_t)-1 },
	};
	wchar_t *w = NULL;

	for (size_t i = 0; i < nitems(cases); i++)
		ATF_CHECK_EQ(ssid_to_wcs(cases[i].ssid, &w), cases[i].expected);

	ATF_REQUIRE_EQ(ssid_to_wcs("ab", &w), 2);
	ATF_REQUIRE(w != NULL);
	ATF_CHECK_EQ(wcscmp(w, L"ab"), 0);
}

ATF_TC_WITHOUT_HEAD(display_width);
ATF_TC_BODY(display_width, tc)
{
	struct {
		const char *ssid;
		size_t expected;
	} cases[] = {
		{ "", 0 },
		{ "abc", 3 },
		{ "1111111111111111111111111111111", 31 },
		{ "11111111111111111111111111111111", 32 },
		{ "111111111111111111111111111111111", (size_t)-1 },
		{ "\x01", (size_t)-1 },
	};

	for (size_t i = 0; i < nitems(cases); i++)
		ATF_CHECK_EQ(display_width(cases[i].ssid), cases[i].expected);
}

ATF_TC_WITHOUT_HEAD(ssid_extra_width);
ATF_TC_BODY(ssid_extra_width, tc)
{
	struct {
		const char *ssid;
		size_t expected;
	} cases[] = {
		{ "", 0 },
		{ "abc", 0 },
		{ "1111111111111111111111111111111", 0 },
		{ "11111111111111111111111111111111", 0 },
		{ "111111111111111111111111111111111", (size_t)-1 },
		{ "\x01", (size_t)-1 },
	};

	for (size_t i = 0; i < nitems(cases); i++) {
		ATF_CHECK_EQ(ssid_extra_width(cases[i].ssid),
		    cases[i].expected);
	}
}

ATF_TC_WITHOUT_HEAD(locale_multibyte);
ATF_TC_BODY(locale_multibyte, tc)
{
	struct {
		const char *ssid;
		size_t chars;
		size_t width;
		size_t extra;
	} cases[] = {
		{ "", 0, 0, 0 },
		{ "شاهد", 4, 4, 0 },
		{ "intrest面白いing", 13, 16, 3 },
		{ "面白い", 3, 6, 3 },
		{ "\xff", (size_t)-1, (size_t)-1, (size_t)-1 },
	};

	if (setlocale(LC_CTYPE, "C.UTF-8") == NULL)
		atf_tc_skip("C.UTF-8 locale is not available");

	if (MB_CUR_MAX == 1)
		atf_tc_skip("not a multibyte locale");

	for (size_t i = 0; i < nitems(cases); i++) {
		wchar_t *w = NULL;

		ATF_CHECK_EQ(ssid_to_wcs(cases[i].ssid, &w), cases[i].chars);
		ATF_CHECK_EQ(display_width(cases[i].ssid), cases[i].width);
		ATF_CHECK_EQ(ssid_extra_width(cases[i].ssid), cases[i].extra);
	}
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, unescape);
	ATF_TP_ADD_TC(tp, unescape_embedded_nul);
	ATF_TP_ADD_TC(tp, last_codepoint_pos);
	ATF_TP_ADD_TC(tp, ssid_to_wcs);
	ATF_TP_ADD_TC(tp, display_width);
	ATF_TP_ADD_TC(tp, ssid_extra_width);
	ATF_TP_ADD_TC(tp, locale_multibyte);

	return (atf_no_error());
}
