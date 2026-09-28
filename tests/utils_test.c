/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026, Muhammad Saheed <saheed@FreeBSD.org>
 */

#include <sys/param.h>

#include <atf-c.h>
#include <locale.h>
#include <stdlib.h>

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

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, unescape);
	ATF_TP_ADD_TC(tp, unescape_embedded_nul);
	ATF_TP_ADD_TC(tp, last_codepoint_pos);

	return (atf_no_error());
}
