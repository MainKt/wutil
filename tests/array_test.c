/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026, Muhammad Saheed <saheed@FreeBSD.org>
 */

#include <atf-c.h>

ATF_TC_WITHOUT_HEAD(hello);
ATF_TC_BODY(hello, tc)
{
	ATF_CHECK(true);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, hello);

	return (atf_no_error());
}
