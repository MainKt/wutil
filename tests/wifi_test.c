/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026, Muhammad Saheed <saheed@FreeBSD.org>
 */

#include <atf-c.h>

#include "./mock_supplicant.h"

ATF_TC_WITHOUT_HEAD(mock_supplicant);
ATF_TC_BODY(mock_supplicant, tc)
{
	struct mock_supplicant *ms = mock_supplicant_create();
	ATF_REQUIRE(ms != NULL);

	mock_supplicant_destroy(ms);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, mock_supplicant);

	return (atf_no_error());
}
