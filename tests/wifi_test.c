/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026, Muhammad Saheed <saheed@FreeBSD.org>
 */

#include <atf-c.h>

#include "../wpa_ctrl.h"
#include "./mock_supplicant.h"

ATF_TC_WITHOUT_HEAD(mock_supplicant);
ATF_TC_BODY(mock_supplicant, tc)
{
	struct mock_supplicant *ms = mock_supplicant_create();
	struct wpa_ctrl *ctrl = NULL;

	ATF_REQUIRE(ms != NULL);

	ctrl = wpa_ctrl_open_mock(ms);
	ATF_REQUIRE(ctrl != NULL);

	wpa_ctrl_close(ctrl);
	mock_supplicant_destroy(ms);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, mock_supplicant);

	return (atf_no_error());
}
