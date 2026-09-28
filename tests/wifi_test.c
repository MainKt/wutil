/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026, Muhammad Saheed <saheed@FreeBSD.org>
 */

#include <sys/param.h>

#include <atf-c.h>

#include "../wpa_ctrl.h"
#include "./mock_supplicant.h"

static void mock_supplicant_populate(struct mock_supplicant *);

ATF_TC_WITHOUT_HEAD(mock_supplicant);
ATF_TC_BODY(mock_supplicant, tc)
{
	struct mock_supplicant *ms = mock_supplicant_create();
	struct wpa_ctrl *ctrl = NULL;

	ATF_REQUIRE(ms != NULL);

	mock_supplicant_populate(ms);

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

static void
mock_supplicant_populate(struct mock_supplicant *ms)
{
	struct supplicant_status status = {
		.freq = 2345,
		.state = "COMPLETED",
		.bssid = "c8:5b:76:f0:9f:85",
		.ssid = "shawarma",
		.ip_address = "192.168.1.5",
		.security = "WPA2-PSK",
	};
	struct known_network kns_items[] = {
		{
		    .id = 1,
		    .priority = 10,
		    .security = SEC_PSK,
		    .state = KN_CURRENT,
		    .hidden = true,
		    .ssid = "shawarma",
		    .bssid = { { 0xc8, 0x5b, 0x76, 0xf0, 0x9f, 0x85 } },
		},
	};
	struct known_networks kns = {
		.items = kns_items,
		.len = nitems(kns_items),
	};
	struct scan_result srs_items[] = {
		{
		    .freq = 2345,
		    .signal = -45,
		    .security = SEC_PSK,
		    .ssid = "shawarma",
		    .bssid = { { 0xc8, 0x5b, 0x76, 0xf0, 0x9f, 0x85 } },
		},
	};
	struct scan_results srs = {
		.items = srs_items,
		.len = nitems(srs_items),
	};

	ATF_REQUIRE(ms != NULL);
	ATF_REQUIRE_EQ(mock_supplicant_set_status(ms, &status), true);
	ATF_REQUIRE_EQ(mock_supplicant_set_known_networks(ms, &kns), true);
	ATF_REQUIRE_EQ(mock_supplicant_set_scan_results(ms, &srs), true);
}
