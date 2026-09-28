/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026, Muhammad Saheed <saheed@FreeBSD.org>
 */

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>

#include <net/if_dl.h>

#include <atf-c.h>
#include <ifaddrs.h>
#include <stdbool.h>
#include <unistd.h>

#include "../interface.h"

static bool in_vnet_jail(void);

ATF_TC_WITHOUT_HEAD(is_wlan_group_null_ifname);
ATF_TC_BODY(is_wlan_group_null_ifname, tc)
{
	struct ifconfig_handle *lifh = ifconfig_open();

	ATF_REQUIRE(lifh != NULL);
	ATF_CHECK(!is_wlan_group(lifh, NULL));

	ifconfig_close(lifh);
}

ATF_TC_WITHOUT_HEAD(is_wlan_group_invalid_ifname);
ATF_TC_BODY(is_wlan_group_invalid_ifname, tc)
{
	struct ifconfig_handle *lifh = ifconfig_open();

	ATF_REQUIRE(lifh != NULL);
	ATF_CHECK(!is_wlan_group(lifh, "NoSuchInterface"));

	ifconfig_close(lifh);
}

ATF_TC(is_wlan_group_not_member);
ATF_TC_HEAD(is_wlan_group_not_member, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "execenv", "jail");
	atf_tc_set_md_var(tc, "execenv.jail.params", "vnet");
}
ATF_TC_BODY(is_wlan_group_not_member, tc)
{
	struct ifconfig_handle *lifh = NULL;

	if (!in_vnet_jail())
		atf_tc_skip("needs a vnet jail, run using kyua");

	lifh = ifconfig_open();
	ATF_REQUIRE(lifh != NULL);
	ATF_CHECK(!is_wlan_group(lifh, "lo0"));

	ifconfig_close(lifh);
}

ATF_TC(is_wlan_group_wlan);
ATF_TC_HEAD(is_wlan_group_wlan, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "execenv", "jail");
	atf_tc_set_md_var(tc, "execenv.jail.params", "vnet");
}
ATF_TC_BODY(is_wlan_group_wlan, tc)
{
	struct ifgroupreq ifgr = {
		.ifgr_name = "lo0",
		.ifgr_group = "wlan",
	};
	int fd = -1;
	struct ifconfig_handle *lifh = NULL;

	if (!in_vnet_jail())
		atf_tc_skip("needs a vnet jail, run using kyua");

	fd = socket(AF_LOCAL, SOCK_DGRAM, 0);
	ATF_REQUIRE(fd != -1);
	ATF_REQUIRE(ioctl(fd, SIOCAIFGROUP, &ifgr) != -1);

	close(fd);

	lifh = ifconfig_open();
	ATF_REQUIRE(lifh != NULL);
	ATF_CHECK(is_wlan_group(lifh, "lo0"));

	ifconfig_close(lifh);
}

ATF_TC_WITHOUT_HEAD(is_ifaddr_af_inet);
ATF_TC_BODY(is_ifaddr_af_inet, tc)
{
	struct {
		struct sockaddr sa;
		bool expected;
	} cases[] = {
		{ { .sa_family = AF_INET }, true },
		{ { .sa_family = AF_INET6 }, true },
		{ { .sa_family = AF_LINK }, false },
	};
	struct ifconfig_handle *lifh = ifconfig_open();

	ATF_REQUIRE(lifh != NULL);
	for (size_t i = 0; i < nitems(cases); i++) {
		struct ifaddrs ifa = { .ifa_addr = &cases[i].sa };
		bool flag = false;

		is_ifaddr_af_inet(lifh, &ifa, &flag);
		ATF_CHECK_EQ(flag, cases[i].expected);
	}

	ifconfig_close(lifh);
}

ATF_TC_WITHOUT_HEAD(get_mac_add);
ATF_TC_BODY(get_mac_add, tc)
{
	struct {
		struct sockaddr_dl sdl;
		uint8_t expected[ETHER_ADDR_LEN];
	} cases[] = {
		{
		    {
			.sdl_family = AF_LINK,
			.sdl_alen = ETHER_ADDR_LEN,
			.sdl_data = { 0xc8, 0x5b, 0x76, 0xf0, 0x9f, 0x85 },
		    },
		    { 0xc8, 0x5b, 0x76, 0xf0, 0x9f, 0x85 },
		},
		{
		    {
			.sdl_family = AF_INET,
			.sdl_alen = ETHER_ADDR_LEN,
			.sdl_data = { 0xc8, 0x5b, 0x76, 0xf0, 0x9f, 0x85 },
		    },
		    { 0 },
		},
		{
		    {
			.sdl_family = AF_LINK,
			.sdl_alen = ETHER_ADDR_LEN - 1,
			.sdl_data = { 0xc8, 0x5b, 0x76, 0xf0, 0x9f, 0x85 },
		    },
		    { 0 },
		},
	};
	struct ifconfig_handle *lifh = ifconfig_open();

	ATF_REQUIRE(lifh != NULL);

	for (size_t i = 0; i < nitems(cases); i++) {
		struct ifaddrs ifa = { .ifa_addr = (void *)&cases[i].sdl };
		struct ether_addr ea = {};

		get_mac_addr(lifh, &ifa, &ea);

		for (size_t j = 0; j < ETHER_ADDR_LEN; j++)
			ATF_CHECK_EQ(ea.octet[j], cases[i].expected[j]);
	}

	ifconfig_close(lifh);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, is_wlan_group_null_ifname);
	ATF_TP_ADD_TC(tp, is_wlan_group_invalid_ifname);
	ATF_TP_ADD_TC(tp, is_wlan_group_not_member);
	ATF_TP_ADD_TC(tp, is_wlan_group_wlan);
	ATF_TP_ADD_TC(tp, is_ifaddr_af_inet);
	ATF_TP_ADD_TC(tp, get_mac_add);

	return (atf_no_error());
}

static bool
in_vnet_jail(void)
{
	int vnet = 0;
	size_t len = sizeof(vnet);

	if (sysctlbyname("security.jail.vnet", &vnet, &len, NULL, 0) != 0)
		return (false);

	return (vnet != 0);
}
