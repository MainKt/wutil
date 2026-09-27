/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025, Muhammad Saheed <saheed@FreeBSD.org>
 */

#include <sys/param.h>
#include <sys/pciio.h>

#include <net/if.h>
#include <net/if_dl.h>

#include <arpa/inet.h>
#include <err.h>
#include <getopt.h>
#include <ifaddrs.h>
#include <libifconfig.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include "interface.h"
#include "usage.h"
#include "utils.h"
#include "wifi.h"
#include "wpa_ctrl.h"

typedef int (*cmd_handler_f)(int argc, char *argv[], void *udata);

struct command {
	const char *name;
	cmd_handler_f handler;
};

static int cmd_interfaces(int argc, char *argv[], void *udata);
static int cmd_interface(int argc, char *argv[], void *udata);

static int cmd_known_networks(int argc, char *argv[], void *udata);
static int cmd_known_network(int argc, char *argv[], void *udata);
static int cmd_forget(int argc, char *argv[], void *udata);
static int cmd_set(int argc, char *argv[], void *udata);

static int cmd_scan(int argc, char *argv[], void *udata);
static int cmd_networks(int argc, char *argv[], void *udata);
static int cmd_status(int argc, char *argv[], void *udata);
static int cmd_disconnect(int argc, char *argv[], void *udata);
static int cmd_connect(int argc, char *argv[], void *udata);

static void list_interface(struct ifconfig_handle *lifh, struct ifaddrs *ifa,
    void *udata);
static void show_interface(struct ifconfig_handle *lifh, struct ifaddrs *ifa,
    void *udata);
static void print_ifaddr(ifconfig_handle_t *lifh, struct ifaddrs *ifa,
    void *udata __unused);

static struct command commands[] = {
	{ "interfaces", cmd_interfaces },
	{ "interface", cmd_interface },

	{ "known-networks", cmd_known_networks },
	{ "known-network", cmd_known_network },
	{ "forget", cmd_forget },
	{ "set", cmd_set },

	{ "scan", cmd_scan },
	{ "networks", cmd_networks },
	{ "status", cmd_status },
	{ "disconnect", cmd_disconnect },
	{ "connect", cmd_connect },
};

int
main(int argc, char *argv[])
{
	int ret = 0, opt = -1;
	struct command *cmd = NULL;
	const char *ctrl_path = NULL;
	struct wpa_ctrl *ctrl = NULL;
	struct option opts[] = {
		{ "ctrl-interface", required_argument, NULL, 'c' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 },
	};

	if (setlocale(LC_ALL, "") == NULL)
		err(EXIT_FAILURE, "setlocale");

	ctrl_path = wpa_ctrl_default_path();
	while ((opt = getopt_long(argc, argv, "+c:h", opts, NULL)) != -1) {
		switch (opt) {
		case 'c':
			ctrl_path = optarg;
			break;
		case 'h':
			usage(stdout);
			exit(EXIT_SUCCESS);
		case '?':
		default:
			usage(stderr);
			exit(EXIT_FAILURE);
		}
	}

	argc -= optind;
	argv += optind;

	optreset = 1;
	optind = 1;

	if (ctrl_path == NULL) {
		warn(
		    "no wpa ctrl interface on default path, provide --ctrl-interface");
		return (1);
	}

	if ((ctrl = wpa_ctrl_open(ctrl_path)) == NULL) {
		warn("failed to open wpa_supplicant control interface, %s",
		    ctrl_path);
		return (1);
	}

	if (argc == 0) {
		usage(stderr);
		exit(EXIT_FAILURE);
	}

	for (size_t i = 0; i < nitems(commands); i++) {
		if (strcmp(*argv, commands[i].name) == 0) {
			cmd = &commands[i];
			break;
		}
	}

	if (cmd == NULL) {
		warnx("Unknown command: %s", argv[0]);
		usage(stderr);
		return (EXIT_FAILURE);
	}

	ret = cmd->handler(argc, argv, ctrl);

	wpa_ctrl_close(ctrl);

	return (ret);
}

static int
cmd_interfaces(int argc, char *argv[], void *udata)
{
	struct ifconfig_handle *lifh = NULL;
	int ret = 0;

	(void)udata;

	if (argc > 2) {
		warnx("bad value %s", argv[2]);
		return (1);
	}

	if ((lifh = ifconfig_open()) == NULL) {
		warnx("failed to open libifconfig handle");
		return (1);
	}

	printf("%-*s %-17s %-4s %-*s %-12s\n", IFNAMSIZ, "Interface", "MAC",
	    "State", PCI_MAXNAMELEN, "Device", "Connection");
	if (ifconfig_foreach_iface(lifh, list_interface, NULL) != 0) {
		warnx("failed to get network interfaces");
		ret = 1;
		goto cleanup;
	}

cleanup:
	ifconfig_close(lifh);

	return (ret);
}

static int
cmd_interface(int argc, char *argv[], void *udata)
{
	int ret = 0;
	struct ifconfig_handle *lifh = NULL;
	const char *ifname = NULL;

	(void)udata;

	if (argc < 2) {
		warnx("<interface> not provided");
		return (1);
	}
	ifname = argv[1];

	if (if_nametoindex(ifname) == 0) { /* returns 0 if invalid i.e false */
		warnx("unknown interface %s", ifname);
		return (1);
	}

	if (argc > 2) {
		warnx("bad value %s", argv[2]);
		return (1);
	}

	if ((lifh = ifconfig_open()) == NULL) {
		warnx("failed to open libifconfig handle");
		return (1);
	}

	if (!is_wlan_group(lifh, ifname)) {
		warnx("invalid interface %s", ifname);
		ret = 1;
		goto cleanup;
	}

	if (ifconfig_foreach_iface(lifh, show_interface, &ifname) != 0) {
		warnx("failed to get network interfaces");
		ret = 1;
		goto cleanup;
	}

cleanup:
	ifconfig_close(lifh);

	return (ret);
}

static int
cmd_known_networks(int argc, char *argv[], void *udata)
{
	struct wpa_ctrl *ctrl = udata;
	struct known_networks *nws = get_known_networks(ctrl);

	if (argc > 1) {
		warnx("bad value %s", argv[1]);
		return (1);
	}

	if (nws == NULL) {
		warnx("failed to retrieve known networks");
		return (1);
	}

	sort_known_networks(nws);

	printf("  %-*s %-8s %-6s %-8s\n", IEEE80211_NWID_LEN, "SSID",
	    "Security", "Hidden", "Priority");
	for (size_t i = 0; i < nws->len; i++) {
		struct known_network *nw = &nws->items[i];
		const size_t ssid_width = display_width(nw->ssid);

		printf("%c %s%*s %-8s %-6s %8d\n",
		    nw->state == KN_CURRENT ? '>' : ' ', nw->ssid,
		    MAX(IEEE80211_NWID_LEN - (int)ssid_width, 0), "",
		    security_to_string[nw->security], nw->hidden ? "Yes" : "",
		    nw->priority);
	}

	free_known_networks(nws);

	return (0);
}

static int
cmd_known_network(int argc, char *argv[], void *udata)
{
	struct wpa_ctrl *ctrl = udata;
	struct known_network *nw = NULL;
	struct known_networks *nws = NULL;
	const char *ssid;

	if (argc < 2) {
		warnx("<network> not provided");
		return (1);
	}
	ssid = argv[1];

	if (argc > 2) {
		warnx("bad value %s", argv[2]);
		return (1);
	}

	if ((nws = get_known_networks(ctrl)) == NULL) {
		warnx("failed to retrieve known networks");
		return (1);
	}

	for (size_t i = 0; i < nws->len; i++) {
		if (strcmp(nws->items[i].ssid, ssid) == 0) {
			nw = &nws->items[i];
			break;
		}
	}

	if (nw == NULL) {
		warnx("unknown network %s", ssid);
		free_known_networks(nws);
		return (1);
	}

	printf("%12s: %s\n", "Network SSID", nw->ssid);
	printf("%12s: %s\n", "Security", security_to_string[nw->security]);
	printf("%12s: %s\n", "Hidden", nw->hidden ? "Yes" : "No");
	printf("%12s: %d\n", "Priority", nw->priority);
	printf("%12s: %s\n", "Autoconnect",
	    nw->state == KN_CURRENT	? "Current" :
		nw->state == KN_ENABLED ? "Yes" :
					  "No");

	free_known_networks(nws);

	return (0);
}

static int
cmd_forget(int argc, char *argv[], void *udata)
{
	struct wpa_ctrl *ctrl = udata;
	struct known_network *nw = NULL;
	struct known_networks *nws = NULL;
	const char *ssid;

	if (argc < 2) {
		warnx("<network> not provided");
		return (1);
	}
	ssid = argv[1];

	if (argc > 2) {
		warnx("bad value %s", argv[2]);
		return (1);
	}

	if ((nws = get_known_networks(ctrl)) == NULL) {
		warnx("failed to retrieve known networks");
		return (1);
	}

	for (size_t i = 0; i < nws->len; i++) {
		if (strcmp(nws->items[i].ssid, ssid) == 0) {
			nw = &nws->items[i];
			break;
		}
	}

	if (nw == NULL) {
		warnx("unknown network %s", ssid);
		free_known_networks(nws);
		return (1);
	}

	if (remove_network(ctrl, nw->id) != 0) {
		warnx("failed to forget network %s", ssid);
		free_known_networks(nws);
		return (1);
	}

	free_known_networks(nws);

	return (0);
}

static int
cmd_set(int argc, char *argv[], void *udata)
{
	int ret = 0, opt = -1;
	int priority = 0;
	bool change_priority = false;
	enum { UNCHANGED, YES, NO } autoconnect = UNCHANGED;
	char *endptr;
	const char *ssid;
	struct wpa_ctrl *ctrl = udata;
	struct known_network *nw = NULL;
	struct known_networks *nws = NULL;
	struct option opts[] = {
		{ "priority", required_argument, NULL, 'p' },
		{ "autoconnect", required_argument, NULL, 'a' },
		{ NULL, 0, NULL, 0 },
	};

	while ((opt = getopt_long(argc, argv, "p:a:", opts, NULL)) != -1) {
		switch (opt) {
		case 'a':
			if (strcmp(optarg, "y") == 0 ||
			    strcmp(optarg, "yes") == 0) {
				autoconnect = YES;
			} else if (strcmp(optarg, "n") == 0 ||
			    strcmp(optarg, "no") == 0) {
				autoconnect = NO;
			} else {
				warnx("invalid value '%s' for --autoconnect",
				    optarg);
				return (1);
			}
			break;
		case 'p':
			priority = strtol(optarg, &endptr, 10);
			if (*endptr != '\0') {
				warnx("invalid value '%s' for --priority",
				    optarg);
				return (-1);
			}
			change_priority = true;
			break;
		case '?':
		default:
			return (1);
		}
	}

	if (optind == 1) {
		warnx("no options were provided");
		return (1);
	}

	argc -= optind;
	argv += optind;

	if (argc < 1) {
		warnx("<network> not provided");
		return (1);
	}
	ssid = argv[0];

	if (argc > 1) {
		warnx("bad value %s", argv[1]);
		return (1);
	}

	if ((nws = get_known_networks(ctrl)) == NULL) {
		warnx("failed to retrieve known networks");
		return (1);
	}

	for (size_t i = 0; i < nws->len; i++) {
		if (strcmp(nws->items[i].ssid, ssid) == 0) {
			nw = &nws->items[i];
			break;
		}
	}

	if (nw == NULL) {
		warnx("unknown network %s", ssid);
		ret = 1;
		goto cleanup;
	}

	if (autoconnect != UNCHANGED &&
	    set_autoconnect(ctrl, nw->id, autoconnect == YES) != 0) {
		warnx("failed to set priority");
		ret = 1;
		goto cleanup;
	}

	if (change_priority && set_priority(ctrl, nw->id, priority) != 0) {
		warnx("failed to set priority");
		ret = 1;
		goto cleanup;
	}

	if (update_config(ctrl) != 0) {
		warnx("failed to update config");
		ret = 1;
	}

cleanup:
	free_known_networks(nws);

	return (ret);
}

static int
cmd_scan(int argc, char *argv[], void *udata)
{
	struct wpa_ctrl *ctrl = udata;

	if (argc > 1) {
		warnx("bad value %s", argv[1]);
		return (1);
	}

	set_passive_scan(ctrl, true);
	if (scan_and_wait(ctrl) != 0) {
		warnx("scan failed");
		set_passive_scan(ctrl, false);
		return (1);
	}
	set_passive_scan(ctrl, false);

	return (0);
}

static int
cmd_networks(int argc, char *argv[], void *udata)
{
	struct wpa_ctrl *ctrl = udata;
	struct scan_results *srs = NULL;

	if (argc > 1) {
		warnx("bad value %s", argv[1]);
		return (1);
	}

	if ((srs = get_scan_results(ctrl)) == NULL) {
		warnx("failed to retrieve scan results");
		return (1);
	}
	sort_scan_results(srs);

	printf("%-*s %-8s %-9s %-8s\n", IEEE80211_NWID_LEN, "SSID", "Signal",
	    "Frequency", "Security");
	for (size_t i = 0; i < srs->len; i++) {
		struct scan_result *sr = &srs->items[i];
		const size_t ssid_width = display_width(sr->ssid);

		printf("%s%*s %-4d dBm %-5d MHz %-8s\n", sr->ssid,
		    MAX(IEEE80211_NWID_LEN - (int)ssid_width, 0), "",
		    sr->signal, sr->freq, security_to_string[sr->security]);
	}

	free_scan_results(srs);

	return (0);
}

static int
cmd_status(int argc, char *argv[], void *udata)
{
	struct wpa_ctrl *ctrl = udata;
	struct supplicant_status *status = NULL;

	if (argc > 1) {
		warnx("bad value %s", argv[1]);
		return (1);
	}

	if ((status = get_supplicant_status(ctrl)) == NULL) {
		warnx("failed to retrieve wpa_supplicant status");
		return (1);
	}

	printf("%15s: %s\n", "WPA State", status->state);
	if (status->ssid != NULL)
		printf("%15s: %s\n", "Connected SSID", status->ssid);
	if (status->bssid != NULL) {
		printf("%15s: %s\n", "Connected BSSID", status->bssid);
		printf("%15s: %d MHz\n", "Frequency", status->freq);
	}
	if (status->ssid != NULL && status->ip_address != NULL)
		printf("%15s: %s\n", "IP Address", status->ip_address);
	if (status->security != NULL)
		printf("%15s: %s\n", "Security", status->security);

	free_supplicant_status(status);

	return (0);
}

static int
cmd_disconnect(int argc, char *argv[], void *udata)
{
	struct wpa_ctrl *ctrl = udata;
	if (argc > 1) {
		warnx("bad value %s", argv[1]);
		return (1);
	}

	if (disconnect(ctrl) != 0) {
		warnx("failed to disconnect");
		return (1);
	}

	return (0);
}

static int
cmd_connect(int argc, char *argv[], void *udata)
{
	int ret = 0, nwid = -1, opt = -1, freq = 0;
	struct known_networks *nws = NULL;
	char *endptr;
	const char *ssid;
	const char *identity = NULL, *password = NULL;
	bool hidden = false;
	struct wpa_ctrl *ctrl = udata;
	struct option options[] = {
		{ "identity", required_argument, NULL, 'i' },
		{ "password", required_argument, NULL, 'p' },
		{ "hidden", no_argument, NULL, 'h' },
		{ "frequency", required_argument, NULL, 'f' },
		{ NULL, 0, NULL, 0 },
	};

	while (
	    (opt = getopt_long(argc, argv, "i:p:hf:", options, NULL)) != -1) {
		switch (opt) {
		case 'i':
			identity = optarg;
			break;
		case 'p':
			password = optarg;
			break;
		case 'h':
			hidden = true;
			break;
		case 'f':
			freq = strtol(optarg, &endptr, 10);
			if (*endptr != '\0') {
				warnx("invalid value '%s' for --frequency",
				    optarg);
				return (-1);
			}
			break;
		case '?':
			break;
		default:
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 1) {
		warnx("<ssid> not provided");
		return (1);
	}
	ssid = argv[0];

	if (argc == 2 && password == NULL) {
		password = argv[1];
	} else if (argc >= 2) {
		warnx("bad value %s", argv[password != NULL ? 1 : 2]);
		return (1);
	}

	if ((nws = get_known_networks(ctrl)) == NULL) {
		warnx("failed to retrieve known networks");
		return (1);
	}

	for (size_t i = 0; i < nws->len; i++) {
		if (strcmp(nws->items[i].ssid, ssid) == 0) {
			nwid = nws->items[i].id;
			break;
		}
	}

	if (nwid == -1) {
		int config_ret;

		if ((nwid = add_network(ctrl, ssid)) == -1) {
			warnx("failed to create new network");
			ret = 1;
			goto exit;
		}

		config_ret = hidden ?
		    configure_hidden_ssid(ctrl, nwid, identity, password) :
		    configure_ssid(ctrl, nwid, ssid, identity, password);

		if (config_ret != 0) {
			warnx("failed to configure network: %s", ssid);
			remove_network(ctrl, nwid);
			ret = 1;
			goto exit;
		}
	}

	if (select_network(ctrl, nwid, freq) != 0) {
		warnx("failed to select network: %s", ssid);
		ret = 1;
		goto exit;
	}

	for (size_t i = 0; i < nws->len; i++) {
		struct known_network *nw = &nws->items[i];

		if (nw->id == nwid)
			continue;

		set_autoconnect(ctrl, nw->id, nw->state == KN_ENABLED);
	}

	if (update_config(ctrl) != 0) {
		warnx("failed to update wpa_supplicant config");
		ret = 1;
		goto exit;
	}

exit:
	free_known_networks(nws);
	return (ret);
}

static void
list_interface(struct ifconfig_handle *lifh, struct ifaddrs *ifa, void *udata)
{
	enum connection_state status;
	const char *state = (ifa->ifa_flags & IFF_UP) ? "Up" : "Down";
	char device[PCI_MAXNAMELEN + 1];
	char mac[18];
	struct ether_addr ea = { 0 };
	struct ifgroupreq ifgr;

	(void)udata;

	if (!is_wlan_group(lifh, ifa->ifa_name))
		return;

	status = get_connection_state(lifh, ifa);

	if (get_iface_parent(ifa->ifa_name, strlen(ifa->ifa_name), device,
		sizeof(device)) != 0)
		device[0] = '\0';

	if (ifconfig_get_groups(lifh, ifa->ifa_name, &ifgr) == -1)
		return;

	ifconfig_foreach_ifaddr(lifh, ifa, get_mac_addr, &ea);

	if (ether_ntoa_r(&ea, mac) == NULL)
		strcpy(mac, "N/A");

	printf("%-*s %-17s %-5s %-*s %-12s\n", IFNAMSIZ, ifa->ifa_name, mac,
	    state, PCI_MAXNAMELEN, device, connection_state_to_string[status]);
}

static void
show_interface(struct ifconfig_handle *lifh, struct ifaddrs *ifa, void *udata)
{
	char device[PCI_MAXNAMELEN + 1];
	const char **ifname = udata;
	const char *state = (ifa->ifa_flags & IFF_UP) ? "Up" : "Down";

	if (ifname == NULL || strcmp(*ifname, ifa->ifa_name) != 0)
		return;

	if (get_iface_parent(ifa->ifa_name, strlen(ifa->ifa_name), device,
		sizeof(device)) != 0)
		device[0] = '\0';

	printf("%9s: %s\n", "Interface", ifa->ifa_name);
	printf("%9s: %s\n", "State", state);
	printf("%9s: %s\n", "Device", device);
	ifconfig_foreach_ifaddr(lifh, ifa, print_ifaddr, NULL);
}

static void
print_ifaddr(ifconfig_handle_t *lifh, struct ifaddrs *ifa, void *udata __unused)
{
	struct ether_addr ea = { 0 };
	struct ifconfig_inet_addr inet;
	struct ifconfig_inet6_addr inet6;
	char addr_buf[INET6_ADDRSTRLEN];

	switch (ifa->ifa_addr->sa_family) {
	case AF_INET: {
		if (ifconfig_inet_get_addrinfo(lifh, ifa->ifa_name, ifa,
			&inet) != 0)
			return;

		if (inet_ntop(AF_INET, &inet.sin->sin_addr, addr_buf,
			sizeof(addr_buf)) == NULL)
			return;
		printf("%9s: %s/%d\n", "inet", addr_buf, inet.prefixlen);

		break;
	}
	case AF_INET6: {
		if (ifconfig_inet6_get_addrinfo(lifh, ifa->ifa_name, ifa,
			&inet6) != 0)
			return;

		if (inet_ntop(AF_INET6, &inet6.sin6->sin6_addr, addr_buf,
			sizeof(addr_buf)) == NULL)
			return;
		printf("%9s: %s/%d\n", "inet6", addr_buf, inet6.prefixlen);

		break;
	}
	case AF_LINK: {
		struct sockaddr_dl *sdl = (void *)ifa->ifa_addr;

		if (sdl->sdl_family != AF_LINK ||
		    sdl->sdl_alen != ETHER_ADDR_LEN)
			return;

		memcpy(&ea, LLADDR(sdl), ETHER_ADDR_LEN);

		if (ether_ntoa_r(&ea, addr_buf) == NULL)
			strcpy(addr_buf, "N/A");
		printf("%9s: %s\n", "MAC", addr_buf);

		break;
	}
	default:
		break;
	}
}
