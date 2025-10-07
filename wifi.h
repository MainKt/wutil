/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025, Muhammad Saheed <saheed@FreeBSD.org>
 */

#ifndef IEEE80211_H
#define IEEE80211_H

#include <sys/cdefs.h>
#include <sys/queue.h>

#include <net/ethernet.h>

#include "array.h"
#include "wpa_ctrl.h"

#define IEEE80211_NWID_LEN   32

#define WPA_EVENT_ASSOCIATED "Associated with"

#define PSK_MIN		     8
#define PSK_MAX		     63

#define EAP_MIN		     0
#define EAP_MAX		     256

enum security { SEC_OPEN = 0, SEC_EAP, SEC_PSK, SEC_NA };

struct known_network {
	int id, priority;
	bool hidden;
	enum security security;
	enum { KN_ENABLED = 0, KN_DISABLED, KN_CURRENT } state;
	char ssid[IEEE80211_NWID_LEN + 1];
	struct ether_addr bssid;
	TAILQ_ENTRY(known_network) next;
};

ARRAY(known_networks, struct known_network);

ARRAY_APPEND_PROTOTYPE(known_networks)

extern const char *security_to_string[];

struct scan_result {
	int freq, signal;
	struct ether_addr bssid;
	char ssid[IEEE80211_NWID_LEN + 1];
	enum security security;
	TAILQ_ENTRY(scan_result) next;
};

ARRAY(scan_results, struct scan_result);

ARRAY_APPEND_PROTOTYPE(scan_results)

struct supplicant_status {
	int freq;
	char *state;
	char *bssid;
	char *ssid;
	char *ip_address;
	char *security;
};

struct supplicant_status *get_supplicant_status(struct wpa_ctrl *);
void free_supplicant_status(struct supplicant_status *);
int get_bss_freq(struct wpa_ctrl *ctrl, const char *bssid);

const char *wpa_ctrl_default_path(void);
int wpa_ctrl_wait(int wpa_fd, const char *wpa_event, struct timespec *timeout);
struct scan_results *get_scan_results(struct wpa_ctrl *ctrl);
void free_scan_results(struct scan_results *head);
int scan(struct wpa_ctrl *ctrl);
int set_passive_scan(struct wpa_ctrl *ctrl, bool enable);
int scan_and_wait(struct wpa_ctrl *ctrl);
int reconnect(struct wpa_ctrl *ctrl);
int disconnect(struct wpa_ctrl *ctrl);

struct known_networks *get_known_networks(struct wpa_ctrl *ctrl);
void free_known_networks(struct known_networks *nws);
enum security known_network_security(struct wpa_ctrl *ctrl, int nwid);
bool is_hidden_network(struct wpa_ctrl *ctrl, int nwid);
int get_network_priority(struct wpa_ctrl *ctrl, int nwid);
int set_autoconnect(struct wpa_ctrl *ctrl, int nwid, bool enable);
int set_priority(struct wpa_ctrl *ctrl, int nwid, int priority);
int remove_network(struct wpa_ctrl *ctrl, int nwid);

int add_network(struct wpa_ctrl *ctrl, const char *ssid);
int configure_psk(struct wpa_ctrl *ctrl, int, const char *psk);
int configure_eap(struct wpa_ctrl *ctrl, int nwid, const char *identity,
    const char *password);
int configure_ess(struct wpa_ctrl *ctrl, int nwid);
/* use nwid = -1 to select any network */
int select_network(struct wpa_ctrl *ctrl, int nwid);
int update_config(struct wpa_ctrl *ctrl);

int configure_hidden_ssid(struct wpa_ctrl *ctrl, int nwid, const char *identity,
    const char *password);
int configure_ssid(struct wpa_ctrl *ctrl, int nwid, const char *ssid,
    const char *identity, const char *password);

#endif /* !IEEE80211_H */
