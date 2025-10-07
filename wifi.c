/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025, Muhammad Saheed <saheed@FreeBSD.org>
 */

#include <sys/param.h>

#include <net/ethernet.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/ether.h>

#include <bsd/readpassphrase.h>
#include <bsd/stdlib.h>
#include <bsd/sys/queue.h>
#include <dirent.h>
#include <err.h>
#include <getopt.h>
#include <kqueue/sys/event.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "utils.h"
#include "wifi.h"
#include "wpa_ctrl.h"

static int wpa_ctrl_requestf(struct wpa_ctrl *ctrl, char *reply,
    size_t *reply_len, const char *fmt, ...);
static int wpa_ctrl_ack_request(struct wpa_ctrl *ctrl, char *reply,
    size_t *reply_len, const char *fmt, ...);
static int known_networks_cmp(const void *a, const void *b);
static int scan_result_cmp_signal(const void *a, const void *b);

#define WPA_MAX_REPLY_SIZE   4096
#define WPA_BIN_REPLY_SIZE   2	/* sizeof("0") or sizeof("1") */
#define WPA_ACK_REPLY_SIZE   4	/* sizeof("FAIL") for OK or FAIL reply */
#define WPA_INT32_REPLY_SIZE 13 /* snprintf(NULL, 0, "%d\n", INT32_MIN) + 1 */

const char *security_to_string[] = {
	[SEC_OPEN] = "Open",
	[SEC_EAP] = "EAP",
	[SEC_PSK] = "PSK",
	[SEC_NA] = "N/A",
};

ARRAY_APPEND_DEFINITION(known_networks)

ARRAY_APPEND_DEFINITION(scan_results)

int
wpa_ctrl_wait(int wpa_fd, const char *wpa_event, struct timespec *timeout)
{
	char buf[4096];
	struct kevent event;
	int kq = kqueue();
	int ret = 0;

	if (kq == -1) {
		warn("kqueue() failed");
		return (1);
	}

	EV_SET(&event, wpa_fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
	if (kevent(kq, &event, 1, NULL, 0, NULL) == -1) {
		warn("kevent register");
		close(kq);
		return (1);
	}

	for (;;) {
		struct kevent tevent;
		int len;

		ret = kevent(kq, NULL, 0, &tevent, 1, timeout);
		if (ret == -1) {
			warn("kevent wait");
			break;
		} else if (ret == 0) {
			warnx("timeout waiting for %s", wpa_event);
			ret = 1;
			break;
		}

		if (tevent.flags & EV_ERROR) {
			warnx("kevent error: %s", strerror(tevent.data));
			ret = 1;
			break;
		}

		len = recv(wpa_fd, buf, sizeof(buf) - 1, 0);
		if (len == -1) {
			warn("recv(wpa_fd)");
			ret = 1;
			break;
		} else if (len == 0) {
			warnx("wpa ctrl_interface socket closed");
			ret = 1;
			break;
		}

		buf[len] = '\0';
		if (strstr(buf, wpa_event) != NULL) {
			ret = 0;
			break;
		}
	}

	close(kq);
	return (ret);
}

int
scan(struct wpa_ctrl *ctrl)
{
	char reply[WPA_ACK_REPLY_SIZE];
	size_t reply_len = sizeof(reply) - 1;

	if (wpa_ctrl_ack_request(ctrl, reply, &reply_len, "SCAN") != 0) {
		warnx("failed to initiate scan");
		return (1);
	}

	return (0);
}

int
set_passive_scan(struct wpa_ctrl *ctrl, bool enable)
{
	char reply[WPA_ACK_REPLY_SIZE];
	size_t reply_len = sizeof(reply) - 1;

	if (wpa_ctrl_ack_request(ctrl, reply, &reply_len, "SET passive_scan %d",
		enable) != 0) {
		warnx("(wpa_ctrl) failed to set passive_scan=%d", enable);
		return (1);
	}

	return (0);
}

int
scan_and_wait(struct wpa_ctrl *ctrl)
{
	int wpa_fd = wpa_ctrl_get_fd(ctrl);
	int ret = 0;
	struct timespec timeout = { .tv_sec = 5, .tv_nsec = 0 };

	if (scan(ctrl) != 0) {
		warnx("failed to initiate scan");
		return (1);
	}

	if (wpa_fd == -1) {
		warnx("invalid wpa_ctrl socket");
		return (1);
	}

	if (wpa_ctrl_attach(ctrl) != 0) {
		warnx("failed to register to wpa_ctrl event monitor");
		return (1);
	}

	ret = wpa_ctrl_wait(wpa_fd, WPA_EVENT_SCAN_RESULTS, &timeout);

	wpa_ctrl_detach(ctrl);

	return (ret);
}

const char *
wpa_ctrl_default_path(void)
{
	static char path[128];
	char *ret = NULL;
	const char *run_dir = "/var/run/wpa_supplicant";
	DIR *dirp = opendir(run_dir);

	if (dirp == NULL)
		return (NULL);

	for (struct dirent *entry = readdir(dirp); entry != NULL;
	    entry = readdir(dirp)) {
		if (entry->d_type == DT_SOCK) {
			snprintf(path, sizeof(path), "%s/%s", run_dir,
			    entry->d_name);
			ret = path;
			break;
		}
	}

	closedir(dirp);

	return (ret);
}

int
add_network(struct wpa_ctrl *ctrl, const char *ssid)
{
	char reply[WPA_INT32_REPLY_SIZE];
	size_t reply_len = sizeof(reply) - 1;
	int nwid = -1;
	char *nl;
	const char *errstr;

	if (wpa_ctrl_request(ctrl, "ADD_NETWORK", sizeof("ADD_NETWORK") - 1,
		reply, &reply_len, NULL) != 0)
		return (-1);

	reply[reply_len] = '\0';
	nl = strchr(reply, '\n');
	if (nl != NULL)
		*nl = '\0';
	nwid = strtonum(reply, 0, INT_MAX, &errstr);

	if (errstr != NULL) {
		warnx("(wpa_ctrl) failed to add network");
		return (-1);
	}

	if (wpa_ctrl_ack_request(ctrl, reply, &reply_len,
		"SET_NETWORK %d ssid \"%s\"", nwid, ssid) != 0) {
		warnx("(wpa_ctrl) failed to set ssid(%s) on network id(%d)",
		    ssid, nwid);
		return (-1);
	}

	return (nwid);
}

int
select_network(struct wpa_ctrl *ctrl, int nwid)
{
	char reply[WPA_ACK_REPLY_SIZE];
	size_t reply_len = sizeof(reply) - 1;
	char req[32] = "SELECT_NETWORK any";

	if (nwid != -1)
		snprintf(req, sizeof(req), "SELECT_NETWORK %d", nwid);

	if (wpa_ctrl_request(ctrl, req, strlen(req), reply, &reply_len, NULL) !=
	    0)
		return (1);

	reply[reply_len] = '\0';

	return (strncmp(reply, "OK", sizeof("OK") - 1) != 0);
}

struct known_networks *
get_known_networks(struct wpa_ctrl *ctrl)
{
	char reply[WPA_MAX_REPLY_SIZE];
	size_t reply_len = sizeof(reply) - 1;
	struct known_networks *nws = NULL;

	if (wpa_ctrl_request(ctrl, "LIST_NETWORKS", strlen("LIST_NETWORKS"),
		reply, &reply_len, NULL) != 0)
		return (NULL);
	reply[reply_len] = '\0';

	nws = malloc(sizeof(*nws));
	if (nws == NULL) {
		warn("malloc");
		return (NULL);
	}
	*nws = ARRAY_INITIALIZER(known_networks);

	for (char *brkn,
	    *line = (strtok_r(reply, "\n", &brkn), strtok_r(NULL, "\n", &brkn));
	    line != NULL; line = strtok_r(NULL, "\n", &brkn)) {
		char *brkt;
		/* network id / ssid / bssid / flags */
		char *id_str = strtok_r(line, "\t", &brkt);
		int id = id_str != NULL ? strtol(id_str, NULL, 10) : -1;
		char *ssid = strtok_r(NULL, "\t", &brkt);
		char *bssid = strtok_r(NULL, "\t", &brkt);
		char *flags = strtok_r(NULL, "\t", &brkt);
		struct known_network nw = { 0 };

		nw.id = id;
		nw.priority = get_network_priority(ctrl, nw.id);
		nw.hidden = is_hidden_network(ctrl, nw.id);
		nw.security = known_network_security(ctrl, nw.id);

		if (ssid != NULL) {
			ssid = unescape(ssid, strlen(ssid));
			strlcpy(nw.ssid, ssid, sizeof(nw.ssid));
		}

		if (bssid != NULL && ether_aton_r(bssid, &nw.bssid) == NULL)
			nw.bssid = (struct ether_addr) { 0 };

		nw.state = KN_ENABLED;

		if (flags != NULL) {
			if (strstr(flags, "CURRENT") != NULL)
				nw.state = KN_CURRENT;
			else if (strstr(flags, "DISABLED") != NULL)
				nw.state = KN_DISABLED;
		}

		if (!ARRAY_APPEND(known_networks, nws, nw)) {
			warn("reallocarray");
			free_known_networks(nws);
			return (NULL);
		}
	}

	if (nws->len != 0) {
		qsort(nws->items, nws->len, sizeof(nws->items[0]),
		    known_networks_cmp);
	}

	return (nws);
}

static int
known_networks_cmp(const void *a, const void *b)
{
	const struct known_network *kn_a = a, *kn_b = b;
	return ((kn_b->priority > kn_a->priority) -
	    (kn_b->priority < kn_a->priority));
}

void
free_known_networks(struct known_networks *nws)
{
	if (nws == NULL)
		return;

	ARRAY_FREE(nws);
	free(nws);
}

struct scan_results *
get_scan_results(struct wpa_ctrl *ctrl)
{
	char reply[WPA_MAX_REPLY_SIZE];
	size_t reply_len = sizeof(reply) - 1;
	struct scan_results *srs = NULL;

	if (wpa_ctrl_request(ctrl, "SCAN_RESULTS", strlen("SCAN_RESULTS"),
		reply, &reply_len, NULL) != 0)
		return (NULL);
	reply[reply_len] = '\0';

	srs = malloc(sizeof(*srs));
	if (srs == NULL) {
		warn("malloc");
		return (NULL);
	}
	*srs = ARRAY_INITIALIZER(scan_results);

	for (char *brkn,
	    *line = (strtok_r(reply, "\n", &brkn), strtok_r(NULL, "\n", &brkn));
	    line != NULL; line = strtok_r(NULL, "\n", &brkn)) {
		char *brkt;
		/* bssid / frequency / signal level / flags / ssid */
		char *bssid = strtok_r(line, "\t", &brkt);
		char *freq_str = strtok_r(NULL, "\t", &brkt);
		int freq = freq_str != NULL ? strtol(freq_str, NULL, 10) : 0;
		char *signal_str = strtok_r(NULL, "\t", &brkt);
		int signal = signal_str != NULL ? strtol(signal_str, NULL, 10) :
						  0;
		char *flags = strtok_r(NULL, "\t", &brkt);
		char *ssid = strtok_r(NULL, "\t", &brkt);
		struct scan_result sr = { 0 };

		sr.freq = freq;
		sr.signal = signal;

		if (ssid != NULL) {
			ssid = unescape(ssid, strlen(ssid));
			if (ssid[0] == '\0') /* hidden network */
				continue;
			strlcpy(sr.ssid, ssid, sizeof(sr.ssid));
		}

		if (bssid != NULL && ether_aton_r(bssid, &sr.bssid) == NULL)
			sr.bssid = (struct ether_addr) { 0 };

		if (flags != NULL) {
			sr.security = strstr(flags, "PSK") != NULL ? SEC_PSK :
			    strstr(flags, "EAP") != NULL	   ? SEC_EAP :
								     SEC_OPEN;
		}

		if (!ARRAY_APPEND(scan_results, srs, sr)) {
			warn("reallocarray");
			free_scan_results(srs);
			return (NULL);
		}
	}

	if (srs->len != 0) {
		qsort(srs->items, srs->len, sizeof(srs->items[0]),
		    scan_result_cmp_signal);
	}

	return (srs);
}

static int
scan_result_cmp_signal(const void *a, const void *b)
{
	const struct scan_result *sr_a = a, *sr_b = b;

	return ((sr_b->signal > sr_a->signal) - (sr_b->signal < sr_a->signal));
}

void
free_scan_results(struct scan_results *srs)
{
	if (srs == NULL)
		return;

	ARRAY_FREE(srs);
	free(srs);
}

int
configure_psk(struct wpa_ctrl *ctrl, int nwid, const char *psk)
{
	char reply[WPA_ACK_REPLY_SIZE];
	size_t reply_len = sizeof(reply) - 1;

	return (wpa_ctrl_ack_request(ctrl, reply, &reply_len,
	    "SET_NETWORK %d psk \"%s\"", nwid, psk));
}

int
configure_eap(struct wpa_ctrl *ctrl, int nwid, const char *identity,
    const char *password)
{
	char reply[WPA_ACK_REPLY_SIZE];
	size_t reply_len = sizeof(reply) - 1;

	if (wpa_ctrl_ack_request(ctrl, reply, &reply_len,
		"SET_NETWORK %d password \"%s\"", nwid, password) != 0)
		return (1);

	reply_len = sizeof(reply) - 1;
	if (wpa_ctrl_ack_request(ctrl, reply, &reply_len,
		"SET_NETWORK %d identity \"%s\"", nwid, identity) != 0)
		return (1);

	reply_len = sizeof(reply) - 1;
	if (wpa_ctrl_ack_request(ctrl, reply, &reply_len,
		"SET_NETWORK %d key_mgmt WPA-EAP", nwid) != 0)
		return (1);

	return (0);
}

int
configure_ess(struct wpa_ctrl *ctrl, int nwid)
{
	char reply[WPA_ACK_REPLY_SIZE];
	size_t reply_len = sizeof(reply) - 1;

	return (wpa_ctrl_ack_request(ctrl, reply, &reply_len,
	    "SET_NETWORK %d key_mgmt NONE", nwid));
}

int
update_config(struct wpa_ctrl *ctrl)
{
	char reply[WPA_ACK_REPLY_SIZE];
	size_t reply_len = sizeof(reply) - 1;

	if (wpa_ctrl_ack_request(ctrl, reply, &reply_len,
		"SET update_config 1") != 0) {
		warnx("(wpa_ctrl) failed to set update_config=1");
		return (1);
	}

	reply_len = sizeof(reply) - 1;
	if (wpa_ctrl_ack_request(ctrl, reply, &reply_len, "SAVE_CONFIG") != 0) {
		warnx("(wpa_ctrl) failed to save config");
		return (1);
	}

	return (0);
}

int
reconnect(struct wpa_ctrl *ctrl)
{
	char reply[WPA_ACK_REPLY_SIZE];
	size_t reply_len = sizeof(reply) - 1;

	return (wpa_ctrl_ack_request(ctrl, reply, &reply_len, "RECONNECT"));
}

int
disconnect(struct wpa_ctrl *ctrl)
{
	char reply[WPA_ACK_REPLY_SIZE];
	size_t reply_len = sizeof(reply) - 1;

	return (wpa_ctrl_ack_request(ctrl, reply, &reply_len, "DISCONNECT"));
}

int
configure_ssid(struct wpa_ctrl *ctrl, int nwid, const char *ssid,
    const char *identity, const char *password)
{
	struct scan_results *srs = NULL;
	struct scan_result *sr = NULL;
	char identity_buf[EAP_MAX], password_buf[EAP_MAX];
	int ret = 0;

	if (scan_and_wait(ctrl) != 0) {
		warnx("scan failed");
		ret = 1;
		goto cleanup;
	}

	if ((srs = get_scan_results(ctrl)) == NULL) {
		warnx("failed to retrieve scan results");
		ret = 1;
		goto cleanup;
	}

	for (size_t i = 0; i < srs->len; i++) {
		if (strcmp(srs->items[i].ssid, ssid) == 0) {
			sr = &srs->items[i];
			break;
		}
	}

	if (sr == NULL) {
		warnx("SSID unavailable");
		ret = 1;
		goto cleanup;
	}

	if (sr->security == SEC_PSK) {
		int psk_len;

		if (password == NULL &&
		    (password = readpassphrase("network password: ",
			 password_buf, sizeof(password_buf),
			 RPP_REQUIRE_TTY)) == NULL) {
			warn("failed to read password");
			goto cleanup;
		}

		psk_len = strlen(password);
		if (psk_len < PSK_MIN || psk_len > PSK_MAX) {
			warnx("password must be %d–%d characters", PSK_MIN,
			    PSK_MAX);
			goto cleanup;
		}

		ret = configure_psk(ctrl, nwid, password);
	} else if (sr->security == SEC_EAP) {
		if (identity == NULL) {
			printf("network EAP identity: ");
			if (fgets(identity_buf, sizeof(identity_buf), stdin) ==
			    NULL) {
				warnx("failed to read identity");
				goto cleanup;
			}
			identity_buf[strcspn(identity_buf, "\n")] = '\0';
			identity = identity_buf;
		}

		if (password == NULL &&
		    (password = readpassphrase("network EAP password: ",
			 password_buf, sizeof(password_buf),
			 RPP_REQUIRE_TTY)) == NULL) {
			warn("failed to read password");
			goto cleanup;
		}

		ret = configure_eap(ctrl, nwid, identity, password);
	} else {
		ret = configure_ess(ctrl, nwid);
	}

	if (ret != 0) {
		warnx("failed to configure key_mgmt");
		goto cleanup;
	}

cleanup:
	free_scan_results(srs);

	return (ret);
}

int
configure_hidden_ssid(struct wpa_ctrl *ctrl, int nwid, const char *identity,
    const char *password)
{
	char reply[WPA_ACK_REPLY_SIZE];
	size_t reply_len = sizeof(reply) - 1;
	int ret = 0;

	if (wpa_ctrl_ack_request(ctrl, reply, &reply_len,
		"SET_NETWORK %d scan_ssid 1", nwid) != 0)
		return (1);

	if (identity != NULL) {
		char password_buf[EAP_MAX];

		if (password == NULL &&
		    (password = readpassphrase("network EAP password: ",
			 password_buf, sizeof(password_buf),
			 RPP_REQUIRE_TTY)) == NULL) {
			warn("failed to read password");
			return (1);
		}

		ret = configure_eap(ctrl, nwid, identity, password);
	} else if (password != NULL) {
		ret = configure_psk(ctrl, nwid, password);
	} else {
		ret = configure_ess(ctrl, nwid);
	}

	return (ret);
}

int
get_bss_freq(struct wpa_ctrl *ctrl, const char *bssid)
{
	char reply[sizeof("freq=") + WPA_INT32_REPLY_SIZE];
	size_t reply_len = sizeof(reply) - 1;
	int freq = 0;

	if (wpa_ctrl_requestf(ctrl, reply, &reply_len, "BSS %s MASK=%x", bssid,
		WPA_BSS_MASK_FREQ) != 0) {
		warnx("failed to fetch frequency for %s", bssid);
		return (0);
	}

	if (sscanf(reply, "freq=%d", &freq) != 1)
		return (0);

	return (freq);
}

struct supplicant_status *
get_supplicant_status(struct wpa_ctrl *ctrl)
{
	char reply[WPA_MAX_REPLY_SIZE];
	size_t reply_len = sizeof(reply) - 1;
	struct supplicant_status *status;

	if (wpa_ctrl_request(ctrl, "STATUS", strlen("STATUS"), reply,
		&reply_len, NULL) != 0) {
		warnx("failed to request wpa_supplicant status");
		return (NULL);
	}
	reply[reply_len] = '\0';

	if ((status = calloc(1, sizeof(*status))) == NULL)
		return (NULL);

	for (char *brkn, *line = strtok_r(reply, "\n", &brkn); line != NULL;
	    line = strtok_r(NULL, "\n", &brkn)) {
		char *brkt;
		/* key=value */
		char *key = strtok_r(line, "=", &brkt);
		char *value = strtok_r(NULL, "=", &brkt);
		char **status_key = strcmp(key, "bssid") == 0 ? &status->bssid :
		    strcmp(key, "ssid") == 0		      ? &status->ssid :
		    strcmp(key, "ip_address") == 0 ? &status->ip_address :
		    strcmp(key, "wpa_state") == 0  ? &status->state :
		    strcmp(key, "key_mgmt") == 0   ? &status->security :
						     NULL;

		if (status_key != NULL &&
		    (*status_key = strdup(value)) == NULL) {
			free_supplicant_status(status);
			return (NULL);
		}
	}

	status->freq = 0;
	if (status->bssid != NULL)
		status->freq = get_bss_freq(ctrl, status->bssid);

	if (status->ssid != NULL)
		status->ssid = unescape(status->ssid, strlen(status->ssid));

	return (status);
}

void
free_supplicant_status(struct supplicant_status *status)
{
	if (status == NULL)
		return;

	free(status->state);
	free(status->bssid);
	free(status->ssid);
	free(status->ip_address);
	free(status->security);
	free(status);
}

static int
wpa_ctrl_requestf(struct wpa_ctrl *ctrl, char *reply, size_t *reply_len,
    const char *fmt, ...)
{
	char req[128];
	va_list ap;

	va_start(ap, fmt);
	if ((size_t)vsnprintf(req, sizeof(req), fmt, ap) >= sizeof(req)) {
		va_end(ap);
		warnx("wpa_ctrl request too long: %s", req);
		return (1);
	}
	va_end(ap);

	if (wpa_ctrl_request(ctrl, req, strlen(req), reply, reply_len, NULL) !=
	    0)
		return (1);
	reply[*reply_len] = '\0';

	return (0);
}

static int
wpa_ctrl_ack_request(struct wpa_ctrl *ctrl, char *reply, size_t *reply_len,
    const char *fmt, ...)
{
	char req[128];
	va_list ap;

	va_start(ap, fmt);
	if ((size_t)vsnprintf(req, sizeof(req), fmt, ap) >= sizeof(req)) {
		va_end(ap);
		warnx("wpa_ctrl request too long: %s", req);
		return (1);
	}
	va_end(ap);

	if (wpa_ctrl_request(ctrl, req, strlen(req), reply, reply_len, NULL) !=
	    0)
		return (1);
	reply[*reply_len] = '\0';

	if (strncmp(reply, "OK", 2) != 0) {
		warnx("wpa_ctrl request failed: %s", req);
		return (1);
	}

	return (0);
}

enum security
known_network_security(struct wpa_ctrl *ctrl, int nwid)
{
	char reply[WPA_MAX_REPLY_SIZE];
	size_t reply_len = sizeof(reply) - 1;

	if (wpa_ctrl_requestf(ctrl, reply, &reply_len,
		"GET_NETWORK %d key_mgmt", nwid) != 0)
		return (SEC_NA);

	return (strstr(reply, "PSK") != NULL  ? SEC_PSK :
		strstr(reply, "EAP") != NULL  ? SEC_EAP :
		strstr(reply, "NONE") != NULL ? SEC_OPEN :
						SEC_NA);
}

bool
is_hidden_network(struct wpa_ctrl *ctrl, int nwid)
{
	char reply[WPA_BIN_REPLY_SIZE];
	size_t reply_len = sizeof(reply) - 1;

	if (wpa_ctrl_requestf(ctrl, reply, &reply_len,
		"GET_NETWORK %d scan_ssid", nwid) != 0)
		return (false);

	return (reply[0] == '1');
}

int
get_network_priority(struct wpa_ctrl *ctrl, int nwid)
{
	int priority;
	char *endptr;
	char reply[WPA_INT32_REPLY_SIZE];
	size_t reply_len = sizeof(reply) - 1;

	if (wpa_ctrl_requestf(ctrl, reply, &reply_len,
		"GET_NETWORK %d priority", nwid) != 0)
		return (SEC_NA);

	priority = strtol(reply, &endptr, 10);

	if (*endptr != '\0')
		return (-1);

	return (priority);
}

int
remove_network(struct wpa_ctrl *ctrl, int nwid)
{
	char reply[WPA_ACK_REPLY_SIZE];
	size_t reply_len = sizeof(reply) - 1;

	if (wpa_ctrl_ack_request(ctrl, reply, &reply_len, "REMOVE_NETWORK %d",
		nwid) != 0)
		return (1);

	return (0);
}

int
set_autoconnect(struct wpa_ctrl *ctrl, int nwid, bool enable)
{
	char reply[WPA_ACK_REPLY_SIZE];
	size_t reply_len = sizeof(reply) - 1;

	return (wpa_ctrl_ack_request(ctrl, reply, &reply_len, "%s_NETWORK %d",
	    enable ? "ENABLE" : "DISABLE", nwid));
}

int
set_priority(struct wpa_ctrl *ctrl, int nwid, int priority)
{
	char reply[WPA_ACK_REPLY_SIZE];
	size_t reply_len = sizeof(reply) - 1;

	return (wpa_ctrl_ack_request(ctrl, reply, &reply_len,
	    "SET_NETWORK %d priority %d", nwid, priority));
}
