/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025, Muhammad Saheed <saheed@FreeBSD.org>
 *
 * wpa_supplicant/hostapd control interface library
 * Copyright (c) 2004-2017, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 *
 * NOTE: This contains code taken as is or modified from
 * wpa_supplicant's src/common/wpa_ctrl.c
 */

#include <sys/socket.h>
#include <sys/un.h>

#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "wpa_ctrl.h"

struct wpa_ctrl {
	int s;
	char *sock_dir;
	struct sockaddr_un local;
	struct sockaddr_un dest;
};

struct wpa_ctrl *
wpa_ctrl_open(const char *ctrl_path)
{
	return (wpa_ctrl_open2(ctrl_path, NULL));
}

struct wpa_ctrl *
wpa_ctrl_open2(const char *ctrl_path, const char *cli_path)
{
	const int SUNPATHLEN = sizeof(((struct sockaddr_un *)NULL)->sun_path);
	struct wpa_ctrl *ctrl = NULL;

	if (ctrl_path == NULL)
		return (NULL);

	ctrl = calloc(1, sizeof(*ctrl));
	if (ctrl == NULL)
		return (NULL);

	ctrl->s = socket(AF_LOCAL, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
	    0);
	if (ctrl->s == -1)
		goto failure;

	if (asprintf(&ctrl->sock_dir, "%s/wpa_ctrl_XXXXXX",
		cli_path == NULL ? "/tmp" : cli_path) == -1)
		goto failure;

	if (mkdtemp(ctrl->sock_dir) == NULL)
		goto failure;

	ctrl->local.sun_family = AF_UNIX;
	if (snprintf(ctrl->local.sun_path, SUNPATHLEN, "%s/sock",
		ctrl->sock_dir) >= SUNPATHLEN)
		goto failure;

	if (bind(ctrl->s, (struct sockaddr *)&ctrl->local,
		SUN_LEN(&ctrl->local)) == -1)
		goto failure;

	ctrl->dest.sun_family = AF_UNIX;
	if (strlcpy(ctrl->dest.sun_path, ctrl_path, SUNPATHLEN) >= SUNPATHLEN)
		goto failure;

	if (connect(ctrl->s, (struct sockaddr *)&ctrl->dest,
		SUN_LEN(&ctrl->dest)) == -1)
		goto failure;

	return (ctrl);

failure:
	wpa_ctrl_close(ctrl);

	return (NULL);
}

void
wpa_ctrl_close(struct wpa_ctrl *ctrl)
{
	if (ctrl == NULL)
		return;

	close(ctrl->s);

	if (ctrl->local.sun_path[0] != '\0')
		unlink(ctrl->local.sun_path);

	if (ctrl->sock_dir != NULL) {
		rmdir(ctrl->sock_dir);
		free(ctrl->sock_dir);
	}

	free(ctrl);
}

int
wpa_ctrl_request(struct wpa_ctrl *ctrl, const char *cmd, size_t cmd_len,
    char *reply, size_t *reply_len, void (*msg_cb)(char *msg, size_t len))
{
	if (send(ctrl->s, cmd, cmd_len, 0) == -1)
		return (-1);

	for (;;) {
		struct pollfd pfd = { .fd = ctrl->s, .events = POLLIN };
		int nev = poll(&pfd, 1, 1000);
		size_t recv_len = *reply_len;

		if (nev == -1 || nev == 0)
			return (-1);

		if ((pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0)
			return (-1);

		if (wpa_ctrl_recv(ctrl, reply, &recv_len) != 0)
			return (-1);

		/* unsolicited message */
		if ((recv_len > 0 && reply[0] == '<') ||
		    (recv_len > 6 && strncmp(reply, "IFNAME=", 7) == 0)) {
			if (msg_cb != NULL) {
				if (recv_len == *reply_len)
					recv_len = *reply_len - 1;
				reply[recv_len] = '\0';
				msg_cb(reply, recv_len);
			}
			continue;
		}

		*reply_len = recv_len;
		break;
	}

	return (0);
}

static int
wpa_ctrl_attach_helper(struct wpa_ctrl *ctrl, int attach)
{
	const char expected[] = "OK";
	size_t expected_len = sizeof(expected) - 1, len = expected_len;
	char buf[expected_len];
	const char *cmd = attach ? "ATTACH" : "DETACH";
	int ret = wpa_ctrl_request(ctrl, cmd, strlen(cmd), buf, &len, NULL);

	if (ret < 0)
		return (ret);

	if (strncmp(buf, expected, expected_len) == 0)
		return (0);

	return (-1);
}

int
wpa_ctrl_attach(struct wpa_ctrl *ctrl)
{
	return (wpa_ctrl_attach_helper(ctrl, 1));
}

int
wpa_ctrl_detach(struct wpa_ctrl *ctrl)
{
	return (wpa_ctrl_attach_helper(ctrl, 0));
}

int
wpa_ctrl_recv(struct wpa_ctrl *ctrl, char *reply, size_t *reply_len)
{
	ssize_t len = recv(ctrl->s, reply, *reply_len, 0);

	if (len == -1)
		return (-1);
	*reply_len = len;

	return (0);
}

int
wpa_ctrl_pending(struct wpa_ctrl *ctrl)
{
	struct pollfd pfd = { .fd = ctrl->s, .events = POLLIN };
	int ret = poll(&pfd, 1, 0);

	if (ret == -1)
		return (-1);

	if (ret > 0 && pfd.revents & POLLIN)
		return (1);

	return (0);
}

int
wpa_ctrl_get_fd(struct wpa_ctrl *ctrl)
{
	return (ctrl->s);
}
