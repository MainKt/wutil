/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025, Muhammad Saheed <saheed@FreeBSD.org>
 */

#include <sys/socket.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <libifconfig.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include "ctl_seq.h"
#include "ieee80211.h"
#include "utils.h"

static int fetch_size(void);
static void render(void);
static void render_network_interfaces(void);
static void render_networks(void);
static void handle_sig_winch(int);
static void handle_up(void);
static void handle_down(void);
static void print_centeredf(const char *, ...);

static const size_t CONTENT_WIDTH = 80;

static int tty;
static size_t selected_nic = 0, selected_network = 0;
static struct winsize ws = { 0 };

enum section {
	NETWORK_INTERFACES = 0,
	NETWORKS = 1,
};
static enum section current_section = NETWORK_INTERFACES;

static struct network_interface_list *interfaces = NULL;
static struct wifi_network_list *networks = NULL;
static size_t interfaces_count = 0, networks_count = 0;

int
main(void)
{
	int rt_sockfd;
	struct termios cooked, raw;
	int return_status = 0;
	struct wifi_network *network;
	struct network_interface *interface;
	struct ifconfig_handle *lifh = ifconfig_open();

	if (lifh == NULL)
		errx(1, "failed to open libifconfig handle");

	interfaces = get_interfaces(lifh);
	ifconfig_close(lifh);

	if (interfaces == NULL)
		errx(1, "failed to get network interfaces");

	rt_sockfd = socket(PF_ROUTE, SOCK_RAW, 0);
	if (rt_sockfd == -1) {
		perror("socket(PF_ROUTE)");
		return (1);
	}

	STAILQ_FOREACH(interface, interfaces, next) {
		if (strstr(interface->name, "wlan") != NULL) {
			scan_and_wait_ioctl(rt_sockfd, interface->name);
			networks = get_scan_results_ioctl(rt_sockfd,
			    interface->name);

			if (networks == NULL)
				errx(1, "failed to get networks on %s",
				    interface->name);

			break;
		}
		interfaces_count++;
	}
	close(rt_sockfd);

	STAILQ_FOREACH(network, networks, next)
		networks_count++;

	tty = open("/dev/tty", O_RDWR);

	tcgetattr(tty, &cooked);
	raw = cooked;

	raw.c_lflag &= ~(ECHO | ICANON | ISIG | IEXTEN);
	raw.c_iflag &= ~(IXON | ICRNL | BRKINT | INPCK | ISTRIP);
	raw.c_cflag |= CS8;

	raw.c_cc[VTIME] = 0;
	raw.c_cc[VMIN] = 1;

	tcsetattr(tty, TCSAFLUSH, &raw);
	dprintf(tty, "%s%s%s", ALT_BUFFER_ON, CURSOR_HIDE, CLEAR_SCREEN);

	struct sigaction sa = { 0 };
	sa.sa_handler = handle_sig_winch;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGWINCH, &sa, NULL);

	struct pollfd fds[1];
	fds[0].fd = tty;
	fds[0].events = POLLIN;

	for (;;) {
		char buffer[1];
		int ready;

		fetch_size();
		render();

		ready = poll(fds, 1, -1);

		if (ready <= 0 && errno != EINTR) {
			warnx("polling failed");
			return_status = 1;
			break;
		}

		read(tty, buffer, sizeof(buffer));
		if (buffer[0] == 'q')
			break;
		else if (buffer[0] == '\x1B') {
			int esc_read;
			char esc_buffer[8];

			raw.c_cc[VTIME] = 1;
			raw.c_cc[VMIN] = 0;
			tcsetattr(tty, TCSANOW, &raw);

			esc_read = read(tty, esc_buffer, sizeof(esc_buffer));

			raw.c_cc[VTIME] = 0;
			raw.c_cc[VMIN] = 1;
			tcsetattr(tty, TCSANOW, &raw);

			if (strncmp(esc_buffer, "[A", esc_read) == 0)
				handle_up();
			else if (strncmp(esc_buffer, "[B", esc_read) == 0)
				handle_down();
		} else if (buffer[0] == 'k') {
			handle_up();
		} else if (buffer[0] == 'j') {
			handle_down();
		} else if (buffer[0] == '\t') {
			current_section = !current_section;
		}
	}

	tcsetattr(tty, TCSAFLUSH, &cooked);
	dprintf(tty, "%s%s", ALT_BUFFER_OFF, CURSOR_SHOW);

	close(tty);

	free_wifi_network_list(networks);
	free_network_interface_list(interfaces);

	return (return_status);
}

static int
fetch_size(void)
{
	if (ioctl(tty, TIOCGWINSZ, &ws) == 0)
		return (1);
	return (0);
}

static void
handle_sig_winch(int signo)
{
	(void)signo;
	fetch_size();
	render();
}

void
render(void)
{
	int interfaces_section_height = 1 + interfaces_count + 1;
	int networks_section_height = 1 + networks_count + 1;
	int instructions_height = 2;
	int total_height = interfaces_section_height + networks_section_height +
	    instructions_height;
	int v_pad = (ws.ws_row - total_height) / 2;

	dprintf(tty, "%s%s", CLEAR_SCREEN, CURSOR_HOME);

	if (ws.ws_col < CONTENT_WIDTH || ws.ws_row < total_height) {
		print_centeredf("Terminal is too small.");
		return;
	}

	for (int i = 0; i < v_pad; i++)
		dprintf(tty, "\n");

	render_network_interfaces();
	dprintf(tty, "\n");
	render_networks();

	print_centeredf("%sPress Tab to switch sections,"
			" Up/Down or j/k to navigate and"
			" q to quit%s",
	    BOLD, RESET);
}

static void
handle_up(void)
{
	if (current_section == NETWORK_INTERFACES && selected_nic != 0)
		selected_nic -= 1;
	if (current_section == NETWORKS && selected_network != 0)
		selected_network -= 1;
}

static void
handle_down(void)
{
	if (current_section == NETWORK_INTERFACES &&
	    selected_nic != interfaces_count - 1)
		selected_nic += 1;
	if (current_section == NETWORKS &&
	    selected_network != networks_count - 1)
		selected_network += 1;
}

static void
print_centeredf(const char *fmt, ...)
{
	char buffer[512];
	int padding;
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buffer, sizeof(buffer), fmt, ap);
	va_end(ap);

	padding = (ws.ws_col - strlen(buffer)) / 2;
	if (padding < 0)
		padding = 0;

	dprintf(tty, "%*s%s", padding, "", buffer);
}

static void
render_network_interfaces(void)
{
	int h_pad = (ws.ws_col - CONTENT_WIDTH) / 2;
	size_t i = 0;
	struct network_interface *interface;

	if (h_pad < 0)
		h_pad = 0;

	dprintf(tty, "%*s%s%s%sINTERFACES%s%s\n", h_pad, "",
	    current_section == NETWORK_INTERFACES ? FG_GREEN : FG_WHITE, BOLD,
	    UNDERLINE, NO_UNDERLINE, RESET);
	dprintf(tty, "\n");

	dprintf(tty, "%*s%s%-20s%-20s%-20s%s\n", h_pad, "", FG_YELLOW, "Name",
	    "State", "Connected SSID", RESET);

	STAILQ_FOREACH(interface, interfaces, next) {
		const char *state, *ssid = interface->connected_ssid;

		dprintf(tty, "%*s", h_pad, "");
		if (i == selected_nic && current_section == NETWORK_INTERFACES)
			dprintf(tty, "%s%s", BG_GRAY, BOLD);

		state = connection_state_to_string[interface->state];

		ssid = ssid != NULL ? ssid : "-";
		dprintf(tty, "%-20s%-20s%-20s%s\n", interface->name, state,
		    ssid, RESET);
	}
	dprintf(tty, "\n");
}

static void
render_networks(void)
{
	int h_pad = (ws.ws_col - CONTENT_WIDTH) / 2;
	struct wifi_network *network;
	size_t i = 0;

	if (h_pad < 0)
		h_pad = 0;

	dprintf(tty, "%*s%s%s%sNETWORKS%s%s\n", h_pad, "",
	    current_section == NETWORKS ? FG_GREEN : FG_WHITE, BOLD, UNDERLINE,
	    NO_UNDERLINE, RESET);
	dprintf(tty, "\n");

	dprintf(tty, "%*s%s%-20s%-20s%-20s%-15s%s\n", h_pad, "", FG_YELLOW,
	    "SSID", "Channel", "Signal (dBm)", "Noise (dBm)", RESET);

	STAILQ_FOREACH(network, networks, next) {
		dprintf(tty, "%*s", h_pad, "");
		if (i == selected_network && current_section == NETWORKS)
			dprintf(tty, "%s%s", BG_GRAY, BOLD);

		dprintf(tty, "%-20s%-20d%-20d%-15d%s\n", network->ssid,
		    network->channel, network->signal_dbm, network->noise_dbm,
		    RESET);
		i++;
	}
	dprintf(tty, "\n");
}
