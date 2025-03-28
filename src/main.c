#include "usage.h"
#include "utils.h"

#include <getopt.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

typedef int (*cmd_handler_t)(int argc, char **argv);

struct command_t {
  const char *name;
  cmd_handler_t handler;
};

static int cmd_help(int argc, char **argv) {
  usage(argv[0]);
  return 0;
}

static int cmd_list(int argc, char **argv) {
  if (argc > 2) {
    fprintf(stderr, "bad value %s\n", argv[3]);
    return 1;
  }

  struct network_interface **interfaces = get_network_interfaces();
  printf("%-10s %-12s %-20s\n", "NAME", "STATE", "CONNECTED SSID");
  for (int i = 0; interfaces[i] != NULL; i++) {
    char *ssid = interfaces[i]->connected_ssid;
    ssid = ssid == NULL ? "" : ssid;
    printf("%-10s %-12s %-20s\n", interfaces[i]->name,
           connection_state_to_string[interfaces[i]->state], ssid);
  }

  free_network_interfaces(interfaces);
  return 0;
}

static char *parse_interface_arg(int argc, char **argv) {
  if (argc < 3) {
    fprintf(stderr, "<interface> not provided\n");
    return NULL;
  }

  if (argc > 3) {
    fprintf(stderr, "bad value %s\n", argv[3]);
    return NULL;
  }

  char *interface_name = argv[2];
  if (!is_valid_interface(interface_name)) {
    fprintf(stderr, "unknown interface %s\n", interface_name);
    return NULL;
  }

  return interface_name;
}

static int cmd_show(int argc, char **argv) {
  char *interface_name = parse_interface_arg(argc, argv);
  if (interface_name == NULL)
    return 1;

  struct network_interface *interface =
      get_network_interface_by_name(interface_name);

  char *ssid = interface->connected_ssid;
  ssid = ssid == NULL ? "" : ssid;
  printf("%-10s %-12s %-20s\n", interface_name,
         connection_state_to_string[interface->state], ssid);

  return 0;
}

static int cmd_enable(int argc, char **argv) {
  char *interface_name = parse_interface_arg(argc, argv);
  if (interface_name == NULL)
    return 1;

  return enable_interface(interface_name);
}

static int cmd_disable(int argc, char **argv) {
  char *interface_name = parse_interface_arg(argc, argv);
  if (interface_name == NULL)
    return 1;

  return disable_interface(interface_name);
}

static int cmd_restart(int argc, char **argv) {
  char *interface_name = parse_interface_arg(argc, argv);
  if (interface_name == NULL)
    return 1;

  return restart_interface(interface_name);
}

static int cmd_scan(int argc, char **argv) {
  char *interface_name = parse_interface_arg(argc, argv);
  if (interface_name == NULL)
    return 1;
  struct wifi_network **networks = scan_network_interface(interface_name);
  if (networks == NULL)
    return 1;

  printf("%-20.20s %-9.9s %6s %s\n", "SSID", "SIGNAL", "CHANNEL",
         "CAPABILITIES");
  for (int i = 0; networks[i] != NULL; i++) {
    struct wifi_network *network = networks[i];
    char signal_str[9];
    snprintf(signal_str, sizeof(signal_str), "%d dBm", network->signal_dbm);
    printf("%-20.20s %-9s %6d  %s\n", network->ssid, signal_str,
           network->channel, network->capabilities);
  }

  free_wifi_networks(networks);
  return 0;
}

static int cmd_configure(int argc, char **argv) {
  if (argc < 3) {
    fprintf(stderr, "<interface> not provided\n");
    return 1;
  }

  char *interface_name = argv[2];
  if (!is_valid_interface(interface_name)) {
    fprintf(stderr, "unknown interface %s\n", interface_name);
    return 1;
  }

  struct network_configuration *config =
      generate_network_configuration(argc - 2, argv + 2);
  if (config == NULL) {
    return 1;
  }

  printf("Interface: %s\n", interface_name);
  if (config->method)
    printf("Method: %s\n", config->method);
  if (config->ip)
    printf("IP: %s\n", config->ip);
  if (config->netmask)
    printf("Netmask: %s\n", config->netmask);
  if (config->gateway)
    printf("Gateway: %s\n", config->gateway);
  if (config->dns1)
    printf("DNS1: %s\n", config->dns1);
  if (config->dns2)
    printf("DNS2: %s\n", config->dns2);
  if (config->search_domain)
    printf("Search Domain: %s\n", config->search_domain);

  return 0;
}

static int cmd_disconnect(int argc, char **argv) {
  char *interface_name = parse_interface_arg(argc, argv);
  if (interface_name == NULL)
    return 1;

  struct network_interface *interface =
      get_network_interface_by_name(interface_name);
  if (interface->state != CONNECTED) {
    fprintf(stderr, "%s is not connected\n", interface_name);
    return 1;
  }

  return disconnect_network_interface(interface->name);
}

static void read_password(char *buffer, size_t size, const char *prompt_format,
                          ...) {
  struct termios oldt, newt;

  tcgetattr(STDIN_FILENO, &oldt);
  newt = oldt;

  newt.c_lflag &= ~(ECHO);
  tcsetattr(STDIN_FILENO, TCSANOW, &newt);

  va_list args;
  va_start(args, prompt_format);
  vprintf(prompt_format, args);
  va_end(args);

  if (fgets(buffer, size, stdin) == NULL) {
    perror("error reading password");
    buffer[0] = '\0';
  }

  buffer[strcspn(buffer, "\n")] = '\0';

  tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
  printf("\n");
}

static int cmd_connect(int argc, char **argv) {
  if (argc < 3) {
    fprintf(stderr, "<interface> not provided\n");
    return 1;
  }
  char *interface_name = argv[2];
  struct network_interface *interface =
      get_network_interface_by_name(interface_name);
  if (interface == NULL) {
    fprintf(stderr, "unavailable interface %s\n", interface_name);
    return 1;
  }

  if (argc < 4) {
    fprintf(stderr, "<ssid> not provided\n");
    return 1;
  }

  char *ssid = argv[3];
  struct wifi_network *network = get_wifi_network_by_ssid(interface_name, ssid);
  if (network == NULL) {
    fprintf(stderr, "network '%s' is unavailable on %s\n", ssid,
            interface_name);
    return 1;
  }

  if (!is_ssid_configured(ssid)) {
    char password[256] = "";
    if (argv[4] != NULL)
      strncpy(password, argv[4], sizeof(password) - 1);
    else if (is_wifi_network_secured(network))
      read_password(password, sizeof(password),
                    "enter password for %s: ", ssid);
    password[sizeof(password) - 1] = '\0';

    if (configure_wifi_network(network, password) != 0) {
      printf("failed to configure '%s'\n", ssid);
      free_wifi_network(network);
      return 1;
    }
  }
  free_wifi_network(network);

  int status = connect_to_ssid(interface_name, ssid);
  printf(status == 0 ? "connected to '%s'\n" : "failed to connect to '%s'\n",
         ssid);

  return status;
}

static const struct command_t commands[] = {
    {"help", cmd_help},
    {"list", cmd_list},
    {"show", cmd_show},
    {"enable", cmd_enable},
    {"disable", cmd_disable},
    {"restart", cmd_restart},
    {"scan", cmd_scan},
    {"configure", cmd_configure},
    {"disconnect", cmd_disconnect},
    {"connect", cmd_connect},
    {NULL, NULL},
};

int main(int argc, char **argv) {
  if (argc < 2) {
    usage(argv[0]);
    return 1;
  }

  for (const struct command_t *cmd = commands; cmd->name != NULL; cmd++) {
    if (strcmp(argv[1], cmd->name) == 0)
      return cmd->handler(argc, argv);
  }

  fprintf(stderr, "unsupported command '%s'\n", argv[1]);
  usage(argv[0]);

  return 1;
}
