#include "utils.h"
#include "string_utils.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

const char *connection_state_to_string[] = {
    [CONNECTED] = "Connected",
    [DISCONNECTED] = "Disconnected",
    [UNPLUGGED] = "Unplugged",
};

enum connection_state get_interface_connection_state(char *interface_name) {
  char command[256];
  snprintf(command, sizeof(command), "ifconfig %s", interface_name);
  FILE *fp = popen(command, "r");
  if (fp == NULL) {
    perror("popen failed");
    exit(1);
  }

  char **lines = file_read_lines(fp);
  pclose(fp);
  if (lines == NULL)
    exit(1);

  char *output = lines_to_string(lines);
  free_string_array(lines);
  if (lines == NULL)
    exit(1);

  enum connection_state state = strstr(output, "inet ") ? CONNECTED
                                : strstr(output, "status: active")
                                    ? DISCONNECTED
                                    : UNPLUGGED;
  free(output);
  return state;
}

struct network_interface *get_network_interface_by_name(char *interface_name) {
  if (interface_name == NULL)
    return NULL;

  struct network_interface **interfaces = get_network_interfaces();
  int count = 0;
  while (interfaces[count] != NULL)
    count++;

  struct network_interface *interface = NULL;
  for (int i = 0; interfaces[i] != NULL; i++) {
    if (strcmp(interfaces[i]->name, interface_name) == 0) {
      interface = interfaces[i];
      interfaces[i] = interfaces[count - 1];
      interfaces[count - 1] = NULL;
      break;
    }
  }

  free_network_interfaces(interfaces);
  return interface;
}

char **get_network_interface_names() {
  FILE *fp = popen("ifconfig -l", "r");
  if (fp == NULL) {
    perror("popen `ifconfig -l` failed");
    return NULL;
  }

  char buffer[256];
  if (fgets(buffer, sizeof(buffer), fp) == 0) {
    pclose(fp);
    return NULL;
  }
  pclose(fp);

  buffer[strcspn(buffer, "\n")] = '\0';
  char **interface_names = split_string(buffer, " ");
  if (interface_names == NULL)
    return NULL;

  const char pattern[] =
      "(enc|lo|fwe|fwip|tap|plip|pfsync|pflog|ipfw|tun|sl|faith|ppp|bridge|wg)"
      "[0-9]+([[:space:]]*)|vm-[a-z]+([[:space:]]*)";
  if (remove_matching_strings(interface_names, pattern) != 0) {
    free_string_array(interface_names);
    return NULL;
  }

  return interface_names;
}

char *retrieve_network_interface_connected_ssid(char *interface_name) {
  char command[256];
  snprintf(command, sizeof(command), "ifconfig %s", interface_name);
  FILE *fp = popen(command, "r");
  if (fp == NULL) {
    perror("popen failed");
    return NULL;
  }

  char **lines = file_read_lines(fp);
  pclose(fp);
  if (lines == NULL)
    return NULL;

  char *ssid = NULL;
  for (int i = 0; lines[i] != NULL; i++) {
    char *ssid_index = strstr(lines[i], "ssid ");
    if (ssid_index != NULL) {
      char *ssid_start = ssid_index + strlen("ssid ");
      char *ssid_end = strstr(lines[i], " channel");
      ssid = strndup(ssid_start, ssid_end - ssid_start);
      break;
    }
  }
  free_string_array(lines);
  return ssid;
}

struct network_interface **get_network_interfaces() {
  char **interface_names = get_network_interface_names();

  int interfaces_count = 0;
  while (interface_names[interfaces_count] != NULL)
    interfaces_count++;

  struct network_interface **interfaces =
      calloc(sizeof(struct network_interface *), interfaces_count + 1);
  for (int i = 0; interface_names[i] != NULL; i++) {
    interfaces[i] = malloc(sizeof(struct network_interface));
    interfaces[i]->name = interface_names[i];
    interfaces[i]->connected_ssid =
        retrieve_network_interface_connected_ssid(interfaces[i]->name);
    interfaces[i]->state = get_interface_connection_state(interfaces[i]->name);
  }
  interfaces[interfaces_count] = NULL;
  free(interface_names);

  return interfaces;
}

void free_network_interface(struct network_interface *interface) {
  free(interface->name);
  free(interface->connected_ssid);
  free(interface);
}

void free_network_interfaces(struct network_interface **interfaces) {
  for (int i = 0; interfaces[i] != NULL; i++) {
    free_network_interface(interfaces[i]);
  }
  free(interfaces);
}

static void guard_root_access() {
  if (geteuid() != 0) {
    fprintf(stderr, "insufficient permissions\n");
    exit(EXIT_FAILURE);
  }
}

int enable_interface(char *interface_name) {
  guard_root_access();

  char command[256];
  snprintf(command, sizeof(command), "ifconfig %s up", interface_name);
  return system(command);
}

int disable_interface(char *interface_name) {
  guard_root_access();

  char command[256];
  snprintf(command, sizeof(command), "ifconfig %s down", interface_name);
  return system(command);
}

int restart_interface(char *interface_name) {
  guard_root_access();

  char command[256];
  snprintf(command, sizeof(command),
           "service netif restart %s > /dev/null 2>&1", interface_name);
  return system(command);
}

bool is_valid_interface(char *interface_name) {
  char **interface_names = get_network_interface_names();
  bool is_valid = string_array_contains(interface_names, interface_name);
  free_string_array(interface_names);
  return is_valid;
}

static struct wifi_network *extract_wifi_network(char *network_info) {
  char ssid[256], bssid[18], channel[5], date_rate[5], sn[8],
      beacon_interval[4], capabilities[256];
  if (sscanf(network_info, "%255s %17s %4s %4s %7s %3s %[^\n]", ssid, bssid,
             channel, date_rate, sn, beacon_interval, capabilities) != 7)
    return NULL;
  int signal, noise;
  if (sscanf(sn, "%d:%d", &signal, &noise) != 2)
    return NULL;

  struct wifi_network *network = malloc(sizeof(struct wifi_network));
  if (network == NULL)
    return NULL;

  network->ssid = strdup(ssid);
  if (network->ssid == NULL) {
    free(network);
    return NULL;
  }

  network->bssid = strdup(bssid);
  if (network->bssid == NULL) {
    free(network->ssid);
    free(network);
    return NULL;
  }

  network->channel = atoi(channel);
  network->data_rate = atoi(date_rate);
  network->signal_dbm = signal;
  network->noise_dbm = noise;
  network->beacon_interval = atoi(beacon_interval);

  network->capabilities = strdup(capabilities);
  if (network->capabilities == NULL) {
    free(network->bssid);
    free(network->ssid);
    free(network);
    return NULL;
  }

  return network;
}

void free_wifi_network(struct wifi_network *network) {
  if (network == NULL)
    return;
  free(network->capabilities);
  free(network->bssid);
  free(network->ssid);
  free(network);
}

void free_wifi_networks(struct wifi_network **networks) {
  for (int i = 0; networks[i] != NULL; i++)
    free_wifi_network(networks[i]);
  free(networks);
}

struct wifi_network **scan_network_interface(char *interface_name) {
  char command[256];
  snprintf(command, sizeof(command), "ifconfig %s scan", interface_name);
  FILE *fp = popen(command, "r");
  if (fp == NULL) {
    perror("popen failed");
    return NULL;
  }

  char **lines = file_read_lines(fp);
  pclose(fp);
  if (lines == NULL)
    return NULL;
  int line_count = string_array_length(lines);
  if (line_count == 0) {
    free_string_array(lines);
    return NULL;
  }

  char *output = lines_to_string(lines);
  if (strstr(output, "unable to get scan results"))
    return NULL;

  struct wifi_network **wifi_networks =
      calloc(line_count, sizeof(struct wifi_network **));
  for (int i = 1; lines[i] != NULL; i++) {
    wifi_networks[i - 1] = extract_wifi_network(lines[i]);
    if (wifi_networks[i - 1] == NULL) {
      free_wifi_networks(wifi_networks);
      return NULL;
    }
  }
  wifi_networks[line_count - 1] = NULL;

  free(output);
  free_string_array(lines);
  return wifi_networks;
}

struct wifi_network *get_wifi_network_by_ssid(char *network_interface,
                                              char *ssid) {
  if (ssid == NULL)
    return NULL;

  struct wifi_network **networks = scan_network_interface(network_interface);
  if (networks == NULL)
    return NULL;

  int count = 0;
  while (networks[count] != NULL)
    count++;

  struct wifi_network *network = NULL;
  for (int i = 0; networks[i] != NULL; i++) {
    if (strcmp(networks[i]->ssid, ssid) == 0) {
      network = networks[i];
      networks[i] = networks[count - 1];
      networks[count - 1] = NULL;
      break;
    }
  }

  free_wifi_networks(networks);
  return network;
}

int disconnect_network_interface(char *interface_name) {
  guard_root_access();

  char command[256];
  snprintf(command, sizeof(command), "ifconfig %s down", interface_name);
  if (system(command) != 0) {
    fprintf(stderr, "failed to bring %s down\n", interface_name);
    return 1;
  }

  snprintf(command, sizeof(command), "ifconfig %s ssid 'none'", interface_name);
  if (system(command) != 0) {
    fprintf(stderr, "failed to clear SSID on %s\n", interface_name);
    return 1;
  }

  snprintf(command, sizeof(command), "ifconfig %s up", interface_name);
  if (system(command) != 0) {
    fprintf(stderr, "failed to bring %s up\n", interface_name);
    return 1;
  }

  return 0;
}

int connect_to_ssid(char *network_interface, char *ssid) {
  guard_root_access();

  if (system("killall wpa_supplicant > /dev/null 2>&1") != 0)
    return 1;

  char command[256];
  snprintf(command, sizeof(command), "ifconfig %s ssid '%s' > /dev/null 2>&1",
           network_interface, ssid);
  if (system(command) != 0)
    return 1;

  snprintf(
      command, sizeof(command),
      "wpa_supplicant -B -i %s -c /etc/wpa_supplicant.conf > /dev/null 2>&1",
      network_interface);
  return system(command);
}

bool is_ssid_configured(char *ssid) {
  FILE *conf_file = fopen("/etc/wpa_supplicant.conf", "r");
  if (conf_file == NULL)
    return false;
  char **conf_lines = file_read_lines(conf_file);
  char *wpa_supplicant_conf = lines_to_string(conf_lines);
  free_string_array(conf_lines);

  bool is_configured = strstr(wpa_supplicant_conf, ssid);

  free(wpa_supplicant_conf);
  return is_configured;
}

int configure_wifi_network(struct wifi_network *network, char *password) {
  guard_root_access();

  if (password == NULL)
    password = "";

  char security[256];
  if (strstr(network->capabilities, "RSN")) {
    snprintf(security, sizeof(security),
             "\n key_mgmt=WPA-PSK"
             "\n proto=RSN"
             "\n psk=\"%s\"",
             password);
  } else if (strstr(network->capabilities, "WPA")) {
    snprintf(security, sizeof(security),
             "\n key_mgmt=WPA-PSK"
             "\n proto=WPA"
             "\n psk=\"%s\"",
             password);
  } else {
    snprintf(security, sizeof(security),
             "\n key_mgmt=NONE"
             "\n wep_tx_keyidx=0"
             "\n wep_key0=%s",
             password);
  }

  FILE *conf_file = fopen("/etc/wpa_supplicant.conf", "a");
  if (conf_file == NULL) {
    perror("failed to open /etc/wpa_supplicant.conf");
    return 1;
  }

  fprintf(conf_file,
          "\nnetwork={"
          "\n ssid=\"%s\""
          "%s"
          "\n}"
          "\n",
          network->ssid, security);

  fclose(conf_file);
  return 0;
}

bool is_wifi_network_secured(struct wifi_network *network) {
  if (strstr(network->capabilities, "RSN") ||
      strstr(network->capabilities, "WPA"))
    return true;
  return false;
}

void free_network_configuration(struct network_configuration *configuration) {
  if (configuration == NULL)
    return;

  free(configuration->method);
  free(configuration->ip);
  free(configuration->netmask);
  free(configuration->gateway);
  free(configuration->dns1);
  free(configuration->dns2);
  free(configuration->search_domain);

  free(configuration);
}

struct network_configuration *generate_network_configuration(int argc,
                                                             char **argv) {
  struct option options[] = {
      {"method", required_argument, NULL, 'm'},
      {"ip", required_argument, NULL, 'i'},
      {"netmask", required_argument, NULL, 'n'},
      {"gateway", required_argument, NULL, 'g'},
      {"dns1", required_argument, NULL, 'd'},
      {"dns2", required_argument, NULL, 's'},
      {"search", required_argument, NULL, 'r'},
      {NULL, 0, NULL, 0},
  };

  struct network_configuration *config =
      malloc(sizeof(struct network_configuration));
  if (config == NULL)
    return NULL;
  memset(config, 0, sizeof(struct network_configuration));

  int opt;
  while ((opt = getopt_long(argc, argv, "m:i:n:g:d:s:r:", options, NULL)) !=
         -1) {
    switch (opt) {
    case 'm':
      if (strcmp(optarg, "dhcp") != 0 && strcmp(optarg, "manual") != 0) {
        fprintf(stderr, "invalid method: %s", optarg);
        free_network_configuration(config);
        return NULL;
      }
      config->method = strdup(optarg);
      break;
    case 'i':
      if (config->method == NULL || strcmp(config->method, "manual") != 0) {
        fprintf(stderr, "use --method=manual for manually setting the IP\n");
        free_network_configuration(config);
        return NULL;
      }
      config->ip = strdup(optarg);
      break;
    case 'n':
      if (config->method == NULL || strcmp(config->method, "manual") != 0) {
        fprintf(stderr,
                "use --method=manual for manually setting the netmask\n");
        free_network_configuration(config);
        return NULL;
      }
      config->netmask = strdup(optarg);
      break;
    case 'g':
      if (config->method == NULL || strcmp(config->method, "manual") != 0) {
        fprintf(stderr,
                "use --method=manual for manually setting the gateway\n");
        free_network_configuration(config);
        return NULL;
      }
      config->gateway = strdup(optarg);
      break;
    case 'd':
      config->dns1 = strdup(optarg);
      break;
    case 's':
      config->dns2 = strdup(optarg);
      break;
    case 'r':
      config->search_domain = strdup(optarg);
      break;
    default:
      fprintf(stderr, "unknown option '%s'\n", optarg == NULL ? "" : optarg);
      free_network_configuration(config);
      return NULL;
    }
  }

  if (config->method == NULL || strcmp(config->method, "manual") == 0) {
    if (config->ip == NULL || config->netmask == NULL) {
      fprintf(stderr,
              "provide both ip address and netmask for manual configuration\n");
      free_network_configuration(config);
      return NULL;
    }
  }

  return config;
}
