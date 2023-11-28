#include "mdns.h"
#include "service.h"

#include <argp.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <uv.h>

#define UV_CHECK(r, msg)                                                       \
  if (r < 0) {                                                                 \
    fprintf(stderr, "%s: %s\n", msg, uv_strerror(r));                          \
    exit(1);                                                                   \
  }

static uv_loop_t *uv_loop;
static uv_udp_t *server = NULL;
static uv_timer_t *announce_timer = NULL;
static uv_timer_t *goodbye_timer = NULL;

static char addrbuffer[64];
static char namebuffer[256];
static char sendbuffer[1024];

typedef struct {
  service_t *service;
  uv_udp_t *handle;
} mdns_data_t;

static service_t *services = NULL;
static int services_count = 0;

static mdns_string_t ipv4_address_to_string(char *buffer, size_t capacity,
                                            const struct sockaddr_in *addr,
                                            size_t addrlen) {
  char host[NI_MAXHOST] = {0};
  char service[NI_MAXSERV] = {0};
  int ret = getnameinfo((const struct sockaddr *)addr, (socklen_t)addrlen, host,
                        NI_MAXHOST, service, NI_MAXSERV,
                        NI_NUMERICSERV | NI_NUMERICHOST);
  int len = 0;
  if (ret == 0) {
    if (addr->sin_port != 0)
      len = snprintf(buffer, capacity, "%s:%s", host, service);
    else
      len = snprintf(buffer, capacity, "%s", host);
  } else {
    printf("ipv4_address_to_string fail ret: %d: %s\n", ret, gai_strerror(ret));
  }
  if (len >= (int)capacity)
    len = (int)capacity - 1;
  mdns_string_t str;
  str.str = buffer;
  str.length = len;
  return str;
}

static mdns_string_t ip_address_to_string(char *buffer, size_t capacity,
                                          const struct sockaddr *addr,
                                          size_t addrlen) {
  return ipv4_address_to_string(buffer, capacity,
                                (const struct sockaddr_in *)addr, addrlen);
}

// Callback handling questions incoming on service sockets
static int service_callback(int sock, const struct sockaddr *from,
                            size_t addrlen, mdns_entry_type_t entry,
                            uint16_t query_id, uint16_t rtype, uint16_t rclass,
                            uint32_t ttl, const void *data, size_t size,
                            size_t name_offset, size_t name_length,
                            size_t record_offset, size_t record_length,
                            void *user_data) {
  (void)sizeof(ttl);
  if (entry != MDNS_ENTRYTYPE_QUESTION) {
    return 0;
  }

  const char dns_sd[] = "_services._dns-sd._udp.local.";
  const mdns_data_t *mdns_data = (const mdns_data_t *)user_data;
  const service_t *service = (const service_t *)mdns_data->service;
  uv_udp_t *handle = mdns_data->handle;

  mdns_string_t fromaddrstr =
      ip_address_to_string(addrbuffer, sizeof(addrbuffer), from, addrlen);

  size_t offset = name_offset;
  mdns_string_t name =
      mdns_string_extract(data, size, &offset, namebuffer, sizeof(namebuffer));

  const char *record_name = 0;
  if (rtype == MDNS_RECORDTYPE_PTR)
    record_name = "PTR";
  else if (rtype == MDNS_RECORDTYPE_SRV)
    record_name = "SRV";
  else if (rtype == MDNS_RECORDTYPE_A)
    record_name = "A";
  else if (rtype == MDNS_RECORDTYPE_AAAA)
    record_name = "AAAA";
  else if (rtype == MDNS_RECORDTYPE_TXT)
    record_name = "TXT";
  else if (rtype == MDNS_RECORDTYPE_ANY)
    record_name = "ANY";
  else {
    printf("\nQuery BAD RTYPE '%d', %s %.*s from %.*s\n", rtype, record_name,
           MDNS_STRING_FORMAT(name), MDNS_STRING_FORMAT(fromaddrstr));
    return 0;
  }
  printf("\nQuery %s %.*s from %.*s\n", record_name, MDNS_STRING_FORMAT(name),
         MDNS_STRING_FORMAT(fromaddrstr));

  bool is_sd_domain_query =
      (name.length == (sizeof(dns_sd) - 1)) &&
      (strncmp(name.str, dns_sd, sizeof(dns_sd) - 1) == 0);
  bool is_service_query =
      (name.length == service->service.length) &&
      (strncmp(name.str, service->service.str, name.length) == 0);
  bool is_service_instance_query =
      (name.length == service->service_instance.length) &&
      (strncmp(name.str, service->service_instance.str, name.length) == 0);
  bool is_qualified_hostname_query =
      (name.length == service->hostname_qualified.length) &&
      (strncmp(name.str, service->hostname_qualified.str, name.length) == 0);

  if (is_sd_domain_query) {
    if ((rtype == MDNS_RECORDTYPE_PTR) || (rtype == MDNS_RECORDTYPE_ANY)) {
      // The PTR query was for the DNS-SD domain, send answer with a PTR record
      // for the service name we advertise, typically on the
      // "<_service-name>._tcp.local." format

      // Answer PTR record reverse mapping "<_service-name>._tcp.local." to
      // "<hostname>.<_service-name>._tcp.local."
      mdns_record_t answer = {.name = name,
                              .type = MDNS_RECORDTYPE_PTR,
                              .data.ptr.name = service->service};

      // Send the answer, unicast or multicast depending on flag in query
      uint16_t unicast = (rclass & MDNS_UNICAST_RESPONSE);
      printf("  --> answer %.*s (%s)\n",
             MDNS_STRING_FORMAT(answer.data.ptr.name),
             (unicast ? "unicast" : "multicast"));

      if (unicast) {
        mdns_query_answer_unicast(handle, from, addrlen, sendbuffer,
                                  sizeof(sendbuffer), query_id, rtype, name.str,
                                  name.length, answer, 0, 0, 0, 0);
      } else {
        mdns_query_answer_multicast(handle, sendbuffer, sizeof(sendbuffer),
                                    answer, 0, 0, 0, 0);
      }
    }
  } else if (is_service_query) {
    if ((rtype == MDNS_RECORDTYPE_PTR) || (rtype == MDNS_RECORDTYPE_ANY)) {
      // The PTR query was for our service (usually
      // "<_service-name._tcp.local"), answer a PTR record reverse mapping the
      // queried service name to our service instance name (typically on the
      // "<hostname>.<_service-name>._tcp.local." format), and add additional
      // records containing the SRV record mapping the service instance name to
      // our qualified hostname (typically "<hostname>.local.") and port, as
      // well as any IPv4 address for the hostname as A records, and
      // TXT records

      // Answer PTR record reverse mapping "<_service-name>._tcp.local." to
      // "<hostname>.<_service-name>._tcp.local."
      mdns_record_t answer = service->record_ptr;

      mdns_record_t additional[5] = {0};
      size_t additional_count = 0;

      // SRV record mapping "<hostname>.<_service-name>._tcp.local." to
      // "<hostname>.local." with port. Set weight & priority to 0.
      additional[additional_count++] = service->record_srv;

      // A records mapping "<hostname>.local." to IPv4 addresses
      if (service->address_ipv4.sin_family == AF_INET)
        additional[additional_count++] = service->record_a;

      // Add TXT records for our service instance name, will be
      // coalesced into one record with both key-value pair strings by the
      // library
      additional[additional_count++] = service->txt_record[0];

      // Send the answer, unicast or multicast depending on flag in query
      uint16_t unicast = (rclass & MDNS_UNICAST_RESPONSE);
      printf("  --> answer %.*s (%s)\n",
             MDNS_STRING_FORMAT(service->record_ptr.data.ptr.name),
             (unicast ? "unicast" : "multicast"));

      if (unicast) {
        mdns_query_answer_unicast(handle, from, addrlen, sendbuffer,
                                  sizeof(sendbuffer), query_id, rtype, name.str,
                                  name.length, answer, 0, 0, additional,
                                  additional_count);
      } else {
        mdns_query_answer_multicast(handle, sendbuffer, sizeof(sendbuffer),
                                    answer, 0, 0, additional, additional_count);
      }
    }
  } else if (is_service_instance_query) {
    if ((rtype == MDNS_RECORDTYPE_SRV) || (rtype == MDNS_RECORDTYPE_ANY)) {
      // The SRV query was for our service instance (usually
      // "<hostname>.<_service-name._tcp.local"), answer a SRV record mapping
      // the service instance name to our qualified hostname (typically
      // "<hostname>.local.") and port, as well as any IPv4 address for the
      // hostname as A records, and TXT records

      // Answer PTR record reverse mapping "<_service-name>._tcp.local." to
      // "<hostname>.<_service-name>._tcp.local."
      mdns_record_t answer = service->record_srv;

      mdns_record_t additional[5] = {0};
      size_t additional_count = 0;

      // A records mapping "<hostname>.local." to IPv4 addresses
      if (service->address_ipv4.sin_family == AF_INET)
        additional[additional_count++] = service->record_a;

      // Add TXT records for our service instance name, will be
      // coalesced into one record with both key-value pair strings by the
      // library
      additional[additional_count++] = service->txt_record[0];

      // Send the answer, unicast or multicast depending on flag in query
      uint16_t unicast = (rclass & MDNS_UNICAST_RESPONSE);
      printf("  --> answer %.*s port %d (%s)\n",
             MDNS_STRING_FORMAT(service->record_srv.data.srv.name),
             service->port, (unicast ? "unicast" : "multicast"));

      if (unicast) {
        mdns_query_answer_unicast(handle, from, addrlen, sendbuffer,
                                  sizeof(sendbuffer), query_id, rtype, name.str,
                                  name.length, answer, 0, 0, additional,
                                  additional_count);
      } else {
        mdns_query_answer_multicast(handle, sendbuffer, sizeof(sendbuffer),
                                    answer, 0, 0, additional, additional_count);
      }
    }
  } else if (is_qualified_hostname_query) {
    if (((rtype == MDNS_RECORDTYPE_A) || (rtype == MDNS_RECORDTYPE_ANY)) &&
        (service->address_ipv4.sin_family == AF_INET)) {
      // The A query was for our qualified hostname (typically
      // "<hostname>.local.") and we have an IPv4 address, answer with an A
      // record mapping the hostname to an IPv4 address and TXT records

      // Answer A records mapping "<hostname>.local." to IPv4 address
      mdns_record_t answer = service->record_a;

      mdns_record_t additional[5] = {0};
      size_t additional_count = 0;

      // Add TXT records for our service instance name, will be
      // coalesced into one record with both key-value pair strings by the
      // library
      additional[additional_count++] = service->txt_record[0];

      // Send the answer, unicast or multicast depending on flag in query
      uint16_t unicast = (rclass & MDNS_UNICAST_RESPONSE);
      mdns_string_t addrstr = ip_address_to_string(
          addrbuffer, sizeof(addrbuffer),
          (struct sockaddr *)&service->record_a.data.a.addr,
          sizeof(service->record_a.data.a.addr));
      printf("  --> answer %.*s IPv4 %.*s (%s)\n",
             MDNS_STRING_FORMAT(service->record_a.name),
             MDNS_STRING_FORMAT(addrstr), (unicast ? "unicast" : "multicast"));

      if (unicast) {
        mdns_query_answer_unicast(handle, from, addrlen, sendbuffer,
                                  sizeof(sendbuffer), query_id, rtype, name.str,
                                  name.length, answer, 0, 0, additional,
                                  additional_count);
      } else {
        mdns_query_answer_multicast(handle, sendbuffer, sizeof(sendbuffer),
                                    answer, 0, 0, additional, additional_count);
      }
    }
  } else {
    printf("I dont care about this packet\n");
  }
  return 0;
}

static void on_recv(uv_udp_t *req, ssize_t nread, const uv_buf_t *buf,
                    const struct sockaddr *addr, unsigned flags) {
  if (nread < 0) {
    fprintf(stderr, "Read error %s\n", uv_err_name(nread));
    return;
  }
  if (nread == 0) {
    if (buf != NULL && buf->base != NULL) {
      free(buf->base);
    }
    return;
  }

  char sender[17] = {0};
  uv_ip4_name((const struct sockaddr_in *)addr, sender, 16);
  /*
  printf("Packet from %s (%lu)\n", sender, nread);
  printf("Size: %lu %.*s\n", nread, (int)nread, (char *)buf->base);
  for (int i = 0; i < nread; i++) {
    printf("%02X", buf->base[i]);
  }
  printf("\n");
  */

  for (int i = 0; i < services_count; i++) {
    mdns_data_t mdns_data = {0};
    mdns_data.service = &services[i];
    mdns_data.handle = req;
    uvmdns_socket_recv(buf, addr, service_callback, &mdns_data);
  }
  free(buf->base);
}

static void announce_services(uv_timer_t *timer) {
  uv_timer_stop(timer);
  uv_close((uv_handle_t *)timer, NULL);
  printf("Sending announce\n");

  for (int i = 0; i < services_count; i++) {
    service_t service = services[i];
    mdns_record_t additional[5] = {0};
    size_t additional_count = 0;
    additional[additional_count++] = service.record_srv;
    if (service.address_ipv4.sin_family == AF_INET)
      additional[additional_count++] = service.record_a;
    additional[additional_count++] = service.txt_record[0];

    mdns_announce_multicast(server, service.buffer, service.buffer_size,
                            service.record_ptr, 0, 0, additional,
                            additional_count);
  }
  printf("Announced!\n");
}

static void goodbye_services(uv_timer_t *timer) {
  uv_timer_stop(timer);
  uv_close((uv_handle_t *)timer, NULL);
  printf("Sending goodbye\n");

  for (int i = 0; i < services_count; i++) {
    service_t service = services[i];
    mdns_record_t additional[5] = {0};
    size_t additional_count = 0;
    additional[additional_count++] = service.record_srv;
    if (service.address_ipv4.sin_family == AF_INET)
      additional[additional_count++] = service.record_a;
    additional[additional_count++] = service.txt_record[0];

    mdns_goodbye_multicast(server, service.buffer, service.buffer_size,
                           service.record_ptr, 0, 0, additional,
                           additional_count);
  }
  printf("Goodbyed!\n");
}

static void on_walk_cleanup(uv_handle_t *handle, void *data) {
  if (!uv_is_closing(handle)) {
    uv_close(handle, NULL);
  }
}

static void on_close() {
  printf("Closing, goodbye\n");
  uv_timer_start(goodbye_timer, goodbye_services, 0, 0);
  uv_run(uv_loop, UV_RUN_ONCE);
  uv_stop(uv_loop);
  uv_run(uv_loop, UV_RUN_DEFAULT);
  uv_walk(uv_loop, on_walk_cleanup, NULL);
  uv_run(uv_loop, UV_RUN_DEFAULT);
  int ret = uv_loop_close(uv_loop);
  if (ret != 0) {
    fprintf(stderr, "uv_loop_close did not return 0!\n");
  }
  for (int i = 0; i < services_count; i++) {
    service_free(&services[i]);
  }
  free(services);
  free(announce_timer);
  free(goodbye_timer);
  free(server);
}

static void on_signal(uv_signal_t *signal, int signum) {
  if (uv_is_active((uv_handle_t *)&server)) {
    uv_udp_recv_stop(server);
  }
  uv_signal_stop(signal);
  if (server) {
    uv_close((uv_handle_t *)server, on_close);
  } else {
    on_close();
  }
}

static void on_alloc(uv_handle_t *handle, size_t suggested_size,
                     uv_buf_t *buf) {
  buf->base = calloc(1, suggested_size);
  buf->len = suggested_size;
}

const char *argp_program_version = "mdns-mingler 1.0";
const char *argp_program_bug_address = "Jack Burgess <me@jackburgess.dev>";

static char doc[] = "mDNS Mingling Utility. So a mDNS server of sorts.";

static char args_doc[] = "";

static struct argp_option options[] = {
    {.name = "hosts",
     .key = 'h',
     .arg = "HOSTS",
     .flags = OPTION_ARG_OPTIONAL,
     .doc = "Path to hosts file. Default './hosts'.",
     .group = 0},
    {0}};

struct arguments {
  char *hosts;
};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
  struct arguments *arguments = state->input;

  switch (key) {
  case 'h':
    arguments->hosts = arg;
    break;
  default:
    return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

static struct argp argp = {options, parse_opt, args_doc, doc, 0, 0, 0};

int main(int argc, char **argv) {
  struct arguments arguments;
  /* Default values */
  arguments.hosts = "./hosts";

  argp_parse(&argp, argc, argv, 0, 0, &arguments);

  FILE *fp = fopen(arguments.hosts, "r");
  if (fp == NULL) {
    perror("Unable to open hosts file");
    exit(EXIT_FAILURE);
  }

  int c;
  int line_count = 0;
  while ((c = fgetc(fp)) != EOF) {
    if (c == '\n')
      line_count++;
  }

  // more than likely more than is required, when counting comments etc
  services = calloc(line_count, sizeof(service_t));

  fseek(fp, 0, 0);

  char line[256];
  while (fgets(line, sizeof(line), fp) != NULL) {
    int length = strlen(line);
    if (length <= 1) {
      // ignore empty
      continue;
    }
    if (line[0] == '#') {
      // ignore comments
      continue;
    }
    // trim trailing newline
    line[strcspn(line, "\n")] = '\0';

    char *ip = strtok(line, " ");
    char *host = strtok(NULL, " ");
    printf("Service: '%s.local' -> %s\n", host, ip);
    service_t service = service_create(ip, host);
    services[services_count++] = service;
  }
  fclose(fp);

  uv_loop = uv_default_loop();
  int status;

  uv_signal_t sigint, sigterm;
  uv_signal_init(uv_loop, &sigint);
  uv_signal_start(&sigint, on_signal, SIGINT);
  uv_signal_init(uv_loop, &sigterm);
  uv_signal_start(&sigterm, on_signal, SIGTERM);

  server = malloc(sizeof(uv_udp_t));

  struct sockaddr_in addr;
  uv_ip4_addr("0.0.0.0", MDNS_PORT, &addr);

  status = uv_udp_init(uv_loop, server);
  UV_CHECK(status, "init");
  status =
      uv_udp_bind(server, (const struct sockaddr *)&addr, UV_UDP_REUSEADDR);
  UV_CHECK(status, "bind");

  status = uv_udp_recv_start(server, on_alloc, on_recv);
  UV_CHECK(status, "recv");

  announce_timer = malloc(sizeof(uv_timer_t));
  status = uv_timer_init(uv_loop, announce_timer);
  UV_CHECK(status, "announce timer_init");
  status =uv_timer_start(announce_timer, announce_services, 0, 0);
  UV_CHECK(status, "announce timer_start");

  goodbye_timer = malloc(sizeof(uv_timer_t));
  status = uv_timer_init(uv_loop, goodbye_timer);
  UV_CHECK(status, "goodbye timer_init");

  printf("Ready!\n");
  return uv_run(uv_loop, UV_RUN_DEFAULT);
}
