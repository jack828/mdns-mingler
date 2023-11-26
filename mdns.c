#include "mdns.h"

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
static uv_udp_t server;

static char addrbuffer[64];
static char namebuffer[256];
static char sendbuffer[1024];

static struct sockaddr_in service_address_ipv4;

static int has_ipv4;

volatile sig_atomic_t running = 1;

// Data for our service including the mDNS records
typedef struct {
  mdns_string_t service;
  mdns_string_t hostname;
  mdns_string_t service_instance;
  mdns_string_t hostname_qualified;
  struct sockaddr_in address_ipv4;
  int port;
  mdns_record_t record_ptr;
  mdns_record_t record_srv;
  mdns_record_t record_a;
  mdns_record_t txt_record[2];
} service_t;

typedef struct {
  service_t *service;
  uv_udp_t *handle;
} mdns_data_t;

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
  printf("service_callback: ");
  if (entry != MDNS_ENTRYTYPE_QUESTION) {
    printf("no\n");
    return 0;
  }
  printf("yes\n");

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
  } else if ((name.length == service->service_instance.length) &&
             (strncmp(name.str, service->service_instance.str, name.length) ==
              0)) {
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
  } else if ((name.length == service->hostname_qualified.length) &&
             (strncmp(name.str, service->hostname_qualified.str, name.length) ==
              0)) {
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

// Open sockets for sending one-shot multicast queries from an ephemeral port
static int open_client_sockets(int *sockets, int max_sockets, int port) {
  // When sending, each socket can only send to one network interface
  // Thus we need to open one socket for each interface and address family
  int num_sockets = 0;

  struct ifaddrs *ifaddr = 0;
  struct ifaddrs *ifa = 0;

  if (getifaddrs(&ifaddr) < 0)
    printf("Unable to get interface addresses\n");

  int first_ipv4 = 1;
  for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
    if (!ifa->ifa_addr)
      continue;
    if (!(ifa->ifa_flags & IFF_UP) || !(ifa->ifa_flags & IFF_MULTICAST))
      continue;
    if ((ifa->ifa_flags & IFF_LOOPBACK) || (ifa->ifa_flags & IFF_POINTOPOINT))
      continue;

    if (ifa->ifa_addr->sa_family == AF_INET) {
      struct sockaddr_in *saddr = (struct sockaddr_in *)ifa->ifa_addr;
      if (saddr->sin_addr.s_addr != htonl(INADDR_LOOPBACK)) {
        int log_addr = 0;
        if (first_ipv4) {
          service_address_ipv4 = *saddr;
          printf("Local IPv4 address: %u\n",
                 service_address_ipv4.sin_addr.s_addr);
          service_address_ipv4.sin_addr.s_addr = 167880896;
          first_ipv4 = 0;
          log_addr = 1;
        }
        has_ipv4 = 1;
        if (num_sockets < max_sockets) {
          saddr->sin_port = htons(port);
          int sock = mdns_socket_open_ipv4(saddr);
          if (sock >= 0) {
            sockets[num_sockets++] = sock;
            log_addr = 1;
          } else {
            log_addr = 0;
          }
        }
        if (log_addr) {
          char buffer[128];
          mdns_string_t addr = ipv4_address_to_string(
              buffer, sizeof(buffer), &service_address_ipv4,
              sizeof(struct sockaddr_in));
          printf("Local IPv4 address: %.*s\n", MDNS_STRING_FORMAT(addr));
        }
      }
    }
  }

  if (!has_ipv4) {
    printf("IPv4 interface not found, FATAL\n");
    exit(EXIT_FAILURE);
    return 0;
  }
  freeifaddrs(ifaddr);

  return num_sockets;
}

// Open sockets to listen to incoming mDNS queries on port 5353
static int open_service_sockets(int *sockets, int max_sockets) {
  // When receiving, each socket can receive data from all network interfaces
  // Thus we only need to open one socket for each address family
  int num_sockets = 0;

  // Call the client socket function to enumerate and get local addresses,
  // but not open the actual sockets
  open_client_sockets(0, 0, 0);

  if (num_sockets < max_sockets) {
    struct sockaddr_in sock_addr;
    memset(&sock_addr, 0, sizeof(struct sockaddr_in));
    sock_addr.sin_family = AF_INET;
    sock_addr.sin_addr.s_addr = INADDR_ANY;
    sock_addr.sin_port = htons(MDNS_PORT);
    int sock = mdns_socket_open_ipv4(&sock_addr);
    if (sock >= 0)
      sockets[num_sockets++] = sock;
  }

  return num_sockets;
}

// Provide a mDNS service, answering incoming DNS-SD and mDNS queries
static int service_mdns(const char *hostname, const char *service_name) {
  int sockets[32];
  int num_sockets =
      open_service_sockets(sockets, sizeof(sockets) / sizeof(sockets[0]));
  if (num_sockets <= 0) {
    printf("Failed to open any client sockets\n");
    return -1;
  }
  printf("Opened %d socket%s for mDNS service\n", num_sockets,
         num_sockets ? "s" : "");

  size_t service_name_length = strlen(service_name);
  if (!service_name_length) {
    printf("Invalid service name\n");
    return -1;
  }

  char *service_name_buffer = malloc(service_name_length + 2);
  memcpy(service_name_buffer, service_name, service_name_length);
  if (service_name_buffer[service_name_length - 1] != '.')
    service_name_buffer[service_name_length++] = '.';
  service_name_buffer[service_name_length] = 0;
  service_name = service_name_buffer;

  printf("Service mDNS: %s:%d\n", service_name, 80);
  printf("Hostname: %s\n", hostname);

  size_t capacity = 2048;
  void *buffer = malloc(capacity);

  mdns_string_t service_string =
      (mdns_string_t){service_name, strlen(service_name)};
  mdns_string_t hostname_string = (mdns_string_t){hostname, strlen(hostname)};

  // Build the service instance "<hostname>.<_service-name>._tcp.local." string
  char service_instance_buffer[256] = {0};
  snprintf(service_instance_buffer, sizeof(service_instance_buffer) - 1,
           "%.*s.%.*s", MDNS_STRING_FORMAT(hostname_string),
           MDNS_STRING_FORMAT(service_string));
  mdns_string_t service_instance_string =
      (mdns_string_t){service_instance_buffer, strlen(service_instance_buffer)};

  // Build the "<hostname>.local." string
  char qualified_hostname_buffer[256] = {0};
  snprintf(qualified_hostname_buffer, sizeof(qualified_hostname_buffer) - 1,
           "%.*s.local.", MDNS_STRING_FORMAT(hostname_string));
  mdns_string_t hostname_qualified_string = (mdns_string_t){
      qualified_hostname_buffer, strlen(qualified_hostname_buffer)};

  service_t service = {0};
  service.service = service_string;
  service.hostname = hostname_string;
  service.service_instance = service_instance_string;
  service.hostname_qualified = hostname_qualified_string;
  service.address_ipv4 = service_address_ipv4;
  service.port = 80;

  // Setup our mDNS records

  // PTR record reverse mapping "<_service-name>._tcp.local." to
  // "<hostname>.<_service-name>._tcp.local."
  service.record_ptr =
      (mdns_record_t){.name = service.service,
                      .type = MDNS_RECORDTYPE_PTR,
                      .data.ptr.name = service.service_instance,
                      .rclass = 0,
                      .ttl = 0};

  // SRV record mapping "<hostname>.<_service-name>._tcp.local." to
  // "<hostname>.local." with port. Set weight & priority to 0.
  service.record_srv =
      (mdns_record_t){.name = service.service_instance,
                      .type = MDNS_RECORDTYPE_SRV,
                      .data.srv.name = service.hostname_qualified,
                      .data.srv.port = service.port,
                      .data.srv.priority = 0,
                      .data.srv.weight = 0,
                      .rclass = 0,
                      .ttl = 0};

  // A records mapping "<hostname>.local." to IPv4 addresses
  service.record_a = (mdns_record_t){.name = service.hostname_qualified,
                                     .type = MDNS_RECORDTYPE_A,
                                     .data.a.addr = service.address_ipv4,
                                     .rclass = 0,
                                     .ttl = 0};

  // Add TXT records for our service instance name, will be coalesced
  // into one record with both key-value pair strings by the library
  service.txt_record[0] =
      (mdns_record_t){.name = service.service_instance,
                      .type = MDNS_RECORDTYPE_TXT,
                      .data.txt.key = {MDNS_STRING_CONST("x-powered-by")},
                      .data.txt.value = {MDNS_STRING_CONST("mdns-mingler")},
                      .rclass = 0,
                      .ttl = 0};

  // Send an announcement on startup of service
  {
    printf("Sending announce\n");
    mdns_record_t additional[5] = {0};
    size_t additional_count = 0;
    additional[additional_count++] = service.record_srv;
    if (service.address_ipv4.sin_family == AF_INET)
      additional[additional_count++] = service.record_a;
    additional[additional_count++] = service.txt_record[0];

    for (int isock = 0; isock < num_sockets; ++isock) {
      // mdns_announce_multicast(sockets[isock], buffer, capacity,
      //                         service.record_ptr, 0, 0, additional,
      //                         additional_count);
    }
  }

  // This is a crude implementation that checks for incoming queries
  while (running) {
    int nfds = 0;
    fd_set readfs;
    FD_ZERO(&readfs);
    for (int isock = 0; isock < num_sockets; ++isock) {
      if (sockets[isock] >= nfds)
        nfds = sockets[isock] + 1;
      FD_SET(sockets[isock], &readfs);
    }

    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 100000;

    if (select(nfds, &readfs, 0, 0, &timeout) >= 0) {
      for (int isock = 0; isock < num_sockets; ++isock) {
        if (FD_ISSET(sockets[isock], &readfs)) {
          mdns_socket_listen(sockets[isock], buffer, capacity, service_callback,
                             &service);
        }
        FD_SET(sockets[isock], &readfs);
      }
    } else {
      break;
    }
  }

  // Send a goodbye on end of service
  {
    printf("Sending goodbye\n");
    mdns_record_t additional[5] = {0};
    size_t additional_count = 0;
    additional[additional_count++] = service.record_srv;
    if (service.address_ipv4.sin_family == AF_INET)
      additional[additional_count++] = service.record_a;
    additional[additional_count++] = service.txt_record[0];

    for (int isock = 0; isock < num_sockets; ++isock) {
      // mdns_goodbye_multicast(sockets[isock], buffer, capacity,
      //                        service.record_ptr, 0, 0, additional,
      //                        additional_count);
    }
  }

  free(buffer);
  free(service_name_buffer);

  for (int isock = 0; isock < num_sockets; ++isock)
    mdns_socket_close(sockets[isock]);
  printf("Closed socket%s\n", num_sockets ? "s" : "");

  return 0;
}

void signal_handler(int signal) { running = 0; }

static void on_recv(uv_udp_t *req, ssize_t nread, const uv_buf_t *buf,
                    const struct sockaddr *addr, unsigned flags) {
  if (nread < 0) {
    fprintf(stderr, "Read error %s\n", uv_err_name(nread));
    // free(buf->base);
    return;
  }
  if (nread == 0) {
    printf("recv end of packet\n");
    if (buf != NULL && buf->base != NULL) {

      free(buf->base);
    }
    return;
  }

  printf("\nrecv start of packet\n");
  char *service_name = "_http._tcp.local.";
  char *hostname = "plex";
  size_t service_name_length = strlen(service_name);
  char *service_name_buffer = malloc(service_name_length + 2);
  memcpy(service_name_buffer, service_name, service_name_length);
  if (service_name_buffer[service_name_length - 1] != '.')
    service_name_buffer[service_name_length++] = '.';
  service_name_buffer[service_name_length] = 0;
  service_name = service_name_buffer;

  // printf("Service mDNS: %s:%d\n", service_name, 80);
  // printf("Hostname: %s\n", hostname);

  mdns_string_t service_string =
      (mdns_string_t){service_name, strlen(service_name)};
  mdns_string_t hostname_string = (mdns_string_t){hostname, strlen(hostname)};

  // Build the service instance "<hostname>.<_service-name>._tcp.local."
  // string
  char service_instance_buffer[256] = {0};
  snprintf(service_instance_buffer, sizeof(service_instance_buffer) - 1,
           "%.*s.%.*s", MDNS_STRING_FORMAT(hostname_string),
           MDNS_STRING_FORMAT(service_string));
  mdns_string_t service_instance_string =
      (mdns_string_t){service_instance_buffer, strlen(service_instance_buffer)};

  // Build the "<hostname>.local." string
  char qualified_hostname_buffer[256] = {0};
  snprintf(qualified_hostname_buffer, sizeof(qualified_hostname_buffer) - 1,
           "%.*s.local.", MDNS_STRING_FORMAT(hostname_string));
  mdns_string_t hostname_qualified_string = (mdns_string_t){
      qualified_hostname_buffer, strlen(qualified_hostname_buffer)};

  service_t service = {0};
  service.service = service_string;
  service.hostname = hostname_string;
  service.service_instance = service_instance_string;
  service.hostname_qualified = hostname_qualified_string;
  service.address_ipv4 = service_address_ipv4;
  service.port = 80;

  // Setup our mDNS records

  // PTR record reverse mapping "<_service-name>._tcp.local." to
  // "<hostname>.<_service-name>._tcp.local."
  service.record_ptr =
      (mdns_record_t){.name = service.service,
                      .type = MDNS_RECORDTYPE_PTR,
                      .data.ptr.name = service.service_instance,
                      .rclass = 0,
                      .ttl = 0};

  // SRV record mapping "<hostname>.<_service-name>._tcp.local." to
  // "<hostname>.local." with port. Set weight & priority to 0.
  service.record_srv =
      (mdns_record_t){.name = service.service_instance,
                      .type = MDNS_RECORDTYPE_SRV,
                      .data.srv.name = service.hostname_qualified,
                      .data.srv.port = service.port,
                      .data.srv.priority = 0,
                      .data.srv.weight = 0,
                      .rclass = 0,
                      .ttl = 0};

  // A records mapping "<hostname>.local." to IPv4 addresses
  service.record_a = (mdns_record_t){.name = service.hostname_qualified,
                                     .type = MDNS_RECORDTYPE_A,
                                     .data.a.addr = service.address_ipv4,
                                     .rclass = 0,
                                     .ttl = 0};

  // Add TXT records for our service instance name, will be coalesced
  // into one record with both key-value pair strings by the library
  service.txt_record[0] =
      (mdns_record_t){.name = service.service_instance,
                      .type = MDNS_RECORDTYPE_TXT,
                      .data.txt.key = {MDNS_STRING_CONST("x-powered-by")},
                      .data.txt.value = {MDNS_STRING_CONST("mdns-mingler")},
                      .rclass = 0,
                      .ttl = 0};

  mdns_data_t mdns_data = {0};
  mdns_data.service = &service;
  mdns_data.handle = req;

  char sender[17] = {0};
  uv_ip4_name((const struct sockaddr_in *)addr, sender, 16);
  printf("Packet from %s\n", sender);
  printf("Size: %lu %.*s\n", nread, (int)nread, (char *)buf->base);
  for (int i = 0; i < nread; i++) {
    printf("%02X", buf->base[i]);
  }
  printf("\n");
  uvmdns_socket_recv(buf, addr, service_callback, &mdns_data);
  free(buf->base);
  free(service_name_buffer);
  printf("end of on_recv\n");
}

static void close_cb(uv_handle_t *handle) { free(handle); }

static void on_walk_cleanup(uv_handle_t *handle, void *data) {
  if (!uv_is_closing((uv_handle_t *)&handle)) {
    uv_close(handle, NULL);
  }
}

static void on_close(uv_handle_t *handle) {
  printf("Closing, goodbye\n");
  // http://stackoverflow.com/questions/25615340/closing-libuv-handles-correctly
  uv_stop(uv_loop);
  uv_run(uv_loop, UV_RUN_DEFAULT);
  uv_walk(uv_loop, on_walk_cleanup, NULL);
  uv_run(uv_loop, UV_RUN_DEFAULT);
  int ret = uv_loop_close(uv_loop);
  if (ret != 0) {
    fprintf(stderr, "uv_loop_close did not return 0!\n");
  }
}

static void on_signal(uv_signal_t *signal, int signum) {
  if (uv_is_active((uv_handle_t *)&server)) {
    uv_udp_recv_stop(&server);
  }
  uv_close((uv_handle_t *)&server, on_close);
  uv_signal_stop(signal);
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
    {.name = "service",
     .key = 's',
     .arg = "SERVICE",
     .flags = OPTION_ARG_OPTIONAL,
     .doc = "Service name e.g. '_http._tcp.local.'",
     .group = 0},
    {.name = "hosts",
     .key = 'h',
     .arg = "HOSTS",
     .flags = OPTION_ARG_OPTIONAL,
     .doc = "Path to hosts file. Default './hosts'.",
     .group = 1},
    {0}};

struct arguments {
  char *service;
  char *hosts;
};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
  struct arguments *arguments = state->input;

  switch (key) {
  case 's':
    arguments->service = arg;
    break;
  case 'h':
    arguments->hosts = arg;
    break;
  default:
    return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

static struct argp argp = {options, parse_opt, args_doc, doc};

int main(int argc, char **argv) {
  struct arguments arguments;
  /* Default values */
  arguments.service = "_http._tcp.local.";
  arguments.hosts = "./hosts";

  argp_parse(&argp, argc, argv, 0, 0, &arguments);

  signal(SIGINT, signal_handler);

  FILE *fp = fopen(arguments.hosts, "r");
  if (fp == NULL) {
    perror("Unable to open hosts file");
    exit(EXIT_FAILURE);
  }

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
    printf("line: '%s'\n", line);
  }
  fclose(fp);

  int status;
  struct sockaddr_in addr;

  uv_signal_t sigint, sigterm;
  uv_loop = uv_default_loop();

  status = uv_udp_init(uv_loop, &server);
  UV_CHECK(status, "init");
  uv_signal_init(uv_loop, &sigint);
  uv_signal_start(&sigint, on_signal, SIGINT);
  uv_signal_init(uv_loop, &sigterm);
  uv_signal_start(&sigterm, on_signal, SIGTERM);

  uv_ip4_addr("0.0.0.0", MDNS_PORT, &addr);

  open_client_sockets(0, 0, 0);
  status =
      uv_udp_bind(&server, (const struct sockaddr *)&addr, UV_UDP_REUSEADDR);
  UV_CHECK(status, "bind");

  status = uv_udp_recv_start(&server, on_alloc, on_recv);
  UV_CHECK(status, "recv");

  return uv_run(uv_loop, UV_RUN_DEFAULT);
  // return service_mdns("plex", arguments.service);
}
