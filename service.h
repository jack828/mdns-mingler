#pragma once
#include "mdns.h"
#include <netinet/in.h>

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
  void *buffer;
  int buffer_size;
} service_t;

service_t service_create(char *ip, char *host);

void service_free(service_t *service);

service_t service_create(char *ip, char *hostname) {

  char *service_name = "_http._tcp.local.";
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

  // Build the service instance "<hostname>.<_service-name>._tcp.local." string
  char *service_instance_buffer = calloc(256, sizeof(char));
  snprintf(service_instance_buffer, 255, "%.*s.%.*s",
           MDNS_STRING_FORMAT(hostname_string),
           MDNS_STRING_FORMAT(service_string));
  mdns_string_t service_instance_string =
      (mdns_string_t){service_instance_buffer, strlen(service_instance_buffer)};

  // Build the "<hostname>.local." string
  char *qualified_hostname_buffer = calloc(256, sizeof(char));
  snprintf(qualified_hostname_buffer, 255, "%.*s.local.",
           MDNS_STRING_FORMAT(hostname_string));
  mdns_string_t hostname_qualified_string = (mdns_string_t){
      qualified_hostname_buffer, strlen(qualified_hostname_buffer)};

  struct sockaddr_in service_address;
  uv_ip4_addr(ip, 80, &service_address);

  service_t service = {0};
  service.service = service_string;
  service.hostname = hostname_string;
  service.service_instance = service_instance_string;
  service.hostname_qualified = hostname_qualified_string;
  service.address_ipv4 = service_address;
  service.port = 80;
  // utility buffer for announce/goodbye
  service.buffer_size = 2048;
  service.buffer = malloc(service.buffer_size);

  // Setup our mDNS records

  // PTR record reverse mapping "<_service-name>._tcp.local." to
  // "<hostname>.<_service-name>._tcp.local."
  service.record_ptr =
      (mdns_record_t){.name = service.service,
                      .type = MDNS_RECORDTYPE_PTR,
                      .data.ptr.name = service.service_instance,
                      .rclass = 0,
                      .ttl = 1};

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
                      .ttl = 1};

  // A records mapping "<hostname>.local." to IPv4 addresses
  service.record_a = (mdns_record_t){.name = service.hostname_qualified,
                                     .type = MDNS_RECORDTYPE_A,
                                     .data.a.addr = service.address_ipv4,
                                     .rclass = 0,
                                     .ttl = 1};

  // Add TXT records for our service instance name, will be coalesced
  // into one record with both key-value pair strings by the library
  service.txt_record[0] =
      (mdns_record_t){.name = service.service_instance,
                      .type = MDNS_RECORDTYPE_TXT,
                      .data.txt.key = {MDNS_STRING_CONST("x-powered-by")},
                      .data.txt.value = {MDNS_STRING_CONST("mdns-mingler")},
                      .rclass = 0,
                      .ttl = 1};
  return service;
}

void service_free(service_t *service) {
  free((char *)service->service.str);
  free((char *)service->service_instance.str);
  free((char *)service->hostname_qualified.str);
  free(service->buffer);
}
