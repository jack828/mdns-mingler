#pragma once

#include <uv.h>
#include "mdns.h"

/*
 * By-n-large a copy of mdns_socket_listen but modified to not use recvfrom
 * as libuv passes a full buffer object already.
 * Since there's no socket available the `sock` argument is deliberately invalid.
 */
static size_t uvmdns_socket_recv(const uv_buf_t *buf, const struct sockaddr *addr,
                               mdns_record_callback_fn callback,
                               void *user_data) {
  int sock = -1;
  size_t data_size = (size_t)buf->len;
  const uint16_t *data = (const uint16_t *)buf->base;
  socklen_t addrlen = sizeof(*addr);

  uint16_t query_id = mdns_ntohs(data++);
  uint16_t flags = mdns_ntohs(data++);
  uint16_t questions = mdns_ntohs(data++);
  uint16_t answer_rrs = mdns_ntohs(data++);
  uint16_t authority_rrs = mdns_ntohs(data++);
  uint16_t additional_rrs = mdns_ntohs(data++);

  size_t records;
  size_t total_records = 0;
  for (int iquestion = 0; iquestion < questions; ++iquestion) {
    size_t question_offset = MDNS_POINTER_DIFF(data, buf->base);
    size_t offset = question_offset;
    size_t verify_offset = 12;
    int dns_sd = 0;
    if (mdns_string_equal(buf->base, data_size, &offset, mdns_services_query,
                          sizeof(mdns_services_query), &verify_offset)) {
      dns_sd = 1;
    } else if (!mdns_string_skip(buf->base, data_size, &offset)) {
      break;
    }
    size_t length = offset - question_offset;
    data = (const uint16_t *)MDNS_POINTER_OFFSET_CONST(buf->base, offset);

    uint16_t rtype = mdns_ntohs(data++);
    uint16_t rclass = mdns_ntohs(data++);
    uint16_t class_without_flushbit = rclass & ~MDNS_CACHE_FLUSH;

    // Make sure we get a question of class IN or ANY
    if (!((class_without_flushbit == MDNS_CLASS_IN) ||
          (class_without_flushbit == MDNS_CLASS_ANY))) {
      break;
    }

    if (dns_sd && flags)
      continue;

    ++total_records;
    if (callback &&
        callback(sock, addr, addrlen, MDNS_ENTRYTYPE_QUESTION, query_id, rtype,
                 rclass, 0, buf->base, data_size, question_offset, length,
                 question_offset, length, user_data))
      return total_records;
  }

  size_t offset = MDNS_POINTER_DIFF(data, buf->base);
  records = mdns_records_parse(sock, addr, addrlen, buf->base, data_size,
                               &offset, MDNS_ENTRYTYPE_ANSWER, query_id,
                               answer_rrs, callback, user_data);
  total_records += records;
  if (records != answer_rrs)
    return total_records;

  records = mdns_records_parse(sock, addr, addrlen, buf->base, data_size,
                               &offset, MDNS_ENTRYTYPE_AUTHORITY, query_id,
                               authority_rrs, callback, user_data);
  total_records += records;
  if (records != authority_rrs)
    return total_records;

  records = mdns_records_parse(sock, addr, addrlen, buf->base, data_size,
                               &offset, MDNS_ENTRYTYPE_ADDITIONAL, query_id,
                               additional_rrs, callback, user_data);

  return total_records;
}

