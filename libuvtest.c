#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>

#define UV_CHECK(r, msg)                                                          \
  if (r < 0) {                                                                 \
    fprintf(stderr, "%s: %s\n", msg, uv_strerror(r));                          \
    exit(1);                                                                   \
  }

static uv_loop_t *uv_loop;
static uv_udp_t server;

static void on_recv(uv_udp_t *req, ssize_t nread, const uv_buf_t *buf,
                    const struct sockaddr *addr, unsigned flags) {
  if (nread < 0) {
    fprintf(stderr, "Read error %s\n", uv_err_name(nread));
    free(buf->base);
    return;
  }
  if (nread > 0) {
    printf("%lu %.*s\n", nread, nread, buf->base);
    printf("free  :%lu %p\n", buf->len, buf->base);
    char sender[17] = {0};
    uv_ip4_name((const struct sockaddr_in *)addr, sender, 16);
    printf("Recv from %s\n", sender);
  }
  free(buf->base);
}

static void on_walk_cleanup(uv_handle_t *handle, void *data) {
  uv_close(handle, NULL);
}

static void on_close(uv_handle_t *handle) {
  printf("Closing, goodbye");
  // http://stackoverflow.com/questions/25615340/closing-libuv-handles-correctly
  uv_stop(uv_loop);
  uv_run(uv_loop, UV_RUN_DEFAULT);
  uv_walk(uv_loop, on_walk_cleanup, NULL);
  uv_run(uv_loop, UV_RUN_DEFAULT);
  uv_loop_close(uv_loop);
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
  printf("malloc1:%lu\n", suggested_size);
  buf->base = calloc(1, suggested_size);
  buf->len = suggested_size;
  printf("malloc2:%lu %p\n", buf->len, buf->base);
}

int main(int argc, char **argv) {
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

  uv_ip4_addr("0.0.0.0", 11000, &addr);

  status = uv_udp_bind(&server, (const struct sockaddr *)&addr, 0);
  UV_CHECK(status, "bind");

  status = uv_udp_recv_start(&server, on_alloc, on_recv);
  UV_CHECK(status, "recv");

  return uv_run(uv_loop, UV_RUN_DEFAULT);
}
