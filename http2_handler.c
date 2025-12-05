#include "http2_handler.h"
#include "logging.h"
#include "stats.h"
#include <nghttp2/nghttp2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#define MAKE_NV(NAME, VALUE)                                                   \
  {                                                                            \
    (uint8_t *)NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, sizeof(VALUE) - 1,    \
        NGHTTP2_NV_FLAG_NONE                                                   \
  }

typedef struct {
    int32_t stream_id;
    char *method;
    char *scheme;
    char *authority;
    char *path;
    char *user_agent;
} http2_stream_data_t;

static http2_stream_data_t *create_stream_data(int32_t stream_id) {
    http2_stream_data_t *data = malloc(sizeof(http2_stream_data_t));
    if (data) {
        memset(data, 0, sizeof(http2_stream_data_t));
        data->stream_id = stream_id;
    }
    return data;
}

static void free_stream_data(http2_stream_data_t *data) {
    if (data) {
        if (data->method) free(data->method);
        if (data->scheme) free(data->scheme);
        if (data->authority) free(data->authority);
        if (data->path) free(data->path);
        if (data->user_agent) free(data->user_agent);
        free(data);
    }
}

static ssize_t send_callback(nghttp2_session *session, const uint8_t *data,
                             size_t length, int flags, void *user_data) {
    (void)session; (void)flags;
    proxyClient_t *client = (proxyClient_t *)user_data;
    ssize_t sent = send(client->client_socket, data, length, 0);
    if (sent < 0) {
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
            return NGHTTP2_ERR_WOULDBLOCK;
        }
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    return sent;
}

static ssize_t recv_callback(nghttp2_session *session, uint8_t *buf,
                             size_t length, int flags, void *user_data) {
    (void)session; (void)flags;
    proxyClient_t *client = (proxyClient_t *)user_data;
    ssize_t received = recv(client->client_socket, buf, length, 0);
    if (received < 0) {
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
            return NGHTTP2_ERR_WOULDBLOCK;
        }
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    if (received == 0) {
        return NGHTTP2_ERR_EOF;
    }
    return received;
}

static int on_header_callback(nghttp2_session *session,
                              const nghttp2_frame *frame,
                              const uint8_t *name, size_t namelen,
                              const uint8_t *value, size_t valuelen,
                              uint8_t flags, void *user_data) {
    (void)flags; (void)user_data;
    if (frame->hd.type != NGHTTP2_HEADERS || frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
        return 0;
    }

    http2_stream_data_t *stream_data = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
    if (!stream_data) {
        stream_data = create_stream_data(frame->hd.stream_id);
        nghttp2_session_set_stream_user_data(session, frame->hd.stream_id, stream_data);
    }

    if (strncmp((char *)name, ":method", namelen) == 0) {
        stream_data->method = strndup((char *)value, valuelen);
    } else if (strncmp((char *)name, ":scheme", namelen) == 0) {
        stream_data->scheme = strndup((char *)value, valuelen);
    } else if (strncmp((char *)name, ":authority", namelen) == 0) {
        stream_data->authority = strndup((char *)value, valuelen);
    } else if (strncmp((char *)name, ":path", namelen) == 0) {
        stream_data->path = strndup((char *)value, valuelen);
    } else if (strncmp((char *)name, "user-agent", namelen) == 0) {
        stream_data->user_agent = strndup((char *)value, valuelen);
    }

    return 0;
}

static int on_frame_recv_callback(nghttp2_session *session,
                                  const nghttp2_frame *frame, void *user_data) {
    proxyClient_t *client = (proxyClient_t *)user_data;

    if (frame->hd.type == NGHTTP2_HEADERS && frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
        http2_stream_data_t *stream_data = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
        if (stream_data) {
            // Construct URL
            char url[2048];
            snprintf(url, sizeof(url), "%s://%s%s", 
                     stream_data->scheme ? stream_data->scheme : "http",
                     stream_data->authority ? stream_data->authority : "unknown",
                     stream_data->path ? stream_data->path : "/");

            LOG_INFO("HTTP/2 Request: %s %s", stream_data->method, url);

            // Record stats
            extern proxyServer_t *global_server;
            
            if (global_server && global_server->stats) {
                stats_record_visit(global_server->stats, url, client->peer_ip, "HTTP/2.0", stream_data->user_agent);
            }

            // Send simple response
            nghttp2_nv hdrs[] = {
                MAKE_NV(":status", "200"),
                MAKE_NV("content-type", "text/plain"),
            };
            
            nghttp2_data_provider data_prd;
            data_prd.read_callback = NULL; // No body for now, or static body

            nghttp2_submit_response(session, frame->hd.stream_id, hdrs, 2, NULL);
        }
    }
    return 0;
}

static int on_stream_close_callback(nghttp2_session *session, int32_t stream_id,
                                    uint32_t error_code, void *user_data) {
    (void)error_code; (void)user_data;
    http2_stream_data_t *stream_data = nghttp2_session_get_stream_user_data(session, stream_id);
    if (stream_data) {
        free_stream_data(stream_data);
    }
    return 0;
}

#define MAKE_NV(NAME, VALUE)                                                   \
  {                                                                            \
    (uint8_t *)NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, sizeof(VALUE) - 1,    \
        NGHTTP2_NV_FLAG_NONE                                                   \
  }

void handle_http2_connection(proxyClient_t *client, const char *initial_data, size_t initial_len) {
    nghttp2_session_callbacks *callbacks;
    nghttp2_session *session;

    nghttp2_session_callbacks_new(&callbacks);
    nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);
    nghttp2_session_callbacks_set_recv_callback(callbacks, recv_callback);
    nghttp2_session_callbacks_set_on_header_callback(callbacks, on_header_callback);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, on_frame_recv_callback);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, on_stream_close_callback);

    nghttp2_session_server_new(&session, callbacks, client);
    nghttp2_session_callbacks_del(callbacks);

    // Process initial data (preface)
    if (initial_len > 0) {
        ssize_t rv = nghttp2_session_mem_recv(session, (const uint8_t *)initial_data, initial_len);
        if (rv < 0) {
            LOG_ERROR("nghttp2_session_mem_recv failed: %s", nghttp2_strerror((int)rv));
            nghttp2_session_del(session);
            close(client->client_socket);
            return;
        }
    }

    // Send server connection preface
    nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, NULL, 0);

    // Event loop
    while (1) {
        if (nghttp2_session_recv(session) != 0) {
            break;
        }
        if (nghttp2_session_send(session) != 0) {
            break;
        }
        // Check if socket is closed? recv_callback handles EOF
    }

    nghttp2_session_del(session);
    close(client->client_socket);
}
