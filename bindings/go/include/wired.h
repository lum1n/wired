/* C ABI for Wired. Implemented in crates/wired-ffi. */
#ifndef WIRED_H
#define WIRED_H

#include <stdint.h>

typedef struct WiredNode WiredNode;
typedef struct WiredListener WiredListener;

/* Calls returning int: 0 = ok, -1 = error with a message in *err (free with wired_string_free). */
void wired_string_free(char *s);

/* relay_url/relay_bind (nullable): serve a relay behind a TLS-terminating proxy. */
int wired_join(const char *name, const char *invite, const char *state_dir, int ephemeral,
               const char *relay_url, const char *relay_bind, WiredNode **out, char **err);
/* Relay: behind a proxy when relay_url/relay_bind are set; none when no_relay;
   otherwise public on port (qad_port < 0 disables address discovery).
   replica_of (nullable): invite of the network to replicate. */
int wired_anchor(const char *name, const char *bind_host, uint16_t port, int32_t qad_port,
                 const char *public_host, const char *replica_of, int no_relay,
                 const char *relay_url, const char *relay_bind, const char *state_dir, int ephemeral,
                 WiredNode **out, char **err);

char *wired_node_name(const WiredNode *n);
char *wired_node_id(const WiredNode *n);
char *wired_node_invite(const WiredNode *n);
int wired_node_is_root(const WiredNode *n);
/* One member per line: name<TAB>id<TAB>anchor|member. */
char *wired_members(const WiredNode *n);

/* Root only. *invite receives the new invite (free with wired_string_free). */
int wired_revoke(const WiredNode *n, const char *name, char **invite, char **err);
int wired_rotate_invite(const WiredNode *n, char **invite, char **err);
/* One relay per line: url<TAB>pinned|ca. */
char *wired_relays(const WiredNode *n);
int wired_add_relay(const WiredNode *n, const char *url, char **err);
int wired_remove_relay(const WiredNode *n, const char *url, char **err);
int wired_approve_anchor(const WiredNode *n, const char *id, char **err);

/* Blocks; *fd receives a non-blocking socket descriptor owned by the caller. */
int wired_dial(const WiredNode *n, const char *target, int *fd, char **err);
/* 0 = no connection, 1 = direct, 2 = relay. */
int wired_path(const WiredNode *n, const char *peer);

/* allow (nullable): comma-separated node names that may connect.
   NULL allows every member; "" allows nobody. */
int wired_listen(const WiredNode *n, const char *service, const char *allow, WiredListener **out, char **err);
/* Blocks; 0 = stream in *fd, 1 = listener closed, -1 = error. */
int wired_accept(const WiredListener *l, int *fd, char **peer_name, char **peer_id, char **err);
void wired_listener_close(const WiredListener *l);
void wired_listener_free(WiredListener *l);

void wired_node_close(const WiredNode *n);
void wired_node_free(WiredNode *n);

#endif
