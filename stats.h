#ifndef STATS_H
#define STATS_H

#include "linkedlist.h"
#include <pthread.h>

typedef struct {
    char *url;
    char *client_ip;
    char *protocol;
    char *user_agent;
    int visit_count;
} visited_site_t;

typedef struct {
    linked_list_t *sites_list;
    pthread_mutex_t stats_mutex;
} stats_manager_t;

stats_manager_t *stats_manager_create();
void stats_manager_destroy(stats_manager_t *manager);
void stats_record_visit(stats_manager_t *manager, const char *url, const char *client_ip, const char *protocol, const char *user_agent);
void stats_print(stats_manager_t *manager);
void stats_dump(stats_manager_t *manager, int fd);
void stats_clear(stats_manager_t *manager);

#endif
