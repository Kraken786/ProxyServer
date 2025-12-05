#include "stats.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

stats_manager_t *stats_manager_create() {
    stats_manager_t *manager = malloc(sizeof(stats_manager_t));
    if (!manager) return NULL;
    manager->sites_list = create_linked_list();
    if (!manager->sites_list) {
        free(manager);
        return NULL;
    }
    if (pthread_mutex_init(&manager->stats_mutex, NULL) != 0) {
        delete_linked_list(manager->sites_list, NULL);
        free(manager);
        return NULL;
    }
    return manager;
}

void free_visited_site(void *data) {
    visited_site_t *site = (visited_site_t *)data;
    if (site) {
        free(site->url);
        free(site->client_ip);
        if (site->protocol) free(site->protocol);
        if (site->user_agent) free(site->user_agent);
        free(site);
    }
}

void stats_manager_destroy(stats_manager_t *manager) {
    if (!manager) return;
    pthread_mutex_lock(&manager->stats_mutex);
    delete_linked_list(manager->sites_list, free_visited_site);
    pthread_mutex_unlock(&manager->stats_mutex);
    pthread_mutex_destroy(&manager->stats_mutex);
    free(manager);
}

void stats_record_visit(stats_manager_t *manager, const char *url, const char *client_ip, const char *protocol, const char *user_agent) {
    if (!manager || !url || !client_ip) return;

    pthread_mutex_lock(&manager->stats_mutex);
    
    node_t *current = manager->sites_list->head;
    int found = 0;
    while (current) {
        visited_site_t *site = (visited_site_t *)current->data;
        if (strcmp(site->url, url) == 0 && strcmp(site->client_ip, client_ip) == 0) {
            site->visit_count++;
            // Update protocol/UA if changed? For now, keep first seen or overwrite?
            // Let's overwrite to keep latest info
            if (site->protocol) free(site->protocol);
            if (site->user_agent) free(site->user_agent);
            site->protocol = protocol ? strdup(protocol) : NULL;
            site->user_agent = user_agent ? strdup(user_agent) : NULL;
            found = 1;
            break;
        }
        current = current->next;
    }

    if (!found) {
        visited_site_t *new_site = malloc(sizeof(visited_site_t));
        if (new_site) {
            new_site->url = strdup(url);
            new_site->client_ip = strdup(client_ip);
            new_site->protocol = protocol ? strdup(protocol) : NULL;
            new_site->user_agent = user_agent ? strdup(user_agent) : NULL;
            new_site->visit_count = 1;
            
            if (new_site->url && new_site->client_ip) {
                append_node(manager->sites_list, new_site);
            } else {
                // Handle allocation failure
                if (new_site->url) free(new_site->url);
                if (new_site->client_ip) free(new_site->client_ip);
                if (new_site->protocol) free(new_site->protocol);
                if (new_site->user_agent) free(new_site->user_agent);
                free(new_site);
            }
        }
    }

    pthread_mutex_unlock(&manager->stats_mutex);
}

void print_visited_site(void *data) {
    visited_site_t *site = (visited_site_t *)data;
    printf("URL: %s, IP: %s, Visits: %d\n", site->url, site->client_ip, site->visit_count);
}

void stats_print(stats_manager_t *manager) {
    if (!manager) return;
    stats_dump(manager, STDOUT_FILENO);
}

void stats_dump(stats_manager_t *manager, int fd) {
    if (!manager) return;
    pthread_mutex_lock(&manager->stats_mutex);
    dprintf(fd, "\n--- Visited Sites Stats ---\n");
    
    node_t *current = manager->sites_list->head;
    while (current) {
        visited_site_t *site = (visited_site_t *)current->data;
        dprintf(fd, "URL: %s, IP: %s, Proto: %s, UA: %s, Visits: %d\n", 
                site->url, 
                site->client_ip, 
                site->protocol ? site->protocol : "N/A",
                site->user_agent ? site->user_agent : "N/A",
                site->visit_count);
        current = current->next;
    }
    
    dprintf(fd, "---------------------------\n");
    pthread_mutex_unlock(&manager->stats_mutex);
}

void stats_clear(stats_manager_t *manager) {
    if (!manager) return;
    pthread_mutex_lock(&manager->stats_mutex);
    
    // Delete all nodes
    delete_linked_list(manager->sites_list, free_visited_site);
    
    // Re-create the list
    manager->sites_list = create_linked_list();
    
    pthread_mutex_unlock(&manager->stats_mutex);
}
