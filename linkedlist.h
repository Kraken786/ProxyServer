#ifndef LINKEDLIST_H
#define LINKEDLIST_H

typedef struct node {
    void *data;           // Generic data pointer
    struct node *next;
} node_t;

typedef struct {
    node_t *head;
    node_t *tail;
} linked_list_t;

linked_list_t *create_linked_list(void);
void append_node(linked_list_t *list, void *data);
void delete_node(linked_list_t *list, void *data, int (*compare)(void*, void*));
void delete_linked_list(linked_list_t *list, void (*free_data)(void*));
void print_linked_list(linked_list_t *list, void (*print_data)(void*));

#endif // LINKEDLIST_H