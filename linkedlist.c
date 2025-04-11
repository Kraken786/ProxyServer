/*
    * linkedlist.c
    * Implementation of a simple singly linked list in C.
    * This file contains functions to create, append, delete, and print nodes in the linked list.
*/
#include <stdlib.h>
#include <stdio.h>
#include "linkedlist.h"

linked_list_t *create_linked_list(void) {
    linked_list_t *list = (linked_list_t *)malloc(sizeof(linked_list_t));
    if (list == NULL) {
        return NULL;
    }
    list->head = NULL;
    list->tail = NULL;
    return list;
}

void append_node(linked_list_t *list, void *data) {
    node_t *new_node = (node_t *)malloc(sizeof(node_t));
    if (new_node == NULL) {
        return;
    }
    new_node->data = data;
    new_node->next = NULL;

    if (list->head == NULL) {
        list->head = new_node;
        list->tail = new_node;
    } else {
        list->tail->next = new_node;
        list->tail = new_node;
    }
}

void delete_node(linked_list_t *list, void *data, int (*compare)(void*, void*)) {
    node_t *current = list->head;
    node_t *prev = NULL;

    // If head node itself holds the data to be deleted
    if (current != NULL && compare(current->data, data) == 0) {
        list->head = current->next;
        if (list->head == NULL) {
            list->tail = NULL;
        }
        free(current);
        return;
    }

    while (current != NULL && compare(current->data, data) != 0) {
        prev = current;
        current = current->next;
    }

    if (current == NULL) return;

    prev->next = current->next;
    if (prev->next == NULL) {
        list->tail = prev;
    }
    free(current);
}

void delete_linked_list(linked_list_t *list, void (*free_data)(void*)) {
    node_t *current = list->head;
    while (current != NULL) {
        node_t *temp = current;
        current = current->next;
        if (free_data) {
            free_data(temp->data);
        }
        free(temp);
    }
    free(list);
}

void print_linked_list(linked_list_t *list, void (*print_data)(void*)) {
    node_t *current = list->head;
    while (current != NULL) {
        if (print_data) {
            print_data(current->data);
            printf(" -> ");
        }
        current = current->next;
    }
    printf("NULL\n");
}