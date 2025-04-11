/*
    Implementation of a queue using a linked list.
    This file contains functions to create, enqueue, dequeue, check if empty/full,
    peek at the front element, delete the queue, and print the queue contents.
    The queue is implemented using a singly linked list.
    The queue supports dynamic sizing, meaning it can grow and shrink as needed.
*/

#include <stdio.h>
#include <stdlib.h>
#include "queue.h"
#include "logging.h"

queue_t *create_queue(int size, void (*free_data)(void*), void (*print_data)(void*)) {
    queue_t *queue = (queue_t *)malloc(sizeof(queue_t));
    if (queue == NULL) {
        return NULL;
    }
    queue->list = create_linked_list();
    queue->queue_size = 0;
    queue->max_queue_size = size;
    queue->free_data = free_data;
    queue->print_data = print_data;
    
    if (queue->list == NULL) {
        free(queue);
        return NULL;
    }
    return queue;
}

void enqueue(queue_t *queue, void *data) {
    if (queue == NULL || queue->list == NULL || is_full(queue)) {
        return;
    }
    append_node(queue->list, data);
    queue->queue_size++;
}

void *dequeue(queue_t *queue) {
    if (is_empty(queue)) {
        return NULL;
    }
    
    void *data = queue->list->head->data;
    node_t *temp = queue->list->head;
    queue->list->head = queue->list->head->next;
    
    if (queue->list->head == NULL) {
        queue->list->tail = NULL;
    }
    
    free(temp);
    queue->queue_size--;
    return data;
}

bool is_empty(queue_t *queue) {
    return (queue == NULL || queue->list == NULL || queue->queue_size == 0);
}

bool is_full(queue_t *queue) {
    if (queue && queue->list) {
        return (queue->queue_size >= queue->max_queue_size);
    }
    
    return true;
}

void *peek(queue_t *queue) {
    if (is_empty(queue)) {
        return NULL;
    }
    return queue->list->head->data;
}

void delete_queue(queue_t *queue) {
    if (queue == NULL) {
        return;
    }
    if (queue->list != NULL) {
        delete_linked_list(queue->list, queue->free_data);
    }
    free(queue);
}

void print_queue(queue_t *queue) {
    if (is_empty(queue)) {
        printf("Queue is empty\n");
        return;
    }
    printf("Queue: ");
    print_linked_list(queue->list, queue->print_data);
}