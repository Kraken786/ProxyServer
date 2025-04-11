#ifndef __QUEUE_H__
#define __QUEUE_H__

#include <stdbool.h>
#include "linkedlist.h"

typedef struct {
    linked_list_t *list;
    int queue_size;
    int max_queue_size;
    void (*free_data)(void*);    // Function to free data
    void (*print_data)(void*);   // Function to print data
} queue_t;

// Create a new empty queue
queue_t *create_queue(int size, void (*free_data)(void*), void (*print_data)(void*));

// Add an element to the back of the queue
void enqueue(queue_t *queue, void *data);

// Remove and return the front element from the queue
void *dequeue(queue_t *queue);

// Check if the queue is empty
bool is_empty(queue_t *queue);

// Check if the queue is full
bool is_full(queue_t *queue);

// Get the front element without removing it
void *peek(queue_t *queue);

// Delete the queue and free memory
void delete_queue(queue_t *queue);

// Print the queue contents
void print_queue(queue_t *queue);

#endif