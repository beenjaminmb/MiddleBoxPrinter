#include "util.h"
#include <stdlib.h>
list_head_t *new_list() {
  list_t *list = malloc(sizeof(list_t));
  list->next = list->end = list;
  list->data = NULL;
}

int list_empty(list_head_t *head){
  if (head) 
    return (head->next == head);
  else 
    return -1;
}

int list_append(list_head_t *head, void *data) {
  list_t *next = malloc(sizeof(list_t)); 

  return 0;
}

void list_destroy(list_head_t *list) {
  list_t *current = list->next;
  
  while ( current ) {
    
  }
}
void *list_remove(list_head_t *head) {
  return NULL;
}
