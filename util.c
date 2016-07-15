#include "util.h"
#include <stdlib.h>
list_t *new_list() {
  list_t *list = malloc(sizeof(list_t));
  list->next = list->end = list;
  list->data = NULL;
}

int list_empty(list_t *head){
  if (head) 
    return (head->next == head);
  else 
    return -1;
}

int list_append(list_t *head, void *data) {
  list_t *next = malloc(sizeof(list_t)); 
  next->next = head->end;
  head->end = next;
  next->end = head->end;
  head->next = next;

  return 0;
}

void list_destroy(list_t *list) {
  list_t *current = list->next;
  
  while ( current ) {
    
  }
}
void *list_remove(list_t *head) {
  return NULL;
}
