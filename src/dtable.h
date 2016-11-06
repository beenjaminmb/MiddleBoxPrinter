#ifndef _DTABLE_
#define _DTABLE_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define INIT_DICT_SIZE 8 

static unsigned long make_key(void *value, int right);

typedef struct list_t {
  struct list_t *prev;
  struct list_t *next;
  void *value;
} list_t;


list_t * new_list(void *value){
  list_t *l = malloc(sizeof(list_t));
  l->prev = NULL;
  l->next = NULL;
  l->value = value;
  return l;
}

void list_insert(list_t *list, void *value)
{
  
  if (list->next == NULL){
    list_t *current = new_list(value);
    
    list->next = current;
    current->prev = list;
    current->next = NULL;
    return ;
  }
  list_insert(list->next, value);
  return ;
}

list_t* list_find(list_t *list, void *value)
{
  if (value == NULL) return NULL;
  if (list->next == NULL) {
    if (list->value == value) return list;
    else return NULL;
  }
  else if ( list->value == value) return list;
  else return list_find(list->next, value);
}

list_t* list_remove(list_t *list, void *value){
  list_t *l = list_find(list, value);
  if (l == NULL) return NULL; // The list didn't contain the element.
  if (l->prev == NULL && l->next == NULL) { // One element list
    goto FINISH;
  }
  if (l->prev == NULL) { // This is the head of the list.
    l->next->prev = NULL;
    l->next = NULL;
    goto FINISH;
  }
  else if (l->next == NULL) {// This is the tail of the list.
    l->prev->next = NULL;
    l->prev = NULL;
    goto FINISH;
  }
 FINISH:
  return l;
}

typedef struct hash_table
{
  list_t *elements; // A ballanced tree of elements.
  int size; // Current max size of table
  int N; // Number of elements currently in the hash table
} dict;


dict *new_dict()
{
  dict *ndict = malloc(sizeof(dict));
  ndict->elements = malloc(INIT_DICT_SIZE * sizeof(list_t));
  ndict->N = 0;
  ndict->size = INIT_DICT_SIZE;
  return ndict;
}

int dict_insert(dict *d, void *value) 
{
  int N = d->N + 1;
  int size = d->size;
  d->N = N;
  unsigned long key = make_key(value, size);
  if (((float)N/(float)d->size) <= 3/4.0) {
    list_insert(&(d->elements[key]), value);
  }
  else {
    dict *dd = malloc( size * 2 * sizeof(list_t) );
    dd->N = N;
    dd->size = size;
    list_t *current = &(d->elements[0]);
    for (int i = 0; i < N; i++) {
      for (current = &(d->elements[i]); current != NULL;) {
	current = list_remove(&(d->elements[i]), current->value);
	key = make_key(current->value, size*2);
	list_insert(&(dd->elements[key]), current->value);
	free(current);
      }
    }
    return 0;
  }
}

int dict_delete(dict *d, void *value){
//left is always zero, right is the parameter
  int N = d->N - 1;
  int size = d->size;
  unsigned long key = make_key(value, size);
  if (((float) N)/((float) size) >= 1/4.0) { // We haven't reached the desired load factor.
    list_insert(&(d->elements[key]), value);
    return 0;
  }
  else { // We are lower than the desired load factor.
    dict *dd = malloc( (size / 2) * sizeof(list_t));
    dd->N = N;
    dd->size = size/2;
    list_t *current = &(d->elements[0]);
    for (int i = 0; i < N; i++) {
      for (current = &(d->elements[i]); current != NULL;) {
	current = list_remove(&(d->elements[i]), current->value);
	key = make_key(current->value, size/2);
	list_insert(&(dd->elements[key]), current->value);
	free(current);
      }
    }
    return 0;
  }
}

static unsigned long make_key(void *value, int right)
{
  char *str = malloc(sizeof("0xffffffffffffffff") + 1);
  sscanf(str, "%s", value);
  
  printf("%s %d %s %p\n", __func__, __LINE__, str, value);
  unsigned long hash = 5381;
  int c;
  while (c = *str++)
    hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
  free(str);
  return (unsigned long)(hash % right);
}

#endif /* _DTABLE_ */
