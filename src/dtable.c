#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "dtable.h"

unsigned long make_key(void *value, int right);

int list_empty(list_t *l)
{
  return (l->size == 0); 
}

list_t * new_list(){
  list_t *l = malloc(sizeof(list_t));
  l->list = NULL;
  l->size = 0;
  return l;
}

int list_insert(list_t *l, void *value) {
  assert( (l != NULL) );
  l->size += 1;
  if ( l->list == NULL ) {
    l->list = malloc(sizeof(list_node_t));
    l->list->next = NULL;
    l->list->prev = NULL;
    l->list->value = value;
    return 0;
  }
  else {
    return list_append_helper(l, value);
  }
}

int list_append_helper(list_t *l, void *value)
{
  list_node_t *next = l->list;
  list_node_t *current = malloc(sizeof(list_node_t));
  current->value = value;
  next->prev = current;
  l->list = current;
  current->next = next;
  current->prev = NULL;
  return 0;
}

list_node_t* list_find(list_t *l, void *value) {
  list_node_t *element = list_find_helper(l->list, value);
  return element;
}

list_node_t* list_find_helper(list_node_t *list, void *value)
{
  if (list == NULL) return NULL;
  if (list->next == NULL) {
    if (list->value == value) return list;
    else return NULL;
  }
  else if ( list->value == value) return list;
  else return list_find_helper(list->next, value);
}

list_node_t* list_remove(list_t *l, void *value){
  l->size -= 1;
  list_node_t *element = list_find(l, value);
  if (l->list == element) {
    l->list = element->next;
  }
  element = list_remove_helper(element, value);  
  return element;
}

list_node_t* list_remove_helper(list_node_t *l, void *value){
  if (l == NULL) return NULL; // The list didn't contain the element.
  list_node_t *next = l->next;
  list_node_t *prev = l->prev;
  if (next != NULL && prev != NULL) {
    l->next = NULL;
    l->prev = NULL;
    next->prev = prev;
    prev->next = next;
    return l;
  }
  else if (prev == NULL && next == NULL) { // One element list
    goto FINISH;
  }
  else if (prev == NULL) { // This is the head of the list.
    next->prev = NULL;
    l->next = NULL;
    goto FINISH;
  }
  else if (next == NULL) {// This is the tail of the list.
    prev->next = NULL;
    l->prev = NULL;
    goto FINISH;
  }
 FINISH:
  return l;
}

dict_t *new_dict_size(int dict_size)
{
  dict_t *ndict = malloc(sizeof(dict_t));
  ndict->elements = malloc(dict_size * sizeof(list_t));
  ndict->N = 0;
  ndict->size = dict_size;
  for (int i = 0; i < dict_size; i++) {
    ndict->elements[i] = new_list();
  }
  return ndict;
}


dict_t *new_dict()
{
  dict_t *ndict = malloc(sizeof(dict_t));
  ndict->elements = malloc(INIT_DICT_SIZE * sizeof(list_t));
  ndict->N = 0;
  ndict->size = INIT_DICT_SIZE;
  for (int i = 0; i < INIT_DICT_SIZE; i++) {
    ndict->elements[i] = new_list();
  }
  return ndict;
}

int dict_insert(dict_t **dp, void *value) 
{
  return dict_insert_fn(dp, value, ((key_fn)make_key));
}
  /* dict_t *d = *dp; */
  /* int N = d->N + 1; */
  /* int size = d->size; */
  /* d->N = N; */
  /* unsigned long key = make_key(value, size); */
  /* if (((float)N/(float)d->size) <= 3/4.0) { */
  /*   return list_insert( d->elements[key], value); */
  /* } */
  /* else { */
  /*   dict_t *dd = malloc(sizeof(dict_t)); */
  /*   dd->elements = malloc( size * 2 * sizeof(list_t) );  */
  /*   dd->N = N; */
  /*   dd->size = size * 2; */
  /*   for (int i = 0; i < size * 2; i++) { */
  /*     dd->elements[i] = new_list(); */
  /*   } */

  /*   for (int i = 0; i < size; i++) { */
  /*     list_t *l = d->elements[i]; */
  /*     list_node_t *current = l->list; */
  /*     while ( current ) { */
  /* 	list_node_t *tmp = current->next; */
  /* 	key = make_key(current->value, size * 2); */
  /* 	list_insert(dd->elements[key], current->value); */
  /* 	current = tmp; */
  /*     } */
  /*   } */
  /*   dict_destroy(d); */
  /*   d = NULL; */
  /*   *dp = dd; */
  /*   return dict_insert(dp, value); */
  /* } */
/* } */


int dict_insert_fn(dict_t **dp, void *value, key_fn hash_fn) 
{
  dict_t *d = *dp;
  int N = d->N + 1;
  int size = d->size;
  d->N = N;
  unsigned long key = hash_fn(value, size);
  if (((float)N/(float)d->size) <= 3/4.0) {
    return list_insert( d->elements[key], value);
  }
  else {
    dict_t *dd = malloc(sizeof(dict_t));
    dd->elements = malloc( size * 2 * sizeof(list_t) ); 
    dd->N = N;
    dd->size = size * 2;
    for (int i = 0; i < size * 2; i++) {
      dd->elements[i] = new_list();
    }

    for (int i = 0; i < size; i++) {
      list_t *l = d->elements[i];
      list_node_t *current = l->list;
      while ( current ) {
	list_node_t *tmp = current->next;
	key = hash_fn(current->value, size * 2);
	list_insert(dd->elements[key], current->value);
	current = tmp;
      }
    }
    dict_destroy(d);
    d = NULL;
    *dp = dd;
    return dict_insert_fn(dp, value, hash_fn);
  }
}

int dict_delete(dict_t **dp, void *value)
{
  return dict_delete_fn(dp, value, ((key_fn)make_key));
}
/* //left is always zero, right is the parameter */
/*   dict_t *d = *dp; */
/*   int N = d->N - 1; */
/*   int size = d->size; */
/*   unsigned long key = make_key(value, size); */
/*   if (((float) N)/((float) size) >= 1/4.0) { */
/*     // We haven't reached the desired load factor. */
/*     list_node_t *l = list_remove(d->elements[key], value); */
/*     free(l); */
/*     return 0; */
/*   } */
/*   else { // We are lower than the desired load factor. */
/*     int new_size = ((size / 2) >= INIT_DICT_SIZE) ?  */
/*       (size / 2) : INIT_DICT_SIZE; */
/*     dict_t *dd = malloc(sizeof(dict_t)); */
/*     dd->elements = malloc( new_size * sizeof(list_t) );  */
/*     dd->N = N; */
/*     dd->size = new_size; */
/*     for (int i = 0; i < new_size; i++) { */
/*       dd->elements[i] = new_list(); */
/*     } */
    
/*     for (int i = 0; i < size; i++) { */
/*       list_t *l = d->elements[i]; */
/*       list_node_t *current = l->list; */
/*       while ( current ) { */
/* 	list_node_t *tmp = current->next; */
/* 	key = make_key(current->value, new_size); */
/* 	list_insert(dd->elements[key], current->value); */
/* 	current = tmp; */
/*       } */
/*     } */
/*     dict_destroy(d); */
/*     d = NULL; */
/*     *dp = dd; */
/*     return dict_delete(dp, value); */
/*   } */
/* } */

int dict_delete_fn(dict_t **dp, void *value, key_fn hash_fn)
{
  dict_t *d = *dp;
  int N = d->N - 1;
  int size = d->size;
  unsigned long key = hash_fn(value, size);
  if (((float) N)/((float) size) >= 1/4.0) {
    // We haven't reached the desired load factor.
    list_node_t *l = list_remove(d->elements[key], value);
    free(l);
    return 0;
  }
  else { // We are lower than the desired load factor.
    int new_size = ((size / 2) >= INIT_DICT_SIZE) ? 
      (size / 2) : INIT_DICT_SIZE;
    dict_t *dd = malloc(sizeof(dict_t));
    dd->elements = malloc( new_size * sizeof(list_t) ); 
    dd->N = N;
    dd->size = new_size;
    for (int i = 0; i < new_size; i++) {
      dd->elements[i] = new_list();
    }
    
    for (int i = 0; i < size; i++) {
      list_t *l = d->elements[i];
      list_node_t *current = l->list;
      while ( current ) {
	list_node_t *tmp = current->next;
	key = hash_fn(current->value, new_size);
	list_insert(dd->elements[key], current->value);
	current = tmp;
      }
    }
    dict_destroy(d);
    d = NULL;
    *dp = dd;
    return dict_delete_fn(dp, value, hash_fn);
  }
}

int dict_destroy(dict_t  *d) {
  int size = d->size;
  for (int i = size-1; i >= 0; i--) {
    if ( d && d->elements && d->elements[i] != NULL ) {
      list_t *l = d->elements[i];
      list_node_t *current = l->list;
      if (current == NULL) {
	free(d->elements[i]->list);
      }
      else { 
	while ( current ) {
	  list_node_t *tmp = current->next;
	  free(current);
	  current = tmp;
	}
      }
      free(l);
    }
  }
  free(d->elements);
  free(d);
  return 0;  
}

int dict_member(dict_t *d, void *value)
{
  return dict_member_fn(d, value, ((key_fn)make_key));
  /* unsigned long key = make_key(value, d->size); */
  /* list_node_t *l = list_find(d->elements[key], value); */
  /* int ismember = l ? (l->value == value) : 0; */
  /* return ismember; */
}

int dict_member_fn(dict_t *d, void *value, key_fn hash_fn)
{
  unsigned long key = hash_fn(value, d->size);
  list_node_t *l = list_find(d->elements[key], value);
  int ismember = l ? (l->value == value) : 0;
  return ismember;
}

/**
 * Generate a hash in [0, right). The corner case if value is null is to
 * return 0. This could be very bad if we have a lot of null values which
 * SHOULD NEVER happen.
 */
unsigned long make_key(void *value, int right)
{
  if (value == NULL)
    return 0;
  char *str = malloc(sizeof("0xffffffffffffffff\0") + 1);
  sscanf(value, "%s", str);
  unsigned long hash = 5381;
  int c;
  char *tmp = str;
  while ( (c = *tmp++) )
    hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
  free(str);
  if (right)
    return (unsigned long)(hash % right);
  else
    return 0;
}
