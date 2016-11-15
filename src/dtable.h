/**
 * @author: Ben Mixon-Baca
 * @email: bmixonb1@cs.unm.edu
 */
#ifndef _DTABLE_
#define _DTABLE_

#define INIT_DICT_SIZE 8

typedef struct list_node_t {
  struct list_node_t *prev;
  struct list_node_t *next;
  void *value;
} list_node_t;

typedef struct list_t {
  list_node_t *list;
  int size;
} list_t;

typedef struct hash_table
{
  list_t **elements; // A ballanced tree of elements.
  int size; // Current max size of table
  int N; // Number of elements currently in the hash table
} dict_t;

list_t * new_list();
int list_empty(list_t *l);
int list_append_helper(list_t *l, void *value);
int list_insert(list_t *l, void *value);
list_node_t* list_find(list_t *l, void *value);
list_node_t* list_remove(list_t *l, void *value);
list_node_t* list_find_helper(list_node_t *list, void *value);
list_node_t* list_remove_helper(list_node_t *l, void *value);

typedef unsigned long (*key_fn)(void *, int);
unsigned long make_key(void *value, int right);

dict_t *new_dict();
dict_t *new_dict_size(int dict_size);
int dict_insert(dict_t **dp, void *value);
int dict_insert_fn(dict_t **dp, void *value, key_fn hash_fn);
int dict_delete(dict_t **dp, void *value);
int dict_delete_fn(dict_t **dp, void *value, key_fn hash_fn);
int dict_member(dict_t *d, void *value);
int dict_member_fn(dict_t *d, void *value, key_fn hash_fn);
int dict_destroy(dict_t  *d);

#endif /* _DTABLE_ */
