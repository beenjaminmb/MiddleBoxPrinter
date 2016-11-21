/**
 * @author: Ben Mixon-Baca
 * @email: bmixonb1@cs.unm.edu
 */
#ifndef _DTABLE_
#define _DTABLE_

#define INIT_DICT_SIZE 8
/* Doubly linked list structure */
typedef struct list_node_t {
  struct list_node_t *prev;
  struct list_node_t *next;
  void *value;
} list_node_t;

/* Sentenial node to be the actual list.*/
typedef struct list_t {
  list_node_t *list;
  int size;
} list_t;

/* Wrapper to the actual hash table. */
typedef struct hash_table
{
  list_t **elements; // A ballanced tree of elements.
  int size; // Current max size of table
  int N; // Number of elements currently in the hash table
} dict_t;

/* A user-defined key/hashing function. */
typedef unsigned long (*key_fn)(void *, int, void*);
/* User defined freeing function. */
typedef unsigned long (*free_fn)(void *);

/* User defined equality function. */
typedef int (*equal_fn)(void *v1, void *v2);

/* User defined deep copy function. */
typedef void* (*copy_fn)(void *value);

typedef void (*map_fn)(void *value, void *args, void *ret);

list_t *clone_list_fn(list_t *l1, copy_fn copy);

/**
 * Malloc's and returns a new dynamic hash table. 
 * @return: a pointer to the dynamic hash table.
 */
list_t * new_list();
/**
 * @param l: Pointer to list.
 * @return: 1 if the list is empty and 0 otherwise.
 */
int list_empty(list_t *l);

/**
 * This function mallocs a new list_node_t, sets its value
 * field equal to value, appends this node to the head of l.
 */
int list_insert(list_t *l, void *value);

/**
 *
 */
list_node_t* list_find(list_t *l, void *value);

/**
 *
 */
list_node_t *list_find_fn(list_t *l, void *value, equal_fn equal);

/**
 *
 */
list_node_t* list_remove(list_t *l, void *value);

/**
 *
 */
list_node_t* list_remove_fn(list_t *l, void *value, equal_fn equal);

/**
 * @warning: FUNCTION NOT YET IMPLEMENTED. IT WILL DUMP CORE.
 */
list_node_t *list_merge(list_t *l1, list_t *l2);

/**
 * Default key generating algorithm. 
 */
unsigned long make_key(void *value, int right, void *args);

/**
 * Default equality function using logical equals of two
 * pointer addresses.
 */
int logical_equal(void *v1, void *v2);

/**
 *
 */
dict_t *new_dict();

/**
 *
 */
dict_t *new_dict_size(int dict_size);

/**
 *
 */
int dict_insert(dict_t **dp, void *value);

/**
 *
 */
int dict_insert_fn(dict_t **dp, void *value,
		   key_fn hash_fn, void *args,
		   free_fn ufree);

/**
 *
 */
int dict_delete(dict_t **dp, void *value);

/**
 *
 */
int dict_delete_fn(dict_t **dp, void *value, key_fn hash_fn, 
		   void *args, free_fn ufree, equal_fn equal);

/**
 *
 */
int dict_member(dict_t *d, void *value);

/**
 * 
 */
int dict_member_fn(dict_t *d, void *value, key_fn hash_fn,
		   void *args, equal_fn equal);

/**
 * 
 */
void* dict_get_value(dict_t *d, void *value);

/**
 * 
 */
void* dict_get_value_fn(dict_t *d, void *value, key_fn hash_fn,
			void *args, equal_fn equal);

/**
 * Will delete the dictionary and all of the lists it 
 * is composed of. Does not free the values inside each of the 
 * list nodes.
 *
 * @param d: Pointer to the dict_t to be destroyed.
 * @return: 0 upon completion. Always returns 0.
 */
int dict_destroy(dict_t  *d);

/**
 * Destroy a dictionary and apply a user defined free function
 * to each of the elements in the hash table linked lists.
 * @param d: Pointer to the dict_t to be destroyed.
 *
 * @param ufree: Function pointer to a user-defined destruction
 * function. It will be applied to everyone member of the list value
 * pointers instead of freeing only the list_node_t pointers.
 * 
 * @return: 0 upon completion. *should* always return 0.
 */
int dict_destroy_fn(dict_t  *d, free_fn ufree);

/**
 * Frees the list elements if the value in the dictionary is a list.
 */
unsigned long free_list(void *list);

/**
 * Function useful for 
 */
int dict_map(dict_t *d, map_fn f, void *args, void *ret);
#endif /* _DTABLE_ */
