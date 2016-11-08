#include <stdio.h>
#include "dtable.h"


char *names_list[] = {"a\0", "b\0", "c\0", "d\0", 
		      "e\0", "f\0", "g\0", "h\0", 
		      "i\0", "j\0", "k\0", "l\0", 
		      "m\0", "n\0", "o\0", "p\0", 
		      "q\0", "r\0", "s\0", "t\0",
		      "u\0", "v\0", "w\0" ,"x\0", 
		      "y\0", "z\0", "aa\0"};


int test_list_insert() {
  list_t *l = new_list();
  printf("TEST: list insert\n");
  for (int i = 0; i < 26; i++) {
    list_insert(l, names_list[i]);
  }

  list_node_t *current = l->list;
  printf("TEST: list delete\n");
  while ( current ) {
    list_node_t *next = current->next;
    current = list_remove(l, current->value);
    printf("current->value = %s\n", ((char* )current->value));
    if (current->next != NULL) {
      printf("ERROR: next pointer is not NULL\n");
    }
    if (current->prev != NULL) {
      printf("ERROR: prev pointer is not NULL\n");
    }
    free(current);
    current = next;
  }
  free(l);
  return 0;
}

int test_dict_insert() {
  dict *d = new_dict();
  printf("Dynamic hash table implementation test\n");
  for (int i = 0; i < 26; i++) {
    printf("i = %d\n", i);
    dict_insert(&d, names_list[i]);
  }
  dict_destroy(d);
  printf("%s %d %d %d\n", __func__, __LINE__, d->N, d->size);

}
int main(void) {
  test_list_insert();

  return 0;
}
