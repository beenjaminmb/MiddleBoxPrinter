#include <stdio.h>
#include "dtable.h"

int main(void) {
  dict *d = new_dict();
  int i = 0;
  printf("Dynamic hash table implementation test\n");
  for (;i < INIT_DICT_SIZE/2; i++) {
    dict_insert(d, &i);
  }
  printf("%s %d %d %d\n", __func__, __LINE__, d->N, d->size);
  for (;i < INIT_DICT_SIZE; i++) {
    dict_insert(d, i);
  }
  printf("%s %d %d %d\n", __func__, __LINE__, d->N, d->size);
  for (;i < INIT_DICT_SIZE*2; i++) {
    dict_insert(d, i);
  }
  printf("%s %d %d %d\n", __func__, __LINE__, d->N, d->size);
  return;
}
