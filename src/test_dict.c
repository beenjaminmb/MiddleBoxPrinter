#include <stdio.h>
#include "dtable.h"


char *names_list[] = {"a\0","b\0", "c\0", "d\0", "e\0", "f\0", "g\0", "h\0", "i\0", "j\0",
		      "k\0", "l\0", "m\0", "n\0", "o\0", "p\0" "q\0", "r\0", "s\0", "t\0",
		      "u\0", "v\0", "w\0" ,"x\0", "y\0", "z\0" ,"\0"};

int main(void) {
  dict *d = new_dict();
  int i = 0;
  printf("Dynamic hash table implementation test\n");
  for (;i < INIT_DICT_SIZE/2; i++) {
    dict_insert(d, names_list[i]);
  }
  printf("%s %d %d %d\n", __func__, __LINE__, d->N, d->size);
  for (;i < INIT_DICT_SIZE; i++) {
    dict_insert(d, names_list[i]);
  }
  printf("%s %d %d %d\n", __func__, __LINE__, d->N, d->size);
  for (;i < INIT_DICT_SIZE*2; i++) {
    dict_insert(d, names_list[i]);
  }
  printf("%s %d %d %d\n", __func__, __LINE__, d->N, d->size);
  return 0;
}
