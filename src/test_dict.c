#include <stdio.h>
#include "dtable.h"

#define SIZE 52

char *names_list[] = {"a\0", "b\0", "c\0", "d\0", 
		      "e\0", "f\0", "g\0", "h\0", 
		      "i\0", "j\0", "k\0", "l\0", 
		      "m\0", "n\0", "o\0", "p\0", 
		      "q\0", "r\0", "s\0", "t\0",
		      "u\0", "v\0", "w\0" ,"x\0", 
		      "y\0", "z\0", "aa\0", "asd\0",
                      "asdasd\0" ,"fsdfsd\0","sdg\0", "asdasd\0",
		      "ksjfjgf\0","askjaskd","mdfiik","fq",
		      "efu","plpsdaslo\0","8asdi2kjd\0", "wuqj\0", 
		      "lkwklm\0", "asmd=\0", "209ik\0", "ow0928if\0"
                      "ak4","5kasd^","^Q#$SD","!@#*DFGDFG",
		      "lskmdf#$5","234lksfd^","200,mlalf","1lklknnfifo",
		      "20--,l,c\0"};


char *names_list_out[] = {"23a\0", "sdfb\0", "cwef\0", "wefd\0", 
			  "123e\0", "ewrf\0", "wefg\0", "hwef\0", 
			  "123i\0", "dfgj\0", "wefk\0", "dfgl\0", 
			  "123m\0", "dfgn\0", "wefo\0", "pdfg\0", 
			  "123q\0", "asdr\0", "wefs\0", "tdfg\0",
			  "123u\0", "werv\0", "wwef\0" ,"xdfg\0", 
			  "123y\0", "dfgz\0", "awefa\0", "a34fsd\0",
			  "123asdasd\0" ,"fsdfdasdsweasdfd\0","sad123g\0", "asdfwefasd\0",
			  "123ksjfjgf\0","askjaasdasdskd","mdf12adasd3iik","f123q\0",
			  "123efu","plplo\0","8i2kjd\0", "wuq123j\0", 
			  "123lkwklm\0", "123asmd=\0", "209123ik\0", "ow0928if123\0"
			  "123ak4","1235kasd^","^123Q#$SD","!@#123*DFGDFG",
			  "123lskmdf#$5","123234lksfd^","200,mla123lf","1123lklknnfifo",
			  "12320--,l,c\0"};


int test_list_insert() {
  list_t *l = new_list();
  printf("TEST: list insert\n");
  for (int i = 0; i < SIZE; i++) {
    list_insert(l, names_list[i]);
  }

  list_node_t *current = l->list;
  printf("TEST: list delete\n");
  while ( current ) {
    list_node_t *next = current->next;
    current = list_remove(l, current->value);
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
  printf("TEST: table insert\n");
  for (int i = 0; i < SIZE; i++) {
    dict_insert(&d, names_list[i]);
  }
  printf("%s %d %d %d\n", __func__, __LINE__, d->N, d->size);
  dict_destroy(d);
  return 0;
}

int test_dict_member() {
  dict *d = new_dict();
  printf("TEST: table member\n");
  for (int i = 0; i < SIZE; i++) {
    dict_insert(&d, names_list[i]);
  }

  for (int i = 0; i < SIZE; i++) {
    int t = dict_member(d, names_list[i]);
    assert((t == 1));
  }
  
  for (int i = 0; i < SIZE; i++) {
    int t = dict_member(d, names_list_out[i]);
    if ( t ) {
      printf("%i %s\n", i, names_list_out[i]);
    }
    else {
      assert((t == 0));
    }
  }
  
  dict_destroy(d);
  return 0;
}


int test_dict_delete() {
  dict *d = new_dict();
  printf("TEST: table delete\n");
  for (int i = 0; i < SIZE; i++) {
    dict_insert(&d, names_list[i]);
  }

  for (int i = 0; i < SIZE; i++) {
    dict_delete(&d, names_list[i]);
  }
  dict_destroy(d);
  printf("%s %d %d %d\n", __func__, __LINE__, d->N, d->size);
  return 0;
}

int main(void) {
  assert( test_dict_insert() == 0);
  assert( test_dict_delete() == 0);
  assert( test_dict_member() == 0);
  return 0;
}
