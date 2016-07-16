/*
  @author: Ben Mixon-Baca
  @email: bmixonb1@cs.unm.edu
 */

#include <stdlib.h>
#include "scanner.h"

char *make_random_address() {
  int result;
  struct random_data* buf = malloc(sizeof(struct random_data));
  int ret = random_r(buf, &result);
  return NULL;
}
