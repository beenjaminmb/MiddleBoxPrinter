#include "util.h"
#include "blacklist.h"

int init_blacklist(char *blacklist)
{
  blacklist_init(NULL, blacklist, NULL, 0, NULL, 0, 0);
  return EXIT_SUCCESS;
}
