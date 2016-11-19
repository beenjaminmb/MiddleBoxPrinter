/**
 * @author: Ben Mixon-Baca
 * @email: bmixonb1@cs.unm.edu
 */

#include "main.h"
#include "scanner.h"

#define BLACKLIST_FILE "blacklist.conf"

int main(int argc, char *argv[])
{
  struct scan_args_t scan_args = {
    .blacklist = BLACKLIST_FILE
  };
  int ret = scanner_main_loop(&scan_args);
  return ret;
}
