/**
 * @author: Ben Mixon-Baca
 * @email: bmixonb1@cs.unm.edu
 */

#include "main.h"
#include "scanner.h"
#include "util.h"
#ifndef DILLINGER
 #define BLACKLIST_FILE "blacklist.conf"
#else
 #define BLACKLIST_FILE "/vagrant/blacklist.conf"
#endif

int main(int argc, char *argv[])
{
  struct scan_args_t scan_args;
  parse_args(argc, argv, &scan_args);
  char str[] = "/vagrant/blacklist.conf\0";
  scan_args.blacklist = &str;
  int ret = scanner_main_loop(&scan_args);
  return ret;
}
