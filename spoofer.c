#include <stdlib.h>
#include "spoofer.h"

static spoofer_t *spoofer;

spoofer_packet_t *new_packet()
{
  spoofer_packet_t *packet = malloc(sizeof(spoofer_packet_t));
  return packet;
}

spoofer_t *new_spoofer_singleton() 
{
  spoofer = malloc(sizeof(spoofer_t));
}

int 
spoofer_main_loop()
{
  return 0;
}
