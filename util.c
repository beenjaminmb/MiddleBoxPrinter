
/* A replicating multiple producer/multiple consumer ring buffer.
 *
 * - A global head pointer points to the main head of the FIFO
 * - A global tail pointer points to the NEXT FREE ITEM in FIFO
 * - head == tail means the FIFO is empty - writing to the tail will fill in 
 *   the head
 * - tail + 1 == head means that the FIFO is full (yes, we waste one entry)
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "util.h"

int ringbuffer_full(ringbuffer_t *rb)
{
  ringbuffer_cell_t *next = rb->tail + 1;// because of how I call it.
  if (next >= rb->end)
    next = rb->buf;

  return next == rb->head; // full buffer
}

int ringbuffer_empty(ringbuffer_t *rb)
{
  return (rb->head == rb->tail);
}

int Ringbuffer_append_single(ringbuffer_t *rb, void *item)
{
  ringbuffer_cell_t *next = rb->tail + 1;
   
  if (next >= rb->end)
    next = rb->buf;

  if (next == rb->head) // full buffer
    return -1;

  rb->tail->value = item;
  write_barrier(); /* Make sure that the item is set before tail
		    * is updated by us - this is only needed in the 
		    * lock-free case. If we use pthread locks and such,
		    * the need for this goes away. */
  rb->tail = next;
  return 0;
}

int ringbuffer_remove_single(ringbuffer_t *rb, void **item)
{
  ringbuffer_cell_t *curr;

  /* Check that the ring's not empty */
  if (rb->head == rb->tail) // empty buffer
    return -1;

  /* get the item we want and advance the per-thread head. Beause
   * this is all per-thread, there are no atomicity problems
   * here. */
  *item = rb->head->value;
  curr = rb->head + 1;
  if (curr >= rb->end)
    rb->head = rb->buf;
  else
    rb->head = curr;

  return 0;
}

int ringbuffer_destroy(ringbuffer_t *rb)
{
  if (rb->buf) free(rb->buf);
  return 0;
}

/* Initialize a ringbuffer, giving the length in entries */
int ringbuffer_init(ringbuffer_t *rb, int len)
{
  rb->head = rb->tail = rb->buf 
    = malloc(len * sizeof(ringbuffer_cell_t));
  rb->end = rb->buf+len;
  return 0;
}
