
/* A replicating multiple producer/multiple consumer ring buffer.
 *
 * - A global head pointer points to the main head of the FIFO
 * - A global tail pointer points to the NEXT FREE ITEM in FIFO
 * - head == tail means the FIFO is empty - writing to the tail will fill in 
 *   the head
 * - tail + 1 == head means that the FIFO is full (yes, we waste one entry)
 */


/* int ringbuffer_full(ringbuffer_t *rb) */
/* { */

/*   ringbuffer_cell_t *next = rb->tail + 1;// because of how I call it. */

/*   if (next >= rb->end) */
/*     next = rb->buf; */

/*   return next == rb->head; // full buffer */
/* } */

/* int ringbuffer_empty(ringbuffer_t *rb) */
/* { */
/*   return (rb->head == rb->tail); */
/* } */

/* int ringbuffer_append_single(ringbuffer_t *rb, void *item) */
/* { */
/*   pthread_mutex_lock(rb->rb_lock); */
/*   while (next == rb->head) { // full buffer */
/*     pthread_cond_wait(rb->rb_full, rb->rb_lock); */
/*   } */

/*   ringbuffer_cell_t *next = rb->tail + 1; */
   
/*   if (next >= rb->end) */
/*     next = rb->buf; */

/*   rb->tail->value = item; */

  
/*   rb->tail = next; */
  
/*   pthread_cond_signal(rb->rb_empty); */
/*   pthread_mutex_unlock(rb->rb_lock); */
/*   return 0; */
/* } */

/* int ringbuffer_remove_single(ringbuffer_t *rb, void **item) */
/* { */

/*   pthread_mutex_lock(rb->rb_lock); */
  
/*   /\* Check that the ring's not empty *\/ */
/*   while (rb->head == rb->tail){ // empty buffer */
/*     pthread_cond_wait(rb->rb_empty, rb->rb_lock); */
/*   } */
/*   ringbuffer_cell_t *curr; */
/*   /\* get the item we want and advance the per-thread head. Beause */
/*    * this is all per-thread, there are no atomicity problems */
/*    * here. *\/ */
/*   *item = rb->head->value; */
/*   curr = rb->head + 1; */
/*   if (curr >= rb->end) */
/*     rb->head = rb->buf; */
/*   else */
/*     rb->head = curr; */
  
/*   pthread_cond_signal(rb->rb_full); */
/*   pthread_mutex_unlock(rb->rb_lock); */

/*   return 0; */
/* } */

/* int ringbuffer_destroy(ringbuffer_t *rb) */
/* {   */
/*   if (rb->buf) { */
/*     free(rb->rb_lock); */
/*     free(rb->rb_empty); */
/*     free(rb->rb_full); */
/*     free(rb->buf); */
/*   } */
/*   return 0; */
/* } */

/* /\* Initialize a ringbuffer, giving the length in entries *\/ */
/* int ringbuffer_init(ringbuffer_t *rb, int len) */
/* { */
/*   rb->head = rb->tail = rb->buf  */
/*     = malloc(len * sizeof(ringbuffer_cell_t)); */
/*   rb->end = rb->buf+len; */
  
/*   rb->rb_lock = malloc(sizeof(pthread_mutex_t)); */
/*   pthread_mutex_init(rb->rb_lock, NULL); */

/*   rb->rb_empty = malloc(sizeof(pthread_cond_t)); */
/*   pthread_mutex_init(rb->rb_empty, NULL); */

/*   rb->rb_full = malloc(sizeof(pthread_cond_t)); */
/*   pthread_mutex_init(rb->rb_full, NULL); */

/*   return 0; */
/* } */
