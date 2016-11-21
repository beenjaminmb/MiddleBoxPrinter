#ifndef _SSOCKET_
#define  _SSOCKET_

#include <sys/types.h>
#include <sys/socket.h>

/**
 * Generic function applied to a packet before it is sent.
 *
 * @param: Takes the packet buffer. Assumed to start at Layer 3.
 * @return: Return 0 on success. There are assertion checks to ensure
 * that if the function is not succesfully applied the program
 * will dump core.
 */
typedef int (*packet_fn)(const void *buf);

typedef enum layer {
  one, two, three, four
} layer_e;

typedef enum l4field {} l4field_e;

ssize_t ssendto(int sockfd, const void *buf, size_t len, int flags,
		const struct sockaddr *dest_addr, socklen_t addrlen);

ssize_t ssendn(int sockfd, const void *buf, size_t len, int flags,
	       const struct sockaddr *dest_addr, socklen_t addrlen,
	       int n);

ssize_t ssendn_fn(int sockfd, const void *buf, size_t len, 
		  int flags, const struct sockaddr *dest_addr,
		  socklen_t addrlen, int n, packet_fn f);

ssize_t ssendto_fn(int sockfd, const void *buf, size_t len, int flags,
		   const struct sockaddr *dest_addr, socklen_t addrlen,
		   packet_fn f);

#endif /* _SSOCKET_ */
