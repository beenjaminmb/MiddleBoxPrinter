#include <assert.h>
#include "ssocket.h"

ssize_t ssendto(int sockfd, const void *buf, size_t len, int flags,
		const struct sockaddr *dest_addr, socklen_t addrlen){

  return sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

ssize_t ssendn(int sockfd, const void *buf, size_t len, int flags,
	       const struct sockaddr *dest_addr, socklen_t addrlen,
	       int n) {

  ssize_t ret = 0;
  for (int i = 0; i < n; i++) {
    ret += ssendto(sockfd, buf, len, flags, dest_addr, addrlen);
  }
  return ret;
}

ssize_t ssendto_fn(int sockfd, const void *buf, size_t len, int flags,
		   const struct sockaddr *dest_addr, socklen_t addrlen,
		   packet_fn f){
  int ret = f(buf);
  assert(ret == 0);
  return ssendto(sockfd, buf, len, flags, dest_addr, addrlen);
}


ssize_t ssendn_fn(int sockfd, const void *buf, size_t len,
		  int flags, const struct sockaddr *dest_addr,
		  socklen_t addrlen, int n, packet_fn f) {
  int ret = f(buf);
  assert(ret == 0);
  return ssendn(sockfd, buf, len, flags, dest_addr, addrlen, n);
}
