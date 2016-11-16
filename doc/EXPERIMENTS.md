#Experimental Design

##Phase 1 Exploration & Experiments

1. Generate IP datagrams with random IP address.

2. Randomly initialize the Layer 4 protocol to TCP, UDP, ICMP, Other. 
   with some probability.

3. Send packets out.

4. Simultaneously collect probes and responses.

##Phase 2
Once scanner is finished sending phase 1 probes, wait some amount of 
time and then stop packet capturing.

1. Read the capture file in.

2. Seperate the packets in probes and responses.

3. 