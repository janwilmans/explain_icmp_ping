# explain_icmp_ping
example implementations of icmp ping in C and C++

These are working examples that try to be as easy to read and correct as possible.
The focus is not on adding lots of features but on explaining (by example) how ICMP ping works.

![image](https://github.com/janwilmans/explain_icmp_ping/assets/5933444/56858c03-5eab-421c-8520-11312e185e33)

these are the highlevel steps involed:

- create a RAW socket specifing ICMP as protocol
- resolve the hostname to an address if needed
- create ICMP packet of type 8 (Echo)
   - fill the payload (optional)
   - calculate the checksum 
- record the start time
- send out the packet
- wait for a ICMP type 0 (Reply) 
- record the end time
- check the Id byte to make sure it is a reply to _our_ Echo packet.
- if the Id byte is not a match, wait for another packet if the timeout was not reached yet
- print the result

Note: because we use raw sockets we will see a 20-byte ip-header prefixed to the ICMP Reply.


more information:
- https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
- https://gursimarsm.medium.com/customizing-icmp-payload-in-ping-command-7c4486f4a1be
  
