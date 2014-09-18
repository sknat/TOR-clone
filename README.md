Onion routing network
=====================

This project is a basic implementation of a TOR-like proxy,
It behaves as a SOCKS proxy routing the packets thourgh an encrypted level. It thus ensures anonymity and privacy of the communications.

* In its current version, it lacks at the implementation of meeting points, allowing as well end users as content providers to stay anonymous.
* A major issue is the certification of the network nodes. The safety of the whole network is based on the authority giving the list of the servers and their public keys. Anyone who can impersonnate this server could hypothetically take control over ones connection, something that Apple's messaging system has already experienced.

Licence
========
This code is provided as is under the GPL3 licence.
It should be only taken as a proof of concept.
Original authors are Michel Blancard and Nathan Skrzyczak



Principle
=========

Your computer (C) want to access the internet anonymously and privatly. It will want to create a tunnel of let's say three servers in which all its packets will go.

The cryptography is based on the RSA asymetric algorithm. The packets sent accross a tunnel of servers will be encrypted successivly with all the public keys of the servers on its way, and each one of them will decrypt the packet on the way so that each one only knows the node before and after him and only the last hop knows its content.

* (C) --Which are the available nodes?--> (certification authority)       
* C picks a random node sequence (N1) , (N2), (N3)
* (C) --[Open a tunnel to N2].N1key--> (N1)
* (C) --[[Open a tunnel to N3].N2key].N1key--> (N1) --[Open a tunnel to N3].N2key--> (N2)
* (C) --[[[Retrieve website.com].N3key].N2key].N1key--> (N1) --[[Retrieve website.com].N3key].N2key--> (N2) --[Retrieve website.com].N3key--> (N3) --Retrieve website.com--> (Website.com)

* (Website.com) --Website Content--> (N3) --[Website Content].N3key--> (N2) --[[Website Content].N3key].N2key--> (N1) --[[[Website Content].N3key].N2key].N1key--> (C)





Issues
======

SECURITY:
* a thread should be spawn before every blocking operation
* control inputs (particularly lengths to allocate)
* PORC handshake insecurity
* several porc sessions code

TODO :
* treat endianness correctly
* handle 'complete' field
* handle ctrl+C
* handle the 0 flux case correctly
* add timeouts to each field where complete=0
* verify memory allocation
* send PORC_STATUS_FAILURE when failures occurs
* converting sym key representation : issue when too small

* Close ORN sessions & SOCKS
* Client : accepting thread should only accept from listening socket
(add these commands to client_process_porc_packet)






