Onion routing network
=====================

This project is a basic implementation of a TOR-like proxy,
It behaves as a SOCKS proxy routing the packets thourgh an encrypted level. It thus ensures anonymity and privacy of the communications.

* In its current version, it lacks at the implementation of meeting points, allowing as well end users as content providers to stay anonymous.
* A major issue is the certification of the network nodes. The safety of the whole network is based on the 


Principle
=========

Let's say your computer (C) want to access the internet anonymously and privatly. It will want to create a tunnel, let's say of three servers in which all its packets will go

(C) ---> (certification authority) 








Issues
======

SECURITY:
* a thread should be spawn before every blocking operation
* control inputs (particularly lengths to allocate)
* PORC handshake insecurity
* several porc sessions code

TODO :
* ajouter la license GPL2
* treat endianness correctly
* handle 'complete' field
* handle ctrl+C
* handle the 0 flux case correctly
* add timeouts to each field where complete=0
* verify memory allocation
* send PORC_STATUS_FAILURE when failures occurs
* converting sym key representation : issue when too small

* Close PORC & SOCKS
* Client : accepting thread should only accept from listening socket
(add these commands to client_process_porc_packet)






