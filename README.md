# PSI_CE4010
PSI implementation, realising the paper "A More Efficient Cryptographic Matchmaking Protocol for Use in the Absence of a Continuously Available Third Party" [1] into an application. <br />
Private Set Intersection is basically a cryptographic technique that allows for two parties to compare encrypted versions of their personal set and reveal ONLY the intersection. 
Hence,  neither party reveals anythings to the other except for the intersection.


## Components:
- Motivation for Project
- Dependencies
- Client-Server Communication <br />
- Preprocessing of elements

## Motivation for Project
Grab and Gojek are competitors in the transport industry. Despite being competitors, they still want to identify drivers who are double-dipping on both platforms. Therefore, there is a motivation not to reveal their private set of phone numbers to one another. Private Set Intersection enables the comparison of both private sets and shows only the intersection. <br />

We've decided to implement our PSI using an extension of Diffie Hellman as the encryption technique. Comparing it to Homomorphic Encryption, the main plus point is that we do not need a third party to keep the set secrets. Set secrets are kept locally and server can only 'ask' clients for the secret. Intersections are also only revealed to clients and not to the server.

## Dependencies:
- PyCrypto <br />
- numpy <br />
- socket <br />


## Construction of Server-Client based PSI
Server side operations: <br />
- The server only listens for communication requests from client

Client side: <br />
Most operations are done over at the client's side:
- Apply/Check Signature
- Encryption/Decryption
- Hashing

## User Guide:
- To use This PSI service, a server is required to generate encryption parameters and distribute them to PSI clients. To run a server: <br />
```python
#if setting up a new server without environment instance
server = PSI_server(False, 64, 10002) # replace 10002 with the port you wish the server to listen on
server.listen()

#if setting up a new server with environment instance
server = PSI_server(env, 64, 10002)
server.listen()

#instantiate a env
env = PSI.environment(64)
```
- Moreover, the server acts as a trusted source of each parties' public key. Except from that, server does not have a role in intersection. <br />
- For each client participating in PSI, instantiate a PSI_client object. <br />
```python
# In one thread
bob = PSI_client(10001, "127.0.0.1", 10002)               # the last two parameters specifies the server
bob.prepare([5,9,11,17,3,25,20,31,76,4,77,125,91,42,99])  # replace with you list of integers

# In another thread
alice = PSI_client(10000, "127.0.0.1", 10002)
alice.prepare([1,3,5,7,9, 67,4,91,66,83,12,19,37,76,55])
```
- Now, one client starts to listen for intersection requests, after which the other sends out a request. <br />
```python
# In one thread
bob.listen("127.0.0.1", 10000)              # listening from alice on port 10000

# In another thread. Notice the listen() method is blocking!
alice.request_intersect("127.0.0.1", 10001) # requesting bob on port 10001
```
- The intersection is done. <br />
```python
alice.intersection
>>> [76, 91, 4, 3, 5, 9]
bob.intersection
>>> [76, 91, 4, 3, 5, 9]
```
# References:
[1] 	C. Meadows, A More Efficient Cryptographic Matchmaking Protocol for Use in the Absence of a Continuously Available Third Party, 1986
