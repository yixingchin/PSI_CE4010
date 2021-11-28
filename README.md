# PSI_CE4010
PSI implementation, realising the paper "A More Efficient Cryptographic Matchmaking Protocol for Use in the Absence of a Continuously Available Third Party" [1] into an application. <br />

## Components:
- Client-Server Communication <br />
- Preprocessing of elements


## Dependencies:
- PyCrypto <br />
- numpy <br />
- socket <br />



## Construction of Server-Client based PSI
Server side: <br />

Client side: <br />

## User Guide:
- To use This PSI service, a server is required to generate encryption parameters and distribute them to PSI clients. To run a server: <br />
```python
from PSI_server import *

#if setting up a new server without environment instance
server = PSI_server(False, 64, 10002)
server.listen()

#if setting up a new server with environment instance
server = PSI_server(env, 64, 10002)
server.listen()

#instantiate a env
env = PSI.environment(64)
```





# References:
[1] 	C. Meadows, A More Efficient Cryptographic Matchmaking Protocol for Use in the Absence of a Continuously Available Third Party, 1986
