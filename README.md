# CSC574

Research project for Computer and Network Security
at North Carolina State University
Spring 2020

## Depedencies
* Python3
* pip3
* PyCryptodome

## [The paper](https://github.com/richardwsnyder/CSC574/blob/master/Snyder-final.pdf)

## Running
Make sure you've installed the dependencies first
```python
$ python3 -m pip install PyCryptodome
```
### Server
You can run the server instance that will listen on
global variable **HOST** at port **PORT**
```python
$ python3 server.py
```

### Client
There are two test files that were used to benchmark the performance of the server,
*testAddUserAndGetPerms* and *testBootstrap*. 

*testBootstrap* will attempt to connect to the node and become the first *master* user
in the table. If there is already a *master* user, the request will be rejected and that
user will have to issue you a delegation request.

*testAddUserAndGetPerms* will run a number of requests to add a new user with a unique
public key to the node with randomized permissions. The default permissions for *common* users
are all set to false and should be changed in the delegation request from the *master* users.

```python
$ python3 testBootstrap.py
$ python3 testAddUserAndGetPerms.py
```