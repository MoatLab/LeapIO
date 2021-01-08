### SOCP README ###

#### Usage ####

(1). For LocalSSD:

- sudo ./socp client pcie 2>&1 | tee pc.log

(2). For RDMASSD: use ss-mlx.sh for running server and sc-mlx.sh for running
RDMA client

i.e.,

- server: ./ss-mlx.sh
- client: ./sc-mlx.sh

(3). For TCPSSD: use ss-tcp.sh for running server and sc-tcp.sh for running
TCP client

i.e.,

- server: ./ss-tcp.sh
- client: ./sc-tcp.sh


#### Others ####

To recompile the code:

```
   # for debugging version (w/ printing msgs)
   $ ./b d

OR

  # for release version (w/o printing msgs, no assert())
  $ ./b r
```
