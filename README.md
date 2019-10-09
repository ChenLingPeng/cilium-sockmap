# cilium-sockmap

is a project inspired by cilium to accelerate istio network using ebpf sockops & sockhash. 

# how to test

1. build envoy image under envoy directory(or just pull image [chenlingpeng/envoy-demo](https://hub.docker.com/r/chenlingpeng/envoy-demo))
2. setup test container (simulate istio pod with an envoy sidecar in one network space)

```bash
CID=$(docker run -d chenlingpeng/envoy-demo)
CID2=$(docker run -d --net container:$CID fortio/fortio:latest_release server -http-port "127.0.0.1:8080")

ip=$(docker inspect -f '{{.NetworkSettings.Networks.bridge.IPAddress}}' $CID)
```

3. run load tests

```bash
# traffic direct from client to fortio server
docker exec -it $CID2 fortio load -c 1 -qps 10000 -t 10s -a -r 0.00005 -httpbufferkb=128 "127.0.0.1:8080/echo?size=1024"

# traffic send to envoy which then proxy to fortio server
docker exec -it $CID2 fortio load -c 1 -qps 10000 -t 10s -a -r 0.00005 -httpbufferkb=128 "$ip:10000/echo?size=1024"
```

4. clean env

```bash
docker stop $CID $CID2
```

5. run `./load.sh` and re-run step 2 to step 4, compare the latance and qps result. run `./unload.sh` to clean ebpf settings after step 4.

# what would you see

when traffic send direct from client to fortio server using `127.0.0.1:8080` the qps in ebpf mode is better than normal case(in my vm it's 8000+(sockops) vs 6000+(no-sockops)).

when traffic send to envoy which then proxy to fortio server using `$ip:10000` the qps in ebpf mode drop sharply compare to normal case(in my vm it's 200+(sockops) vs 4000+(no-sockops))
