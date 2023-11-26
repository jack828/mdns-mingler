# mdns-mingler

Allow multiple hostnames to resolve to the same (or not) IP address in mDNS

Read more including installation and usage with Traefik on my blog <https://jackburgess.dev/blog/truenas-apps-access-via-mdns>

## Usage

```
docker run jack828/mdns-mingler:latest -v ./hosts:/hosts:ro --network=host
```

This NEEDS host networking enabled because of limitations with how Linux kernels provide [support for multicast routing](https://github.com/moby/libnetwork/issues/2397#issuecomment-935029813).

## Hosts

An example hosts file is found in the [repo](./hosts). Note that the parser is very primitive and fragile.

Hosts are accepted in the format:

```
ip           hostname
```

e.g.

```
192.168.1.10   plex.local
192.168.1.10   sonarr.local
192.168.111.11 somethingelse.local
```

## IPv6

This can support it fairly easily but I am scared of it but will accept a PR. I also spent far too long on this and don't have IPv6 network to test on.

## Development

You'll need:

 - GCC
 - Make
 - Libuv (as in libuv1-dev)
 - argp
 - Sanity (/s)

A watcher facility is provided using nodemon, because I am most familiar with it.

See the [Makefile](./Makefile) for commands etc.

# Author

[Jack Burgess](https://jackburgess.dev)

# License

MIT
