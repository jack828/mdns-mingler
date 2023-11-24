# mdns-mingler

## TODO DOCS

libuv1-dev



Allow multiple hostnames to resolve to the same (or not) IP address in mDNS

Read more including installation and usage with Traefik on my blog <https://jackburgess.dev/blog/truenas-apps-access-via-mdns>

## Usage

```
docker run jack828/mdns-mingler:latest -v ./hosts:/hosts:ro -p 5353:5353
```

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

This can support it really easily but I am scared of it but will accept a PR.

# Author

[Jack Burgess](https://jackburgess.dev)

# License

MIT
