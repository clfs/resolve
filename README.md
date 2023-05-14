# resolve

A toy DNS resolver. It's a Go port of Julia Evans' [Implement DNS in a weekend][0] guide.

Install or upgrade:

```text
go install github.com/clfs/resolve/cmd/resolve@latest
```

Uninstall:

```text
rm -i $(which resolve)
```

Usage:

```text
$ resolve
Usage of resolve:
  -domain string
        domain to lookup
  -record-type string
        record type to lookup (default "A")
```

Example:

```text
$ resolve -domain twitter.com
2023/05/14 16:39:50 querying 198.41.0.4 for twitter.com
2023/05/14 16:39:50 querying 192.12.94.30 for twitter.com
2023/05/14 16:39:50 querying 198.41.0.4 for a.r06.twtrdns.net
2023/05/14 16:39:50 querying 192.12.94.30 for a.r06.twtrdns.net
2023/05/14 16:39:50 querying 205.251.195.207 for a.r06.twtrdns.net
2023/05/14 16:39:50 querying 205.251.192.179 for twitter.com
2023/05/14 16:39:50 104.244.42.65
```

[0]: https://implement-dns.wizardzines.com/