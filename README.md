# Heartbleed

A command-line utility to scan hosts for CVE-2014-0160 OpenSSL Heartbleed Bug.

Forked from https://github.com/FiloSottile/Heartbleed.

## usage

```text
$ go run bleed.go -service <SERVICE> <HOST>[:PORT]
```

Possible values of SERVICE are: https, ftp, smtp, pop3 or imap.  The latter four
use StartTLS.

Possible values of HOST are hostname or ipv4 address.

If PORT is not specified, 443 is assumed.  For the StartTLS protocols, you must
specify the appropriate port otherwise 443 will be used.

Possible values of exit status are `0` - SAFE, `1` - VULNERABLE, or `2` - ERROR.

## example

```text
$ go run bleed.go -service https 192.168.1.1:443
 00000000  02 00 4f 68 65 61 72 74  62 6c 65 65 64 2e 66 69  |..Oheartbleed.fi|
 00000010  6c 69 70 70 6f 2e 69 6f  20 59 45 4c 4c 4f 57 20  |lippo.io YELLOW |
 00000020  53 55 42 4d 41 52 49 4e  45 20 31 39 32 2e 31 36  |SUBMARINE 192.16|
 00000030  38 2e 31 23 31 31 34 34  33 24 61 ff ff ff ff ff  |8.1.1:443$a.....|
 00000040  b1 f8 b9 fb 89 c9 08 40  a7 6d f1 10 35 4f 75 cc  |.......@.m..5Ou.|
 00000050  c4 bd 89 05 2d a8 37 bc  49 a5 cd 3c c9 fe 44 97  |....-.7.I..<..D.|
 00000060  92 2a                                             |.*|
}

2014/04/19 16:24:07 192.168.1.1:443 - VULNERABLE
exit status 1
```

## installation

You will need Go 1.2.x, otherwise you get `undefined: cipher.AEAD` and other errors

```
go get github.com/LucaFilipozzi/Heartbleed
go install github.com/LucaFilipozzi/Heartbleed
```

