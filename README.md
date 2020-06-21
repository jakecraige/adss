# Adept Secret Sharing (ADSS)

A CLI tool and library implementation of dept secret sharing (ADSS) as described
by Bellare, Dai and Rogaway.

## Usage

### CLI

Install by downloading pre-build binaries on the releases pages or it install
from source with `go install github.com/jakecraige/adss`.

```sh
# Split the secret into a 2-of-3 sharing. First we create a file with the
# secret, it can be of any type, not just txt.
$ echo "some secret" > /tmp/secret.txt
$ bin/adss split -threshold 2 -count 3 -out-dir /tmp -secret-path secret.txt
Share written to: tmp/share-0.json
Share written to: tmp/share-1.json
Share written to: tmp/share-2.json
Complete.

# We can recover by providing all shares. It prints to stdout in base64 by
# default, so we decode it with base64 for this example.
$ bin/adss recover --share-paths /tmp/share-0.json,/tmp/share-1.json,/tmp/share-2.json | base64 -d
some secret

# We can also store the result in a file
$ bin/adss recover --share-paths /tmp/share-0.json,/tmp/share-1.json,/tmp/share-2.json -out-path /tmp/recovered-secret.txt
$ cat /tmp/recovered-secret.txt
some secret

# We can also recover by providing only two
$ bin/adss recover --share-paths /tmp/share-0.json,/tmp/share-1.json | base64 -d
some secret

# If we manually modify the secret value of one of the shares and attempt
# recovery, we are warned about the invalid share but we still recover it.
$ bin/adss recover --share-paths /tmp/share-0.json,/tmp/share-1.json,/tmp/share-2-modified.json | base64 -d
WARN: Invalid share at ./tmp/share-2-modified.json
some secret
```

### Library

```golang
// Split the secret into shares. The shares can be json serialized with the
// golang marshaller to be persisted on disk.
as := adss.NewAccessStructure(2, 3)
secret := []byte("the secret")
ad := []byte("the associated data")
shares, err := adss.Share(as, secret, ad)
if err != nil {
  return err
}

// Given a set of shares, attempt to recover the secret. If it can be recovered
// it returns the secret and the set of shares that were valid inputs. If it
// cannot be recovered, an error is returned.
secret, validShares, err := adss.Recover(shares)
if err != nil {
  return err
}

fmt.Printf("%s", secret)
if len(validShares) < len(shares) {
  fmt.Println("Some shares were invalid")
}
```

## Security

This is a work-in-progress implementation and should not be used in any
production systems. It _does not_ currently match the paper so it does not
provide many of the guarantees required by ADSS. It has also received no
security reviews so it should not be trusted until it has.
