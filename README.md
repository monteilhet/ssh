# ssh

## ssh key generation

    ssh-keygen -t rsa [-f key_filename] [-C comment] [-N ""]

```bash
# generate key pair rsakey, rsakey.pub without passphrase
ssh-keygen -t rsa -f rsakey -N ""

```

## ssh tips

- How do I retrieve the public key from a SSH private key?

```bash
ssh-keygen -y -f id_rsa.am
```

- How do I retrieve md5 fingerprint from public key ?


```bash
ssh-keygen -E md5 -lf  public_key
```