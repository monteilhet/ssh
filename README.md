# ssh

## ssh tips

- How do I retrieve the public key from a SSH private key?

```bash
ssh-keygen -y -f id_rsa.am
```

- How do I retrieve md5 fingerprint from public key ?


```bash
ssh-keygen -E md5 -lf  public_key
```