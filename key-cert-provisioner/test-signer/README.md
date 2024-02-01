# test-signer

This is a test signer that approves and signs any CSR for a given signer name. It is not suitable for production systems.

To use it:

```bash
kubectl apply -f test-signer/test-signer.yaml 
kubectl create secret generic test-signer-ca --from-file=tls.crt=<tls.crt> --from-file=tls.key=<tls.key> -n test-signer
```
