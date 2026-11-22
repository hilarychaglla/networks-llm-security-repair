
## Medición de red desde la EC2 (ejecutada el 2026-10-11)

```
2606:4700:7::f3 api.openai.com
2a06:98c1:58::f3 api.openai.com
dns=0.001791s tcp_acumulado=0.003311s tls_acumulado=0.017337s total=0.111258s http=401
```

## Medición adicional (2026-11-22)
```
162.159.140.245 STREAM api.openai.com
162.159.140.245 DGRAM  
162.159.140.245 RAW    
172.66.0.243    STREAM 
dns=0.000715s tcp_acumulado=0.002614s tls_acumulado=0.016413s total=0.106172s http=401
* ALPN: curl offers h2,http/1.1
* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384 / x25519 / id-ecPublicKey
* ALPN: server accepted h2
*   subject: CN=api.openai.com
*   issuer: C=US; O=Google Trust Services; CN=WE1
< HTTP/2 401 
```
