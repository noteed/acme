# Let's Encrypt ACME protocol

This is a simple Haskell script to obtain a certificate from [Let's
Encrypt](https://letsencrypt.org/) using their ACME protocol.


- The main source of information to write this was
  https://github.com/diafygi/letsencrypt-nosudo

- The ACME spec: https://letsencrypt.github.io/acme-spec/

Most values are still hard-coded for my initial attempt (i.e. my email address
and a domain of mine).


## Discover the URL for letsencrypt ACME endpoints

API endpoints are listed at https://acme-v01.api.letsencrypt.org/directory and
are currently hard-coded in the script.

```
> curl -s https://acme-v01.api.letsencrypt.org/directory | json_pp 
{
   "new-cert" : "https://acme-v01.api.letsencrypt.org/acme/new-cert",
   "new-authz" : "https://acme-v01.api.letsencrypt.org/acme/new-authz",
   "revoke-cert" : "https://acme-v01.api.letsencrypt.org/acme/revoke-cert",
   "new-reg" : "https://acme-v01.api.letsencrypt.org/acme/new-reg"
}
```


## Generate user account keys

You need an account with Let's Encrypt to ask and receive certificates for your
domains. The account is controlled by a public/private key pair:

```
openssl genrsa 4096 > user.key
openssl rsa -in user.key -pubout > user.pub
```


## Generate nonces


Each request to the API have a nonce to prevent replays. The nonce is currently
hard-coded in the script. New nonces can be obtained from letsencrypt with

```
> generate-nonce.sh
```


## Create user account

Generate `registration.body` by using the `acme.hs` script then POST it to
letsencrypt (note it assumes you agree to their subscriber agreement):

```
> curl -s -X POST --data-binary "@registration.body" \
  https://acme-v01.api.letsencrypt.org/acme/new-reg | json_pp
{
   "agreement" : "https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf",
   "contact" : [
      "mailto:noteed@gmail.com"
   ],
   "key" : {
      "e" : "...",
      "kty" : "RSA",
      "n" : "..."
   },
   "id" : 36009,
   "createdAt" : "2015-12-04T14:22:08.321951547Z",
   "initialIp" : "80.236.245.73"
}
```


## Request a challenge


Let's Encrypt needs a proof that you control the claimed domain. You can
request a challenge with `challenge-request.body`.

```
> curl -s -X POST --data-binary "@challenge-request.body" \
  https://acme-v01.api.letsencrypt.org/acme/new-authz | json_pp
{
   "expires" : "2015-12-21T18:44:52.331487674Z",
   "challenges" : [
      {
         "status" : "pending",
         "uri" : "https://acme-v01.api.letsencrypt.org/acme/challenge/vXZ1UnZ-y1q7sntnf6NdOfbPAwetJFBqOtvp7FHCjaU/1844047",
         "type" : "tls-sni-01",
         "token" : "oielAbB7MdyCl29mqjzlqGdrCQSB8SyJaxHbAgQBA7Q"
      },
      {
         "uri" : "https://acme-v01.api.letsencrypt.org/acme/challenge/vXZ1UnZ-y1q7sntnf6NdOfbPAwetJFBqOtvp7FHCjaU/1844048",
         "status" : "pending",
         "type" : "http-01",
         "token" : "DjyJpI3HVWAmsAwMT5ZFpW8dj19cel6ml6qaBUeGpCg"
      }
   ],
   "identifier" : {
      "type" : "dns",
      "value" : "aaa.reesd.com"
   },
   "combinations" : [
      [
         0
      ],
      [
         1
      ]
   ],
   "status" : "pending"
}
```

The script assumes you'll answer the challenge by hosting a file at a location
chosen by Let's Encrypt. Extract the token for the `http-01` challenge and run
the script again. Now you have to host the file at the location reported by the
script.

Once this is done, you can ask Let's Encrypt to check the file.

```
> curl -s -X POST --data-binary "@challenge-response.body" \
  https://acme-v01.api.letsencrypt.org/acme/challenge/vXZ1UnZ-y1q7sntnf6NdOfbPAwetJFBqOtvp7FHCjaU/1844048 | json_pp
{
   "token" : "DjyJpI3HVWAmsAwMT5ZFpW8dj19cel6ml6qaBUeGpCg",
   "keyAuthorization" : "DjyJpI3HVWAmsAwMT5ZFpW8dj19cel6ml6qaBUeGpCg.EJe0KReqzCUq6leNOerMC9naZSHxP9TJzGxCcsGkNrw",
   "type" : "http-01",
   "uri" : "https://acme-v01.api.letsencrypt.org/acme/challenge/vXZ1UnZ-y1q7sntnf6NdOfbPAwetJFBqOtvp7FHCjaU/1844048",
   "status" : "pending"
}
```

The same URL can then be polled until the status becomes valid.


## Send CSR / Receive certificate

The CSR is created with:

```
> openssl genrsa 4096 > domain.key
> openssl req -new -sha256 -key domain.key -subj "/CN=aaa.reesd.com" > aaa.reesd.com.csr
> openssl req -in aaa.reesd.com.csr -outform DER > aaa.reesd.com.csr.der
```

And the signed certificate can be obtained from Let's Encrypt:

```
> curl -s -X POST --data-binary "@csr-request.body" \
  https://acme-v01.api.letsencrypt.org/acme/new-cert > aaa.reesd.com.cert.der
```


## Create a certificate for HAProxy

Including explicit DH key exchange parameters to prevent Logjam attack
(https://weakdh.org/).

```
> openssl x509 -inform der -in aaa.reesd.com.cert.der \
    -out aaa.reesd.com.cert.pem
> openssl dhparam -out aaa.reesd.com-dhparams.pem 2048
> cat aaa.reesd.com.cert.pem \
    lets-encrypt-x1-cross-signed.pem \
    aaa.reesd.com.key \
    aaa.reesd.com-dhparams.pem > aaa.reesd.com-combined.pem
```
