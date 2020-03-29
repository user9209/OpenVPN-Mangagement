# Client Configuration

## client-password.ovpn

For all clients the same data.



1. Replace

````
remote <vpn-server-dns-or-ip> <port>
````



2. Replace all `x...x`

```
<key>
-----BEGIN RSA PRIVATE KEY-----
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
-----END RSA PRIVATE KEY-----
</key>
<cert>
-----BEGIN CERTIFICATE-----
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
-----END CERTIFICATE-----
</cert>
<ca>
-----BEGIN CERTIFICATE-----
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
-----END CERTIFICATE-----
</ca>
<tls-auth>
-----BEGIN OpenVPN Static key V1-----
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
-----END OpenVPN Static key V1-----
</tls-auth>
```



## pw.txt

For each client an other value.

Replace

````
<username>
<password>
````

