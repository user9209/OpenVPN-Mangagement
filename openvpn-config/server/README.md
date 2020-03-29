# Server Configuration

Place all files to `/etc/openvpn`!



## server-password.conf

1. Replace server port

````
port <port>
````

2. Check VPN-Network

````
server 10.44.0.0 255.255.255.0
````

3. Generate static key with `openvpn --genkey --secret ta.key`

````
<tls-auth>
-----BEGIN OpenVPN Static key V1-----
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
-----END OpenVPN Static key V1-----
</tls-auth>
````



## Keys

Replace content of `key-password`:

- ca.crt
- dh4096.pem
- server.pem

