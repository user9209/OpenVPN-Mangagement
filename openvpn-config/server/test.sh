#!/bin/bash

# run first:
# java -jar /etc/openvpn/script/OpenvpnLogin.jar add demo demo

export username=demo
export password=demo
java -jar /etc/openvpn/script/OpenvpnLogin.jar
if [ "$?" -eq "0" ]; then
    echo "Login success!"
else
    echo "Login failed!"
fi
