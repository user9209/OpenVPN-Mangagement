#!/bin/bash
cd out/artifacts/OpenvpnLogin_jar/
export username=demo
export password=demo
# java -jar OpenvpnLogin.jar update demo demo
java -jar OpenvpnLogin.jar
if [ "$?" -eq "0" ]; then
    echo "Login success!"
else
    echo "Login failed!"
fi
cd ../../../