#!/bin/bash
export username=demo
export password=demo
# java -jar out/artifacts/OpenvpnLogin_jar/OpenvpnLogin.jar update demo demo
java -jar out/artifacts/OpenvpnLogin_jar/OpenvpnLogin.jar
if [ "$?" -eq "0" ]; then
    echo "Login success!"
else
    echo "Login failed!"
fi
cd ../../../
