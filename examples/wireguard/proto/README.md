## Compile shared library for LuaJIT
https://csl.name/post/luajit-cpp/

gcc -W -Wall -g -fPIC -shared -o libwireguard-crypto.so wireguard-crypto.c 