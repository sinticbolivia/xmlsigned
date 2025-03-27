#Requierments

- Vala >= 0.56
- Meson >= 1.5.1
- glib-2.0
- gobject-2.0
- gee-0.8
- gio-2.0
- libxml-2.0
- libgcrypt
- gnutls
- xmlsec

For xmlsec, you can download it from https://www.aleksey.com/xmlsec/

#Compilation

```
meson setup build
cd build
meson compile
```
## For windows compilation

In order to compile the library for windows, you will need a GNU Toolchain compilation environment, we recommend MinGW.

You can download MinGW from next link

https://www.mingw-w64.org/

#Test

In order to test the library, you can execute

## For Linux and MACOS
```
LD_LIBRARY_PATH=`pwd` ./signer-test
```

## For Windows
```
signer-test.exe
```
