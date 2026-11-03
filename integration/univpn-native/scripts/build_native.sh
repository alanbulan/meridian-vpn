#!/bin/sh
# Run in an extracted/patched OpenConnect tree. Dependencies are OS packages.
set -eu
export CFLAGS="${CFLAGS:--std=gnu11 -O2 -g0} -ffile-prefix-map=$PWD=."
if [ "$(uname -s)" = Darwin ]; then
    export CPPFLAGS="${CPPFLAGS:-} -I$(brew --prefix openssl@3)/include"
    export LDFLAGS="${LDFLAGS:-} -L$(brew --prefix openssl@3)/lib"
    export PKG_CONFIG_PATH="$(brew --prefix openssl@3)/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
fi
case "$(uname -s)" in
    MINGW*|MSYS*)
        # Some MSYS2 runners omit this MinGW compatibility header although
        # OpenConnect only needs errno_t from it.
        mkdir -p sec_api
        if [ ! -f sec_api/stdlib_s.h ]; then
            cat > sec_api/stdlib_s.h <<'EOF'
#ifndef UNIVPN_STDLIB_S_H
#define UNIVPN_STDLIB_S_H
typedef int errno_t;
#endif
EOF
        fi
        export CPPFLAGS="${CPPFLAGS:-} -I$PWD"
        ;;
esac
sh autogen.sh
./configure --without-gnutls --with-openssl --without-lz4 --without-libpcsclite \
    --without-libproxy --without-stoken --without-libpskc --without-gssapi \
    --disable-nls --with-vpnc-script=/bin/false
make -j4 P11KIT_LIBS=
case "$(uname -s)" in
    MINGW*|MSYS*) ;; # Windows integration needs its real socket/TUN environment.
    *) if [ -f tests/univpn-integration.py ]; then
           python3 tests/univpn-integration.py ./openconnect
       fi
       if [ -f tests/univpn-codec.c ]; then
           ${CC:-cc} -I. tests/univpn-codec.c -o tests/univpn-codec
           ./tests/univpn-codec
       fi
       make -C tests buftest seqtest lzstest
       ./tests/buftest && ./tests/seqtest && ./tests/lzstest ;;
esac

# Linux-only trusted UniVPN hook contract, without any TUN operation.
if [ "$(uname -s)" = Linux ]; then
    ${CC:-cc} -I. -Ijson ${LIBXML2_CFLAGS:-$(pkg-config --cflags libxml-2.0)} \
      tests/univpn-hook.c .libs/libopenconnect_la-*.o json/.libs/*.o \
      ${LIBXML2_LIBS:-$(pkg-config --libs libxml-2.0)} -lssl -lcrypto -lz -ldl -lm \
      -Wl,--wrap=open -o tests/univpn-hook
    ./tests/univpn-hook
fi

# Native lifecycle/parser tests: syscall-wrapped TUN and netlink, pipes only.
if [ "$(uname -s)" = Linux ]; then
    ${CC:-cc} -I. -Ijson ${LIBXML2_CFLAGS:-$(pkg-config --cflags libxml-2.0)} \
      tests/univpn-session.c .libs/libopenconnect_la-*.o json/.libs/*.o \
      ${LIBXML2_LIBS:-$(pkg-config --libs libxml-2.0)} -lssl -lcrypto -lz -ldl -lm \
      -Wl,--wrap=open,--wrap=ioctl,--wrap=if_nametoindex,--wrap=socket,--wrap=setsockopt,--wrap=sendto,--wrap=recvfrom \
      -o tests/univpn-session
    ./tests/univpn-session
fi
if [ "$(uname -s)" = Linux ]; then
    python3 tests/univpn-session-integration.py ./openconnect
fi

# Combined private session pipe + preconnected dual TLS; never creates a TUN.
if [ "$(uname -s)" = Linux ]; then
    ${CC:-cc} -I. -Ijson ${LIBXML2_CFLAGS:-$(pkg-config --cflags libxml-2.0)} \
      tests/univpn-fd-session.c .libs/libopenconnect_la-*.o json/.libs/*.o \
      ${LIBXML2_LIBS:-$(pkg-config --libs libxml-2.0)} -lssl -lcrypto -lz -ldl -lm \
      -Wl,--wrap=open -o tests/univpn-fd-session
    python3 tests/univpn-fd-session.py ./openconnect
fi

# Allocation fault injection verifies adopted TLS descriptor cleanup, no network.
if [ "$(uname -s)" = Linux ]; then
    ${CC:-cc} -I. -Ijson ${LIBXML2_CFLAGS:-$(pkg-config --cflags libxml-2.0)} \
      tests/univpn-fd-cleanup.c .libs/libopenconnect_la-*.o json/.libs/*.o \
      ${LIBXML2_LIBS:-$(pkg-config --libs libxml-2.0)} -lssl -lcrypto -lz -ldl -lm \
      -Wl,--wrap=connect_https_socket,--wrap=SSL_CTX_new,--wrap=SSL_new,--wrap=BIO_new_socket,--wrap=buf_alloc,--wrap=close \
      -o tests/univpn-fd-cleanup
    ./tests/univpn-fd-cleanup
fi

# No host interface: inherited packet socket + authenticated offer, loopback only.
if [ "$(uname -s)" = Linux ]; then
    python3 tests/univpn-packet-integration.py ./openconnect
fi
