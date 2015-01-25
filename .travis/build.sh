#!/bin/bash

set -o errexit

KERNELSRC=""
CFLAGS="-msse2"
#CFLAGS="-Werror"

function install_kernel()
{
    wget https://www.kernel.org/pub/linux/kernel/v3.x/linux-3.14.26.tar.gz
    tar xzvf linux-3.14.26.tar.gz > /dev/null
    cd linux-3.14.26
    make allmodconfig
    make net/openvswitch/
    KERNELSRC=$(pwd)
    echo "Installed kernel source in $(pwd)"
    cd ..
}

function install_dpdk()
{
    wget http://www.dpdk.org/browse/dpdk/snapshot/dpdk-1.7.0.tar.gz
    echo "Debug 1"
    tar xzvf dpdk-1.7.0.tar.gz > /dev/null
    echo "Debug 2"
    cd dpdk-1.6.0
    echo "Debug 3"
    find ./ -type f | xargs sed -i 's/max-inline-insns-single=100/max-inline-insns-single=400/'
    echo "Debug 4"
    sed -ri 's,(CONFIG_RTE_BUILD_COMBINE_LIBS=).*,\1y,' config/common_linuxapp
    echo "Debug 5"
    make config CC=gcc T=x86_64-native-linuxapp-gcc
    echo "Debug 6"
    make CC=gcc RTE_KERNELDIR=$KERNELSRC
    echo "Installed DPDK source in $(pwd)"
    cd ..
}

function configure_ovs()
{
    ./boot.sh && ./configure $*
}

if [ "$KERNEL" ] || [ "$DPDK" ]; then
    install_kernel
fi

[ "$DPDK" ] && {
    install_dpdk
    # Disregard bad function cassts until DPDK is fixed
    CFLAGS="$CFLAGS -Wno-error=bad-function-cast -Wno-error=cast-align"
}

configure_ovs $*


if [ $CC = "clang" ]; then
    make CFLAGS="$CFLAGS -Wno-error=unused-command-line-argument"
else
    make CFLAGS="$CFLAGS" C=1
fi

if [ $TESTSUITE ]; then
    if ! make distcheck; then
        # testsuite.log is necessary for debugging.
        cat */_build/tests/testsuite.log
        exit 1
    fi
fi

exit 0
