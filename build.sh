#!/bin/sh -e
#

basedir=$(dirname "$(realpath "$0")")

src_env_conf="${basedir}/src-env.conf"
src_conf="${basedir}/src.conf"

obj_dir_pfx=/usr/obj/bhyve_enode
_build_done="${obj_dir_pfx}/_build_done"
kern_conf_dir="${basedir}/kernel"

export MAKEOBJDIRPREFIX="$obj_dir_pfx"
export SRCCONF="$src_conf"

kldload filemon || true

#################################################################################
if [ -f "$_build_done" ] ; then
    printf '> build marker "%s" exists, skipping build step\n' "$_build_done"
else
    ##  kernel
    env KERNCONFDIR="$kern_conf_dir" \
        make -s -j8 -C /usr/src  SRC_ENV_CONF="$src_env_conf" buildkernel

    ## /bin/sh and the libraries needed by it
    ## additional libraries needed by erts runtime
    tgts="bin/sh
        lib/msun
        lib/libc
        lib/libedit
        lib/ncurses/ncurses
        lib/ncurses/ncursesw
        libexec/rtld-elf
        lib/libutil
        lib/libdl
        lib/libelf
        lib/libz
        lib/libthr
        lib/librt"
    for tgt in $tgts
    do make -s -j8 -C /usr/src/"$tgt" SRC_ENV_CONF="$src_env_conf"
    done

    ## build minit
    make -s -C "${basedir}/minit" SRC_ENV_CONF="$src_env_conf" obj
    make -s -C "${basedir}/minit" SRC_ENV_CONF="$src_env_conf"

    touch "$_build_done"
fi
#################################################################################

