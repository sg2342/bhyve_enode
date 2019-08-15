#!/bin/sh -e
#

basedir=$(dirname "$(realpath "$0")")

src_env_conf="${basedir}/src-env.conf"
src_conf="${basedir}/src.conf"
enode_dist="${basedir}/enode.dist"

obj_dir_pfx=/usr/obj/bhyve_enode
_build_done="${obj_dir_pfx}/_build_done"
_tar_done="${obj_dir_pfx}/_tar_done"

kern_conf_dir="${basedir}/kernel"

install_dir="${obj_dir_pfx}/install_dir"
install_img="${obj_dir_pfx}/install_img"

export MAKEOBJDIRPREFIX="$obj_dir_pfx"
export SRCCONF="$src_conf"
## /bin/sh and the libraries needed by it
## additional libraries needed by erts runtime
targets="bin/sh
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

kldload filemon || true

#################################################################################
if [ -f "$_build_done" ] ; then
    printf '> marker "%s" exists: skip build step\n' "$_build_done"
else
    ##  kernel
    env KERNCONFDIR="$kern_conf_dir" \
        make -s -j8 -C /usr/src  SRC_ENV_CONF="$src_env_conf" buildkernel

    for tgt in $targets
    do make -s -j8 -C /usr/src/"$tgt" SRC_ENV_CONF="$src_env_conf"
    done

    ## build minit
    make -s -C "${basedir}/minit" SRC_ENV_CONF="$src_env_conf" obj
    make -s -C "${basedir}/minit" SRC_ENV_CONF="$src_env_conf" \
         WITHOUT_DEBUG_FILES=1

    touch "$_build_done"
fi

#################################################################################

if [ -f "$_tar_done" ] ; then
    printf '> marker "%s" exists: skip tar step\n' "$_tar_done"
else
    mkdir -p "$install_dir"
    truncate -s32M "$install_img"
    mdmfs -S -F "$install_img" md23 "$install_dir"
    mtree -deU -f "$enode_dist" -p "$install_dir"

    # install kernel
    env KERNCONFDIR="$kern_conf_dir" \
        make -s -C /usr/src SRC_ENV_CONF="$src_env_conf" DESTDIR="$install_dir" \
        installkernel

    # install bin/sh and libraries
    for tgt in $targets
    do make -C /usr/src/"$tgt" SRC_ENV_CONF="$src_env_conf" \
            DESTDIR="$install_dir" install
    done

    ## remove static libraries and pkgconfig data
    rm -rf "$install_dir"/usr/lib/lib*.a "$install_dir"/usr/libdata
    ## remove all dynamic links
    find "$install_dir"/usr/lib "$install_dir"/usr/libexec -type l -delete

    ## install minit
    make -s -C "${basedir}/minit" SRC_ENV_CONF="$src_env_conf" \
         DESTDIR="$install_dir"/sbin install WITHOUT_DEBUG_FILES=1

    for f in "${basedir}/minit/etc_minit/"*
    do install -o root -g wheel -m 555 "$f" \
               "${install_dir}/etc/minit/$(basename "$f")"
    done

    find "$install_dir" -print
    umount "$install_dir"; mdconfig -du 23

fi
