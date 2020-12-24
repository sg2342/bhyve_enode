#!/bin/sh -e
#

usr_src=${usr_src:-"/usr/src"}
basedir=$(dirname "$(realpath "$0")")

src_env_conf="${basedir}/src-env.conf"
src_conf="${basedir}/src.conf"
enode_dist="${basedir}/enode.dist"

obj_dir_pfx="${basedir}/_build"
_build_done="${obj_dir_pfx}/_build_done"
_tar_done="${obj_dir_pfx}/_tar_done"

kern_conf_dir="${basedir}/kernel"

install_dir="${obj_dir_pfx}/bhyve_enode_dir"
install_img="${obj_dir_pfx}/bhyve_enode_img"
archive="${obj_dir_pfx}/bhyve_enode.txz"

export MAKEOBJDIRPREFIX="$obj_dir_pfx"
export SRCCONF="$src_conf"

## /bin/sh and the libraries needed by it
## additional libraries needed by erts runtime
base_targets="bin/sh
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

param_h="$usr_src"/sys/sys/param.h

case $(grep define\ __FreeBSD_version $param_h|cut -w -f 3) in
     12*) src_version=12 ;;
     13*) src_version=13;;
     *) printf 'unsupported FreeBSD version in "$usr_src"' >&2 ; exit 99 ;;
esac

src_timestamp=$(date -r "$(stat -f "%m" $param_h)" "+%Y%m%d%H%M.%S")

#################################################################################

if [ -f "$_build_done" ] ; then
    printf '> marker "%s" exists: skip build step\n' "$_build_done"
else
    ##  kernel
    env KERNCONFDIR="$kern_conf_dir" \
        make -s -j8 -C "$usr_src"  SRC_ENV_CONF="$src_env_conf" buildkernel \
	KERNCONF=BH"${src_version}"

    for tgt in $base_targets
    do make -s -j8 -C "$usr_src"/"$tgt" SRC_ENV_CONF="$src_env_conf"
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
    md=$(mdconfig -a -t vnode -f "$install_img")
    newfs -n /dev/"$md"
    mount -o noatime /dev/"$md" "$install_dir"
    mtree -deU -f "$enode_dist" -p "$install_dir"

    # install kernel
    env KERNCONFDIR="$kern_conf_dir" \
        make -s -C "$usr_src" SRC_ENV_CONF="$src_env_conf" DESTDIR="$install_dir" \
        installkernel KERNCONF=BH"${src_version}"

    # install bin/sh and libraries
    for tgt in $base_targets
    do make -s -C "$usr_src"/"$tgt" SRC_ENV_CONF="$src_env_conf" \
            DESTDIR="$install_dir" install
    done

    ## remove static libraries, pkgconfig data and symbolic links
    rm -rf "$install_dir"/usr/lib/lib*.a "$install_dir"/usr/libdata
    find "$install_dir"/usr/lib "$install_dir"/usr/libexec -type l -delete

    ## install minit
    make -s -C "${basedir}/minit" SRC_ENV_CONF="$src_env_conf" \
         DESTDIR="$install_dir"/sbin install WITHOUT_DEBUG_FILES=1
    for f in "${basedir}/minit/etc_minit/"*
    do install -o root -g wheel -m 555 "$f" \
               "${install_dir}/etc/minit/$(basename "$f")"
    done

    find "$install_dir" -type f -flags schg -exec chflags noschg "{}" ";" \
	 -exec touch -t "$src_timestamp" "{}" ";" \
	 -exec chflags noschg "{}" ";"
    find "$install_dir" -not -flags schg -exec touch -t "$src_timestamp" "{}" ";"
    tar -C "$install_dir" -cvaf "$archive" \
        boot var dev etc bin sbin lib libexec sbin usr root

    umount "$install_dir"
    mdconfig -du "$md"
    rm -rf "$install_img"
    touch "$_tar_done"
fi

#################################################################################

printf '> archive SHA256: %s\n' "$(sha256 -q "$archive")"
