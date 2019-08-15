#!/bin/sh -e
#

errx() {
    printf 'Error:\n %s\n' "$1" >&2;
    [ "$2" -eq "$2" ] 2>/dev/null && exit "$2" || exit 99
}

basedir=$(dirname "$(realpath "$0")")

src_env_conf="${basedir}/src-env.conf"
[ -f "$src_env_conf" ] || errx "missing src-env.conf"

src_conf="${basedir}/src.conf"
[ -f "$src_conf" ] || errx "missing src.conf"

obj_dir_pfx=/usr/obj/bhyve_enode
export MAKEOBJDIRPREFIX="$obj_dir_pfx"
export KERNCONFDIR="${basedir}/kernel"

## build
kldload filemon || true
env SRCCONF="$src_conf" \
    make -s -j8 -C /usr/src \
    SRC_ENV_CONF="$src_env_conf" \
    buildworld buildkernel
