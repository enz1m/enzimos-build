#!/usr/bin/bash
# SPDX-License-Identifier: MIT
# Helpers for this fixed lab only; no public authorization or installer API.
authority_check() {
    local home=$1 expected=$2
    (cd "$home" && sha256sum --strict -c "$expected/authority.sha256")
    gpg --homedir "$home" --batch --no-autostart --export-ownertrust | grep -v '^#' | sort > /run/ownertrust.actual
    sort "$home/approved.trust" > /run/ownertrust.expected
    diff -u /run/ownertrust.expected /run/ownertrust.actual
}
select_entry() {
    local name=$1 number=$2
    printf 'default %s.conf\ntimeout 0\neditor no\n' "$name" > /boot/loader/loader.conf
    sed -i "s/^default_entry: .*/default_entry: $number/" /boot/limine/limine.conf
}
package_check() {
    local expected=$1
    pacman -Q | sort > /run/packages.actual
    diff -u "$expected" /run/packages.actual
}
