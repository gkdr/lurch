#! /usr/bin/env bash
# Copyright (c) 2022 Sebastian Pipping <sebastian@pipping.org>
# Licensed under the GPL v2 or late

set -e -u -o pipefail

: ${DLL_HOME:?environment variable not set but required}
: ${BUILD_DIR:?environment variable not set but required}

direct_dependencies_of() {
    local filename="$1"
    objdump -p "${filename}" | fgrep 'DLL Name' | sort -u | sed 's,^.*DLL Name: ,,'
}

copy_dll_closure() {
    local filename="$1"
    local target_directory="$2"
    local indent="${3:-}"
    if [[ -z ${indent} ]]; then
        echo "[*] ${indent}$(basename "${filename}")"
    fi
    indent="${indent}  "
    success=true
    for dependency in $(direct_dependencies_of "${filename}"); do
        case ${dependency} in
        # DLLs native to Windows (that we consider present)
        ADVAPI32.dll|DNSAPI.dll|KERNEL32.dll|msvcrt.dll|ole32.dll|SHELL32.dll|USER32.dll|WS2_32.dll)
            continue
            ;;
        # DLLs native to Pidgin (that we consider present)
        libjabber.dll|libpurple.dll)
            continue
            ;;
        esac

        if [[ -f "${target_directory}/${dependency}" ]]; then
            echo "[+] ${indent}${dependency}"
            continue
        fi

        self_built="$(find "${BUILD_DIR}" -type f -name "${dependency}")"
        if [[ -z "${self_built}" ]]; then
            if [[ ! -f "${DLL_HOME}/${dependency}" ]]; then
                echo "[-] ${indent}${dependency} -- MISSING"
                success=false
                continue
            fi
            cp "${DLL_HOME}/${dependency}" "${target_directory}/"
        else
            cp "${self_built}" "${target_directory}/"
        fi
        echo "[+] ${indent}${dependency} -- COPIED"

        copy_dll_closure "${target_directory}/${dependency}" "${target_directory}" "${indent}"
    done
    ${success}
}

copy_dll_closure "$1" "$2"

echo '[+] DONE.'
