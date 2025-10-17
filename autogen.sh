#! /bin/sh
set -e
set -x

# FreeBSD ports infrastructure expects versioned autom4te binaries (e.g.
# autom4te-2.71) to exist while autoreconf runs.  Recent Autoconf releases no
# longer ship those helpers and may only provide differently named binaries
# such as "autom4te" or "autom4te2.72".  We lazily generate compatibility
# wrappers that forward to whichever autom4te executable is available so builds
# keep working across Autoconf updates.

find_fallback_autom4te() {
        if command -v autom4te >/dev/null 2>&1; then
                command -v autom4te
                return 0
        fi

        local old_ifs=$IFS
        IFS=:
        for dir in $PATH; do
                [ -n "$dir" ] || dir=.
                if [ -d "$dir" ]; then
                        for candidate in "$dir"/autom4te*; do
                                [ -e "$candidate" ] || continue
                                [ -x "$candidate" ] || continue
                                local base
                                base=$(basename "$candidate")
                                case "$base" in
                                autom4te|autom4te-[0-9]*|autom4te[0-9]*)
                                        IFS=$old_ifs
                                        echo "$candidate"
                                        return 0
                                        ;;
                                esac
                        done
                fi
        done
        IFS=$old_ifs
        return 1
}

ensure_autom4te_wrapper() {
        local expected_version="2.71"
        if command -v "autom4te-$expected_version" >/dev/null 2>&1; then
                return 0
        fi

        local fallback_path
        fallback_path=$(find_fallback_autom4te) || {
                echo "autogen.sh: autom4te not found" >&2
                exit 1
        }

        local fallback_version=""
        local fallback_name
        fallback_name=$(basename "$fallback_path")
        case "$fallback_name" in
        autom4te-*)
                fallback_version=${fallback_name#autom4te-}
                ;;
        autom4te[0-9]*)
                fallback_version=${fallback_name#autom4te}
                ;;
        esac

        local helper_dir="$(dirname "$0")/build-aux"
        mkdir -p "$helper_dir"

        local versions="$expected_version"
        if [ -n "$fallback_version" ] && [ "$fallback_version" != "$expected_version" ]; then
                versions="$versions $fallback_version"
        fi

        local need_wrapper=0
        for version in $versions; do
                if command -v "autom4te-$version" >/dev/null 2>&1; then
                        continue
                fi
                need_wrapper=1
                local wrapper="$helper_dir/autom4te-$version"
                cat <<EOF_WRAPPER >"$wrapper"
#!/bin/sh
exec "$fallback_path" "\$@"
EOF_WRAPPER
                chmod +x "$wrapper"
        done

        if [ "$need_wrapper" -eq 1 ]; then
                case ":$PATH:" in
                *":$helper_dir:") ;;
                *) export PATH="$helper_dir:$PATH" ;;
                esac
        fi
}

ensure_autom4te_wrapper

cp README.md README
# remove previous generation
rm -f compile config.guess config.sub missing depcomp
aclocal -I m4 && autoheader && automake --add-missing --copy && autoconf
