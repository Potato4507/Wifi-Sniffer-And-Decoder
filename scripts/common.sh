#!/usr/bin/env bash
set -euo pipefail

format_display_argument() {
    printf '%q' "$1"
}

resolve_repo_python_bin() {
    local repo_root="$1"
    local venv_python="$repo_root/.venv/bin/python"
    if [[ -x "$venv_python" ]]; then
        printf '%s\n' "$venv_python"
        return
    fi
    printf '%s\n' "${PYTHON:-python3}"
}

repo_install_ready() {
    local repo_root="$1"
    local venv_python="$repo_root/.venv/bin/python"
    if [[ ! -x "$venv_python" ]]; then
        return 1
    fi

    local os_name
    os_name="$(uname -s)"
    local required=()
    if [[ "$os_name" == "Darwin" ]]; then
        required=(python3 aircrack-ng airdecap-ng)
    else
        required=(python3 tcpdump tshark aircrack-ng airdecap-ng)
    fi

    local cmd
    for cmd in "${required[@]}"; do
        command -v "$cmd" >/dev/null 2>&1 || return 1
    done
    return 0
}

ensure_repo_install_deps() {
    local repo_root="$1"
    local install_mode="${2:-auto}"

    case "$install_mode" in
        skip|false|no)
            return
            ;;
        auto|0)
            if repo_install_ready "$repo_root"; then
                return
            fi
            printf '\n[*] Missing local dependencies for the supported workflow; running install_deps.sh\n'
            ;;
        force|1|yes)
            ;;
        *)
            printf 'Unknown install mode: %s\n' "$install_mode" >&2
            return 1
            ;;
    esac

    local install_script="$repo_root/install_deps.sh"
    if [[ ! -f "$install_script" ]]; then
        printf 'install_deps.sh was not found.\n' >&2
        return 1
    fi

    printf '\n> bash %s\n' "$(format_display_argument "$install_script")"
    bash "$install_script"
}

invoke_repo_pipeline() {
    local repo_root="$1"
    local config_path="$2"
    shift 2

    local script_path="$repo_root/videopipeline.py"
    if [[ ! -f "$script_path" ]]; then
        printf 'videopipeline.py was not found.\n' >&2
        return 1
    fi

    local python_bin
    python_bin="$(resolve_repo_python_bin "$repo_root")"

    local args=()
    if [[ -n "$config_path" ]]; then
        args+=(--config "$config_path")
    fi
    args+=("$@")

    local rendered=()
    local arg
    for arg in "${args[@]}"; do
        rendered+=("$(format_display_argument "$arg")")
    done

    printf '\n> %s %s' "$(format_display_argument "$python_bin")" "$(format_display_argument "$script_path")"
    if [[ "${#rendered[@]}" -gt 0 ]]; then
        printf ' %s' "${rendered[*]}"
    fi
    printf '\n'

    (
        cd "$repo_root"
        "$python_bin" "$script_path" "${args[@]}"
    )
}
