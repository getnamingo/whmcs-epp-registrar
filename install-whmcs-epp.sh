#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

VERSION='1.2.1'
# v1.2.1 currently has no uploaded release asset. Pin the source archive to the
# commit behind the tag so a moved tag cannot silently change installer input.
SOURCE_COMMIT='a99f2d1bd71324ca21b19e1816106575798b66d6'
ARCHIVE="whmcs-epp-registrar-${VERSION}.tar.gz"
DOWNLOAD_URL="https://github.com/getnamingo/whmcs-epp-registrar/archive/${SOURCE_COMMIT}.tar.gz"

CC_REGISTRIES=(
  registrebf switch niccl cocca cocca2 eurid afnic nicge carnet nicim switchli
  niclv nicmx sidn iisnu nask rotld iis hostmaster ye zadna
)
G_REGISTRIES=(
  central core dns godaddy google hello identity org itcom namingo regtons ryce
  tucows verisign zdns
)
R_REGISTRIES=(drsua ukrnames)

usage() {
  cat <<EOF_USAGE
Usage:
  $(basename "$0") <registry> [whmcs_path]

Examples:
  $(basename "$0") namingo
  $(basename "$0") namingo /var/www/whmcs

Supported registry profiles:
  cc: $(printf '%s ' "${CC_REGISTRIES[@]}")
  g:  $(printf '%s ' "${G_REGISTRIES[@]}")
  r:  $(printf '%s ' "${R_REGISTRIES[@]}")
EOF_USAGE
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

info() {
  printf '%s\n' "$*"
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

is_supported_registry() {
  local wanted=$1 item
  for item in "${CC_REGISTRIES[@]}" "${G_REGISTRIES[@]}" "${R_REGISTRIES[@]}"; do
    [[ "$item" == "$wanted" ]] && return 0
  done
  return 1
}

is_whmcs_root() {
  local path=${1%/}
  [[ -f "$path/init.php" && -d "$path/modules/registrars" ]]
}

find_whmcs_root() {
  local found=() init root item seen

  while IFS= read -r init; do
    root=${init%/init.php}
    is_whmcs_root "$root" || continue

    seen=0
    for item in "${found[@]:-}"; do
      [[ "$item" == "$root" ]] && seen=1 && break
    done
    ((seen == 0)) && found+=("$root")
  done < <(find /var/www -maxdepth 5 -type f -name init.php -print 2>/dev/null || true)

  if ((${#found[@]} == 1)); then
    printf '%s\n' "${found[0]}"
    return 0
  fi

  return 1
}

prompt_whmcs_root() {
  local path
  while true; do
    if [[ -t 0 || -t 1 || -t 2 ]]; then
      read -r -p 'WHMCS path: ' path </dev/tty
    else
      die 'WHMCS was not detected under /var/www and no interactive terminal is available.'
    fi

    path=${path%/}
    if is_whmcs_root "$path"; then
      printf '%s\n' "$path"
      return 0
    fi

    printf 'Not a valid WHMCS root: %s (expected init.php and modules/registrars)\n' "$path" >&2
  done
}

ask_yes_no() {
  local prompt=$1 answer

  [[ -t 0 || -t 1 || -t 2 ]] || return 1

  while true; do
    read -r -p "$prompt [y/N]: " answer </dev/tty
    case "${answer,,}" in
      y|yes) return 0 ;;
      ''|n|no) return 1 ;;
      *) printf 'Please answer yes or no.\n' >&2 ;;
    esac
  done
}

if (($# == 0)); then
  usage
  exit 0
fi

if [[ "${1:-}" == '-h' || "${1:-}" == '--help' ]]; then
  usage
  exit 0
fi

(($# <= 2)) || die 'Too many arguments.'

registry=${1,,}
is_supported_registry "$registry" || {
  usage >&2
  die "Unsupported registry profile: $registry"
}

# Equivalent to PHP ucfirst() after normalizing the profile name to lowercase.
registry_name="${registry^}"

need_cmd curl
need_cmd tar
need_cmd grep
need_cmd find
need_cmd perl
need_cmd mktemp
perl -MJSON::PP -e 1 >/dev/null 2>&1 || die 'Perl JSON::PP module is required.'
id www-data >/dev/null 2>&1 || die 'Required web-server user not found: www-data'

if [[ ${EUID} -eq 0 ]]; then
  SUDO=()
else
  need_cmd sudo
  SUDO=(sudo)
fi

if (($# == 2)); then
  whmcs_path=${2%/}
  is_whmcs_root "$whmcs_path" || die "Invalid WHMCS path: $whmcs_path"
else
  if whmcs_path=$(find_whmcs_root); then
    info "Detected WHMCS: $whmcs_path"
  else
    info 'WHMCS was not uniquely detected under /var/www.'
    whmcs_path=$(prompt_whmcs_root)
  fi
fi

registrars_dir="$whmcs_path/modules/registrars"
module_dest="$registrars_dir/$registry"
[[ ! -L "$module_dest" ]] || die "Refusing to replace symlinked module directory: $module_dest"

workdir=$(mktemp -d -t namingo-whmcs-epp.XXXXXXXX)
cleanup() {
  rm -rf -- "$workdir"
}
trap cleanup EXIT INT TERM

archive_path="$workdir/$ARCHIVE"
extract_dir="$workdir/extracted"
mkdir -p "$extract_dir"

info "Downloading Namingo WHMCS EPP module v${VERSION}..."
curl --fail --location --silent --show-error \
  --retry 3 --retry-delay 1 --retry-all-errors \
  --proto '=https' --tlsv1.2 \
  --output "$archive_path" "$DOWNLOAD_URL"

# The URL is commit-pinned. Also reject path traversal before extraction.
if tar -tzf "$archive_path" | grep -Eq '(^/|(^|/)\.\.(/|$))'; then
  die 'Archive contains an unsafe path.'
fi

tar -xzf "$archive_path" -C "$extract_dir"

mapfile -t module_candidates < <(
  find "$extract_dir" -mindepth 2 -maxdepth 2 -type f -name epp.php -printf '%h\n' | sort -u
)
((${#module_candidates[@]} == 1)) || die 'Unexpected archive structure: could not uniquely locate epp.php.'
module_dir=${module_candidates[0]}

[[ -d "$module_dir/lib" ]] || die 'Unexpected archive structure: missing lib/ directory.'
[[ -f "$module_dir/epp.php" ]] || die 'Unexpected archive structure: missing epp.php.'

# Customize only module PHP, never bundled library code. This mirrors the web customizer.
customizer="$workdir/customize-php.pl"
cat > "$customizer" <<'PERL'
use strict;
use warnings;

my $registry      = $ENV{'REGISTRY'}      // die "REGISTRY missing\n";
my $registry_name = $ENV{'REGISTRY_NAME'} // die "REGISTRY_NAME missing\n";

for my $path (@ARGV) {
    open my $in, '<', $path or die "Cannot read $path: $!\n";
    local $/;
    my $content = <$in>;
    close $in;

    $content =~ s/epp_/${registry}_/g;
    $content =~ s/epp\.log/${registry}.log/g;
    $content =~ s/'epp'/'${registry}'/g;
    $content =~ s/('DisplayName'\s*=>\s*)'[^']*'/${1}'${registry_name} EPP Module'/g;
    $content =~ s/('FriendlyName'\s*=>\s*\[.*?'Value'\s*=>\s*)'[^']*'/${1}'${registry_name} EPP Module'/sg;
    $content =~ s/Connect WHMCS to any domain registry using the standard EPP protocol\./WHMCS EPP integration for the ${registry_name} registry./g;

    open my $out, '>', $path or die "Cannot write $path: $!\n";
    print {$out} $content;
    close $out or die "Cannot close $path: $!\n";
}
PERL

mapfile -d '' php_files < <(
  find "$module_dir" -type f -name '*.php' ! -path "$module_dir/lib/*" -print0
)
((${#php_files[@]} > 0)) || die 'Unexpected archive structure: no customizable PHP files found.'
REGISTRY="$registry" REGISTRY_NAME="$registry_name" perl "$customizer" "${php_files[@]}"

# Update whmcs.json as structured JSON when present.
json_path="$module_dir/whmcs.json"
if [[ -f "$json_path" ]]; then
  REGISTRY="$registry" REGISTRY_NAME="$registry_name" perl -MJSON::PP -e '
    use strict; use warnings;
    my ($path) = @ARGV;
    open my $fh, "<", $path or die "Cannot read $path: $!\n";
    local $/; my $raw = <$fh>; close $fh;
    my $data = decode_json($raw);
    $data->{name} = $ENV{REGISTRY};
    if (ref($data->{description}) eq "HASH") {
      $data->{description}->{name} = "EPP Module for $ENV{REGISTRY_NAME}";
      $data->{description}->{tagline} = "WHMCS EPP integration for the $ENV{REGISTRY_NAME} registry.";
    }
    open my $out, ">", $path or die "Cannot write $path: $!\n";
    print {$out} JSON::PP->new->pretty->encode($data);
    close $out or die "Cannot close $path: $!\n";
  ' "$json_path"
fi

# Preserve the optional config.php substitutions from the web customizer.
config_path="$module_dir/config.php"
if [[ -f "$config_path" ]]; then
  REGISTRY="$registry" REGISTRY_NAME="$registry_name" perl -0pi -e '
    s/PLACEHOLDER_COMPANY/$ENV{REGISTRY_NAME} Registry/g;
    s/PLACEHOLDER_EMAIL/support\@$ENV{REGISTRY}.tld/g;
  ' "$config_path"
fi

mv -- "$module_dir/epp.php" "$module_dir/${registry}.php"

[[ -f "$module_dir/${registry}.php" ]] || die 'Failed to rename main registrar module file.'
grep -Fq "${registry}_" "$module_dir/${registry}.php" \
  || die 'Failed to customize WHMCS registrar function prefix.'

if [[ -f "$json_path" ]]; then
  grep -Fq "\"name\" : \"${registry}\"" "$json_path" \
    || grep -Fq "\"name\": \"${registry}\"" "$json_path" \
    || die 'Failed to customize whmcs.json module name.'
fi

# Preserve existing PEM credentials during upgrades. WHMCS stores registrar settings
# in the database, so module code itself can be replaced cleanly.
pem_backup="$workdir/pem-backup"
mkdir -p "$pem_backup"
if [[ -d "$module_dest" ]]; then
  while IFS= read -r -d '' pem; do
    "${SUDO[@]}" cp -p -- "$pem" "$pem_backup/"
  done < <("${SUDO[@]}" find "$module_dest" -maxdepth 1 -type f -name '*.pem' -print0)
fi

stage_dest="$registrars_dir/.${registry}.install.$$"
backup_dest="$registrars_dir/.${registry}.backup.$$"
"${SUDO[@]}" rm -rf -- "$stage_dest" "$backup_dest"
"${SUDO[@]}" mkdir -p -- "$stage_dest"
"${SUDO[@]}" cp -a -- "$module_dir/." "$stage_dest/"

# Conservative production permissions: executable directories, non-executable module files.
"${SUDO[@]}" find "$stage_dest" -type d -exec chmod 0755 {} +
"${SUDO[@]}" find "$stage_dest" -type f -exec chmod 0644 {} +

# Restore registry/client certificates from an existing installation, if any.
if compgen -G "$pem_backup/*.pem" >/dev/null; then
  for pem in "$pem_backup"/*.pem; do
    "${SUDO[@]}" cp -p -- "$pem" "$stage_dest/"
  done
fi

"${SUDO[@]}" chown -R www-data:www-data -- "$stage_dest"
"${SUDO[@]}" find "$stage_dest" -maxdepth 1 -type f -name '*.pem' -exec chmod 0600 {} +

if [[ -e "$module_dest" ]]; then
  "${SUDO[@]}" mv -- "$module_dest" "$backup_dest"
  if ! "${SUDO[@]}" mv -- "$stage_dest" "$module_dest"; then
    "${SUDO[@]}" mv -- "$backup_dest" "$module_dest" || true
    die 'Failed to install customized module; previous module was restored.'
  fi
  "${SUDO[@]}" rm -rf -- "$backup_dest"
  info "Upgraded WHMCS registrar module: $registry"
else
  "${SUDO[@]}" mv -- "$stage_dest" "$module_dest"
  info "Installed WHMCS registrar module: $registry"
fi

cert_path="$module_dest/${registry}_cert.pem"
key_path="$module_dest/${registry}_key.pem"
cert_generated='no'

if ask_yes_no "Generate a self-signed TEST EPP certificate for ${registry_name}?"; then
  need_cmd openssl

  if [[ -e "$cert_path" || -e "$key_path" ]]; then
    die "Refusing to overwrite an existing certificate/key: $cert_path or $key_path"
  fi

  cert_tmp="$workdir/${registry}_cert.pem"
  key_tmp="$workdir/${registry}_key.pem"

  openssl genrsa -out "$key_tmp" 2048 >/dev/null 2>&1
  openssl req -new -x509 \
    -key "$key_tmp" \
    -out "$cert_tmp" \
    -days 365 \
    -sha256 \
    -subj "/C=XX/ST=Test/L=Test/O=Namingo Test/OU=EPP/CN=${registry}.test/emailAddress=test@example.invalid" \
    >/dev/null 2>&1

  "${SUDO[@]}" install -o www-data -g www-data -m 0600 -- "$cert_tmp" "$cert_path"
  "${SUDO[@]}" install -o www-data -g www-data -m 0600 -- "$key_tmp" "$key_path"
  cert_generated='yes'
fi

cat <<EOF_DONE

Installation complete.
Registry module: ${registry_name}
WHMCS path: ${whmcs_path}
Module directory: ${module_dest}
Main module file: ${module_dest}/${registry}.php
EOF_DONE

if [[ "$cert_generated" == 'yes' ]]; then
  cat <<EOF_CERT
Test certificate: ${cert_path}
Test private key: ${key_path}

These are self-signed TEST credentials only. Replace them with the certificate/key accepted by the registry before production EPP use.
EOF_CERT
else
  info 'Test certificate: not generated.'
fi

if [[ -f "$module_dest/additionalfields.php" ]]; then
  cat <<EOF_FIELDS

Note: this module includes additionalfields.php. If your registry profile needs custom domain fields, merge its contents into:
  ${whmcs_path}/resources/domains/additionalfields.php
Do not blindly overwrite an existing WHMCS additionalfields.php file.
EOF_FIELDS
fi
