# Nonsecret mint configuration renderer

Use Python 3.11 or later. This tool uses only the standard library.
It renders an explicit local or staging fakewallet profile as TOML for
`cdk-mintd` 0.18.2. It does not start a mint or change a database.
It does not read environment settings, resolve secret references, or use the
network. It supports neither production nor a real payment backend.

The caller supplies every required value. There are no deployment-policy
defaults in the renderer. The caller must own the input and output directory.
Keep actual credentials out of the input, output, command arguments, and logs.

```bash
python3 tools/bitcaster-mint-config/render.py \
  --input /owned/mint-input.json --output /owned/mint.toml
```

The default refuses an existing output. Use `--overwrite` only when the caller
owns an explicit replacement operation. An invalid input leaves the output
unchanged. The tool refuses an output that aliases the input.

Success exits `0` with no output. Invalid input or arguments exit `64`.
A file operation failure exits `4`. Errors contain fixed text, not input values.
`--help` prints usage. Unknown arguments and abbreviations are refused.

## Input contract

The top-level object has exactly two keys:

- `environment`: `"local"` or `"staging"`.
- `settings`: the object described below. Its keys match native CDK tables.

An environment label is a declared profile. It is not proof of where the mint
will run. The deployment owner must enforce the target environment separately.
No `production` profile or production backend selection is available here.

All tables below are required unless the table says optional. Do not supply
`null`. Integers must be JSON integers in the range `0..9223372036854775807`.
The upper bound is the TOML signed integer limit. Positive fields exclude zero.
Numeric strings, floats, exponent notation, booleans in numeric fields, NaN,
Infinity, duplicate keys, and unknown keys are refused.
The input limit is 128 KiB. Strings have an 8192-character limit and must encode
as UTF-8. Public text fields can contain line breaks and Unicode.

| Table or field | Required values |
| --- | --- |
| `info` | `url`, `listen_host`, integer `listen_port` in `1..65535`, nonnegative `input_fee_ppk`, `use_keyset_v2: true`, exactly one of `mnemonic` and `seed` |
| `info.http_cache` | `backend: "memory"` |
| `info.logging` | `output: "stderr"`, `format: "json"`, `console_level`: `"debug"`, `"info"`, `"warn"`, or `"error"` |
| `info.quote_ttl` (optional) | Positive `mint_ttl` and `melt_ttl`, in seconds |
| `database` | `engine: "sqlite"` or `"postgres"` |
| `database.postgres` | Required only for PostgreSQL: secret-reference `url`, `tls_mode: "disable"` or `"verify-full"`, positive `max_connections` and `connection_timeout_seconds` |
| `payment_backend` | An array with exactly one object: `backend: "fakewallet"`, `unit: "msat"`, nonnegative `min_mint` and `min_melt`, positive `max_mint` and `max_melt` |
| `fake_wallet` | An empty object. Native CDK supplies its existing test-backend behavior |
| `limits` | Positive `max_inputs` and `max_outputs`; optional positive `max_outcomes_per_condition` |
| `mint_info` | `ctf_default_keyset_creation`: `"none"`, `"one-vs-rest"`, or `"all"`; the fee and settlement fields below |
| `mint_info.ctf_registration_fees` | An array with exactly one object: `unit: "msat"`, nonnegative `registration_fee_base` and `registration_fee_per_keyset` |
| `mint_info.ctf_settlement` | Positive `max_participants`, `max_inputs`, `max_outputs`, `max_request_bytes`, `max_expiry_seconds`, and `max_pool_entries` |
| `mint_management_rpc` | Disabled: exactly `enabled: false`. Enabled: the complete strict profile below |

Optional `mint_info` strings are `name`, `description`, `description_long`,
`pubkey`, `icon_url`, `motd`, `contact_nostr_public_key`, `contact_email`, and
`tos_url`. Native CDK validates their protocol meaning. The caller must put only
public information in these fields. The renderer cannot identify a secret
accidentally entered as a public description.

An enabled management profile has these exact fields:

```json
{
  "enabled": true,
  "address": "127.0.0.1",
  "port": 8087,
  "tls_dir": "/owned/certificates",
  "strict_tls": true,
  "allow_insecure": false,
  "allow_mint_quote_payment_override": false,
  "expected_client_dns_name": "orchard",
  "expected_client_spki_pin_path": "/owned/certificates/client.spki.sha256"
}
```

This is a table example, not a complete input document.
The tests contain complete synthetic inputs for each supported profile.
They are test data, not deployment defaults.

Secret fields accept `env:VARIABLE` or `file:/absolute/path` only.
An environment name must match `[A-Za-z_][A-Za-z0-9_]*`.
File references and certificate paths must be absolute POSIX paths without
`..` or control characters. The root path `/` is refused. The renderer never
opens these paths.
The bootstrap database URL still needs its resolved value through the separate
protected runtime channel. Do not replace the document reference with that value.

The mint URL must be an HTTP(S) origin with no credentials, query, or fragment.
Local HTTP URLs must use `localhost`, `127.0.0.1`, or `::1`.
Staging requires HTTPS, PostgreSQL with `verify-full`, and the `info` log level.
The renderer does not check DNS, certificate chains, or live connectivity.

## Native validation and lifecycle

Install referenced secrets and the strict management client pin file at their
final paths before native validation. Supply the required secret environment
through the local protected channel. Then run:

```bash
cdk-mintd config validate --file /owned/mint.toml
```

Native CDK remains the semantic validator. For example, the renderer accepts
a positive settlement participant limit of `1`; native CDK rejects that limit.
A rendered document alone is not evidence that a mint can start safely.

The owner must select fresh initialization, retained import, explicit apply,
or ordinary restart. This renderer selects none of them.
Do not invoke init or apply on ordinary restart. Do not use an `init || apply`
fallback. Preserve the signer and stored state on an uncertain result.
Native apply stages a full document. On activation, it can replace canonical
metadata and TTL changed through management RPC. Do not apply a stale document
as an automatic policy-only update.

## Atomic output

The tool writes a mode `0600` temporary file beside the destination and fsyncs
its contents. For a new output it uses an atomic hard link, which cannot
overwrite a file created by another writer. For explicit overwrite it uses
atomic replacement. It fsyncs the directory and removes the temporary name.
Symlink and nonregular destinations are refused when observed before publication.
The caller must keep the parent directory under its control.

A failure after publication, such as directory fsync failure, can leave the
complete new output in place. Inspect it before retrying. The tool never writes
a partial destination and never treats an I/O error as permission to reset data.
This output operation is POSIX-only. No Windows filesystem guarantee is claimed.

## Tests

Run the focused unit suite from the CDK root:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s tools/bitcaster-mint-config/tests -v
```

The native tests skip unless an explicit current binary is supplied:

```bash
PYTHONDONTWRITEBYTECODE=1 MINT_CONFIG_TEST_BINARY="$PWD/target/debug/cdk-mintd" \
  python3 -m unittest discover -s tools/bitcaster-mint-config/tests -v
```

Build that binary with `postgres,prometheus,conditional-tokens` features.
The tests require its version to be `0.18.2`. They use synthetic credentials
and a synthetic public pin. They run only `config validate`, not database
initialization, a mint daemon, or real payments.
They cover all profile shapes and prove that native semantic, secret-resolution,
and strict-pin checks remain required. They do not verify deployment fencing,
image packaging, certificate handshakes, or retained-store migration.
