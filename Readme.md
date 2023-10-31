
# Bridgehead Secret Sync

## Usage

### Local

Gets input via ARGS env var which is a `\x1E` (Ascii record separator) delimited list of secret definitions.
A secret definition is a `:` separated 3-tuple. The first value is the [secret type](#secret-types) which defines how the secret is generated. The second argument is the secrets name which will be the name written to the secrets cache file. The third value is the data used to generate the secret which depends on the [secret type](#secret-types) used.

### Central

TODO


## Secret types

### Keycloak
