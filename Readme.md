
# Bridgehead Secret Sync

## Usage

### Local

This component generates a bash sourceable cache file from some [secret definitions](#secret-definitions) by communicating with the central part of this component via [beam](https://github.com/samply/beam).

This enables secure generation and validation of secret tokens like Open ID Connect secrets.

#### Example

```yaml
services:
  local:
    image: samply/secret-sync-local:latest
    environment:
      # See below for the format specification
      - SECRET_DEFINITIONS=${ARGS}
      # The beam app id of the central half of this component
      - OIDC_PROVIDER=${OIDC_PROVIDER_APP_ID}
      # Required args for the beam proxy for more options look at the beam Readme
      - PROXY_ID=proxy1.broker
      - BROKER_URL=${BROKER_URL}
    volumes:
      # Path can be configuard via CACHE_PATH this container path is the default
      - ${CACHE_PATH}:/usr/local/cache
    # Used for the embeded beam proxy
    secrets:
      - privkey.pem
      - root.crt.pem
```

#### Secret Definitions
`SECRET_DEFINITIONS` should be `\x1E` (Ascii record separator) delimited list of secret definitions.
A secret definition is a `:` separated 3-tuple. The first value is the [secret type](#secret-types) which defines how the secret is generated. The second argument is the secrets name which will be the name written to the secrets cache file. The third value is the data used to generate the secret which depends on the [secret type](#secret-types) used.

### Central

#### Example

```yaml
services:
  central:
    image: samply/secret-sync-central:latest
    environment:
      # Url of the local beam proxy
      - BEAM_URL=http://proxy:8082
      # App id of this beam app
      - BEAM_ID=secret-sync.central.broker
      - BEAM_SECRET=${BEAM_SECRET_FOR_THIS_APP}

      # Optional keycloak parameters
      - KEYCLOAK_URL=http://keycloak:8080
      # Client id of the keycloak client which has to have permissions to create clients
      - KEYCLOAK_ID=my_keycloak_admin
      # The client secret for the client
      - KEYCLOAK_SECRET=my_secret
```

## Secret types

### OIDC
Register an Open ID Connect client at the central half of this component.

Secret type: `OIDC`  
Arguments: A comma seperated list of urls permitted for redirection  

Example:
`OIDC:MY_OIDC_CLIENT_SECRET:https://foo.com,https://bar.com`
