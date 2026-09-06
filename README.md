# Simple JWT Authenticator

[![Test](https://github.com/p0is0n/simple-jwt-authenticator/actions/workflows/test.yml/badge.svg)](https://github.com/p0is0n/simple-jwt-authenticator/actions/workflows/test.yml) [![Deploy](https://github.com/p0is0n/simple-jwt-authenticator/actions/workflows/deploy.yml/badge.svg)](https://github.com/p0is0n/simple-jwt-authenticator/actions/workflows/deploy.yml)

A lightweight, security-focused JWT authentication service for reverse
proxies and trusted HTTP infrastructure.

`simple-jwt-authenticator` verifies JWT credentials and provides a
trusted authentication decision that reverse proxies can use to protect
HTTP applications and services.

It is designed for deployments where authentication is centralized
outside the protected application, keeping JWT verification explicit,
reusable, and operationally independent.

Typical use cases include internal applications, APIs, dashboards,
self-hosted services, and other HTTP workloads protected by trusted
reverse-proxy infrastructure.

## Features

-   RS256 JWT signature verification;
-   public-key-only server operation;
-   issuer and audience validation;
-   `exp`, `nbf`, and `iat` validation;
-   configurable clock skew;
-   required-claim validation;
-   `Authorization: Bearer` authentication;
-   authentication-cookie support;
-   deterministic credential precedence;
-   claim-based authentication policies;
-   exact and regular-expression claim matching;
-   logical `AND` and `OR` claim expressions;
-   reverse-proxy authentication handlers;
-   Prometheus metrics;

## Quick start

> [!WARNING]
> `simple-jwt-authenticator` is under active development.
> Configuration and behavior may change between releases.
> Review the release notes carefully before updating.

Create directories for the server configuration and JWT verification
key:

``` sh
mkdir -p config secrets
```

The deployment now has the following structure:

``` text
.
├── config/
└── secrets/
```

### Generate an RSA key pair

Generate a 4096-bit RSA private key:

``` sh
openssl genpkey \
  -algorithm RSA \
  -pkeyopt rsa_keygen_bits:4096 \
  -out secrets/jwt-private.pem
```

Generate the corresponding public key:

``` sh
openssl pkey \
  -in secrets/jwt-private.pem \
  -pubout \
  -out secrets/jwt-public.pem
```

Restrict access to the private key:

``` sh
chmod 600 secrets/jwt-private.pem
```

The directory now contains:

``` text
.
├── config/
└── secrets/
    ├── jwt-private.pem
    └── jwt-public.pem
```

`jwt-private.pem` is sensitive signing material. It is used to issue
JWTs and must be protected accordingly.

The authenticator server does not need the private key. Only
`jwt-public.pem` will be mounted into the server container.

For a production deployment, keep the private signing key outside the
authenticator runtime and make it available only to trusted
token-generation environments.

### Create the server configuration

Create `config/server.yaml`:

``` sh
cat > config/server.yaml <<'EOF'
authentication:
  handlers:
    http:
      nginx:
        enabled: true

  extractors:
    http:
      authorization_header:
        enabled: true

      cookie:
        enabled: true
        name: "auth_token"

jwt:
  algorithm: "RS256"
  public_key_file: "/run/secrets/jwt-public.pem"
  issuer: "home-auth"
  audience:
    - "internal-services"
  default_ttl: 1h
  max_ttl: 168h
  clock_skew: 30s

metrics:
  enabled: true
  path: "/metrics"

logging:
  level: "info"
  format: "json"
EOF
```

This configuration:

-   enables the Nginx authentication handler;
-   accepts Bearer credentials from the `Authorization` header;
-   accepts JWTs from the `auth_token` cookie;
-   verifies RS256 signatures with the mounted public key;
-   requires issuer `home-auth`;
-   requires audience `internal-services`;
-   enables Prometheus metrics at `/metrics`;

Change the issuer and audience to match the tokens issued by your
environment.

### Start with Docker

Start the server directly from the published image:

``` sh
docker run -d \
  --name simple-jwt-authenticator \
  --restart unless-stopped \
  -p 8080:8080 \
  -v "$(pwd)/config/server.yaml:/config/server.yaml:ro" \
  -v "$(pwd)/secrets/jwt-public.pem:/run/secrets/jwt-public.pem:ro" \
  ghcr.io/p0is0n/simple-jwt-authenticator:latest \
  /config/server.yaml
```

### Verify the server

Check that the container is running:

``` sh
docker ps --filter name=simple-jwt-authenticator
```

Inspect the startup logs if needed:

``` sh
docker logs simple-jwt-authenticator
```

Then verify the HTTP health endpoint:

``` sh
curl http://localhost:8080/healthz
```

Expected response:

``` text
ok
```

At this point the authenticator is running and ready to be connected to
a supported authentication handler.

## How it works

`simple-jwt-authenticator` sits on the authentication path between
trusted HTTP infrastructure and a protected application.

``` text
Client
  |
  | HTTP request + JWT credential
  v
Reverse proxy
  |
  | authentication request
  v
simple-jwt-authenticator
  |
  | extract credential
  | verify JWT signature
  | validate JWT claims
  | evaluate additional claim policy, if present
  v
Authentication decision
  |
  +---- failure ----> request rejected
  |
  +---- success ----> authenticated identity
                         |
                         v
                    Reverse proxy
                         |
                         v
                 Protected application
```

The reverse proxy receives the authentication decision and determines
whether the original application request may continue.

On successful authentication, normalized identity information can be
returned to the trusted proxy and propagated to the protected
application.

The authenticator does not proxy the original application request.

Application authorization that depends on resources, ownership, database
state, business permissions, or other application context remains the
responsibility of the reverse proxy, protected application, or another
authorization component.

## Handlers

Handlers integrate `simple-jwt-authenticator` with a particular reverse
proxy or HTTP authentication protocol.

A handler owns the integration-specific HTTP contract while using the
same JWT authentication core.

Currently supported handlers:

  Handler   Integration            Endpoint        Status
  --------- ---------------------- --------------- -----------
  `nginx`   Nginx `auth_request`   `/auth/nginx`   Supported

### Nginx `auth_request`

The Nginx handler implements the authentication contract required by the
Nginx `auth_request` module.

Authentication endpoint:

``` text
GET /auth/nginx
```

Successful authentication:

``` text
204 No Content
```

Normal authentication failure:

``` text
401 Unauthorized
```

Nginx uses the authentication response to decide whether the original
protected request may continue.

### Basic Nginx configuration

``` nginx
location = /_auth {
    internal;

    proxy_pass http://authenticator:8080/auth/nginx;

    proxy_pass_request_body off;
    proxy_set_header Content-Length "";

    proxy_set_header Authorization $http_authorization;
    proxy_set_header Cookie $http_cookie;

    proxy_connect_timeout 2s;
    proxy_send_timeout 2s;
    proxy_read_timeout 2s;
}

location / {
    auth_request /_auth;

    auth_request_set $auth_subject  $upstream_http_x_auth_subject;
    auth_request_set $auth_username $upstream_http_x_auth_username;
    auth_request_set $auth_email    $upstream_http_x_auth_email;

    proxy_set_header X-Auth-Subject  $auth_subject;
    proxy_set_header X-Auth-Username $auth_username;
    proxy_set_header X-Auth-Email    $auth_email;

    proxy_pass http://protected_upstream;
}
```

The `/_auth` location is marked `internal`, preventing external clients
from directly invoking the Nginx-side authentication location.

The authenticator itself is a separate service. Access to it should be
restricted according to the deployment trust boundary using private
networking, firewall rules, container networking, or equivalent
infrastructure controls.

### Request body

JWT authentication does not require the protected application request
body.

The authentication subrequest therefore uses:

``` nginx
proxy_pass_request_body off;
proxy_set_header Content-Length "";
```

The authentication subrequest does not consume or unnecessarily forward
the protected request body. After successful authentication, the
original body remains available to the protected upstream.

### Identity propagation

After successful authentication, Nginx can capture normalized identity
returned by the authenticator:

``` nginx
auth_request_set $auth_subject  $upstream_http_x_auth_subject;
auth_request_set $auth_username $upstream_http_x_auth_username;
auth_request_set $auth_email    $upstream_http_x_auth_email;
```

and explicitly propagate it to the protected application:

``` nginx
proxy_set_header X-Auth-Subject  $auth_subject;
proxy_set_header X-Auth-Username $auth_username;
proxy_set_header X-Auth-Email    $auth_email;
```

Client-supplied identity headers must never be trusted as authenticated
identity.

For example, a client can send:

``` http
X-Auth-Subject: administrator
X-Auth-Username: root
```

but those values do not represent authenticated identity.

The trusted reverse proxy must overwrite or remove client-supplied
identity values and propagate only identity obtained from the
authenticator.

Protected applications should trust these headers only when requests
arrive through the expected trusted proxy.

### Claim expressions

Claim expressions apply additional constraints to JWT claims after the
normal configured JWT validation succeeds.

An exact subject requirement:

``` text
subject == "camera-front"
```

A subject and audience requirement:

``` text
subject == "camera-front" && audience == "frigate"
```

Multiple accepted subjects:

``` text
subject == "camera-front" || subject == "camera-back"
```

Regular-expression matching:

``` text
subject ~= "^camera-[a-z]+$"
```

Expressions can be grouped:

``` text
(
    subject == "camera-front" ||
    subject == "camera-back"
) &&
audience == "frigate"
```

Supported expression operators are:

``` text
==    exact, case-sensitive equality
~=    regular-expression matching
&&    logical AND
||    logical OR
()    grouping
```

Claim expressions currently support:

``` text
subject
issuer
audience
id
username
email
```

Additional claim expressions never replace the server's configured JWT
validation.

Conceptually, authentication requires:

``` text
valid signature
AND
required claims
AND
temporal validation
AND
configured issuer
AND
configured audience
AND
additional claim expression, if present
```

A dynamic expression can therefore make authentication more restrictive,
but it cannot make an otherwise invalid JWT valid.

### Trusted Nginx claim policy

Mandatory route policy should be owned by trusted infrastructure rather
than by the client.

For example, Nginx can assign a policy to a protected camera route:

``` nginx
location /camera/ {
    set $auth_claim_expression 'subject ~= "^camera-[a-z]+$"';

    auth_request /_auth;

    proxy_pass http://camera_upstream;
}
```

The internal authentication location can pass that Nginx-controlled
policy to the authenticator:

``` nginx
location = /_auth {
    internal;

    proxy_pass http://authenticator:8080/auth/nginx;

    proxy_pass_request_body off;
    proxy_set_header Content-Length "";

    proxy_set_header Authorization $http_authorization;
    proxy_set_header Cookie $http_cookie;
    proxy_set_header X-Auth-Claim-Expression $auth_claim_expression;

    proxy_connect_timeout 2s;
    proxy_send_timeout 2s;
    proxy_read_timeout 2s;
}
```

The trust boundary is:

``` text
Client
  |
  | credentials + application request
  v
Nginx
  |
  | credentials + Nginx-owned route policy
  v
simple-jwt-authenticator
  |
  | JWT verification + policy enforcement
  v
Authentication decision
```

Do not use a client-controlled header as a mandatory route ACL.

For example, this is unsafe for a mandatory trusted policy:

``` nginx
proxy_set_header X-Auth-Claim-Expression $http_x_auth_claim_expression;
```

because `$http_x_auth_claim_expression` originates from the client. A
client-controlled policy can be omitted or changed by that same client.

### Failure behavior

Authentication infrastructure should fail closed.

If the authenticator rejects the credential, the protected request must
not continue.

If the authenticator is unavailable or the authentication subrequest
cannot produce a trustworthy decision, Nginx should also reject the
request rather than bypass authentication.

Bounded authentication-upstream timeouts are recommended:

``` nginx
proxy_connect_timeout 2s;
proxy_send_timeout 2s;
proxy_read_timeout 2s;
```

Nginx `auth_request` interprets authentication responses as:

``` text
2xx         allow
401 / 403   deny
other       authentication subrequest error
```

Consequently, malformed authentication input that produces
`400 Bad Request` when calling the authenticator directly is normally
treated by Nginx as an authentication-subrequest error rather than being
converted into an ordinary credential failure.

## CLI

`simple-jwt-authenticator` includes a command-line interface for working
with configuration and JWT tokens without running the authentication
server.

The CLI is distributed as a separate container image:

```text
ghcr.io/p0is0n/simple-jwt-authenticator-cli
```

```sh
docker run --rm \
  ghcr.io/p0is0n/simple-jwt-authenticator-cli:latest \
  --help
```

For example:

```sh
docker run --rm \
  ghcr.io/p0is0n/simple-jwt-authenticator-cli:latest \
  token generate --help
```

and:

```sh
docker run --rm \
  ghcr.io/p0is0n/simple-jwt-authenticator-cli:latest \
  token validate --help
```

### Generate a token

The CLI can generate RS256 JWTs using a configured private signing key:

```sh
docker run --rm \
  -v "$(pwd)/config/cli.yaml:/config/cli.yaml:ro" \
  -v "$(pwd)/secrets:/run/secrets:ro" \
  ghcr.io/p0is0n/simple-jwt-authenticator-cli:latest \
  token generate \
  --config /config/cli.yaml \
  --subject camera-front \
  --audience frigate \
  --ttl 1h
```

Optional identity claims can also be supplied:

```sh
docker run --rm \
  -v "$(pwd)/config/cli.yaml:/config/cli.yaml:ro" \
  -v "$(pwd)/secrets:/run/secrets:ro" \
  ghcr.io/p0is0n/simple-jwt-authenticator-cli:latest \
  token generate \
  --config /config/cli.yaml \
  --subject camera-front \
  --audience frigate \
  --username camera \
  --email camera@example.com \
  --ttl 1h
```

Private signing keys are sensitive material. Mount them only into trusted
environments that are explicitly responsible for issuing tokens.

### Validate a token

The CLI can verify a token using the same JWT validation rules used by the
authentication core:

```sh
docker run --rm \
  -v "$(pwd)/config/cli.yaml:/config/cli.yaml:ro" \
  -v "$(pwd)/secrets:/run/secrets:ro" \
  ghcr.io/p0is0n/simple-jwt-authenticator-cli:latest \
  token validate \
  --config /config/cli.yaml \
  --token "$TOKEN"
```

A token can also be validated against an additional claim expression:

```sh
docker run --rm \
  -v "$(pwd)/config/cli.yaml:/config/cli.yaml:ro" \
  -v "$(pwd)/secrets:/run/secrets:ro" \
  ghcr.io/p0is0n/simple-jwt-authenticator-cli:latest \
  token validate \
  --config /config/cli.yaml \
  --token "$TOKEN" \
  --claim-expression 'subject == "camera-front" && audience == "frigate"'
```

The claim expression is evaluated in addition to the configured JWT
validation policy. It cannot make an otherwise invalid token valid.

## License

This project is distributed under the terms specified in the
[`LICENSE`](LICENSE) file.
