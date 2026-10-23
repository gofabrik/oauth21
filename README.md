# oauth21

OAuth 2.1 authorization server library for Go.

> Work in progress, not ready for production use yet.

## Scope

- Authorization code with PKCE, client credentials, refresh tokens.
- Revocation, introspection and authorization server metadata.
- Endpoints are `http.Handler` functions, mounted on your own router.
- Storage is behind interfaces; an in-memory implementation is included.
- Login and consent are handled by your application.

## Conformance

Targets draft-ietf-oauth-v2-1-16 and RFC 9700. The spec texts are in `conformance/specs`.

## Development

Requires Go 1.26+ and Task. Run `task check`.

## License

Apache-2.0
