# crowsi-key-provider

Request a limited signature from a key provider that does not export the private key.

## What you can do

- Bind signing to a declared purpose and digest.
- Use a closed provider interface for protected keys.

## Current scope

Platform backends must be provisioned and verified separately. Defining a provider port does not prove that hardware custody is available.

Package distribution is not activated by this documentation. Use the checked-in source and the declared dependency versions; published availability must be verified separately.

## Getting started

Install Rust 1.97 or newer and make the declared dependencies available. Use the configured private registry when a dependency is not distributed publicly. Run from this repository:

```sh
cargo test --locked
```

## Documentation and source

[Usage guide](docs/getting-started.md)

[Schemas](schemas) · [Implementation and public interfaces](src) · [Verification cases](tests) · [Contributing](CONTRIBUTING.md) · [Security reporting](SECURITY.md) · [License](LICENSE) · [Attribution notices](NOTICE)
