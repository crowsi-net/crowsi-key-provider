# Using crowsi-key-provider

Request a limited signature from a key provider that does not export the private key.

## Before you start

Platform backends must be provisioned and verified separately. Defining a provider port does not prove that hardware custody is available.

## First steps

Run from the repository root:

```sh
cargo test --locked
```

## How to assess the result

- Bind signing to a declared purpose and digest.
- Use a closed provider interface for protected keys.

A passing source-level check establishes only what that check observes. Keep missing configuration, unavailable services and unverified deployment paths visible.

## Continue reading

[Repository overview](../README.md)
