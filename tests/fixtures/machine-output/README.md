# Machine Output Fixtures

These fixtures are product contracts, not convenient test blobs.

`boringcache/one`, benchmarks, release scripts, and customer automation consume
CLI JSON as an API. If a fixture changes, review the consumer impact before
blessing the new output.

Update these only when the corresponding feature inventory entry under
`web/.planning/features/cli-machine-output-contracts.md` explains the contract
change and the consuming surfaces have been checked.

Fixtures may use placeholders for machine-local paths:

- `$HOME` for user-level setup paths.
- `$WORKSPACE_ROOT` for the temporary project root used by the fixture test.

Token fixtures use deterministic dummy values only. Do not paste real tokens or
credential-shaped production examples into this directory.
