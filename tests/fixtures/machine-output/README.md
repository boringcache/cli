# Machine Output Fixtures

These fixtures are product contracts, not convenient test blobs.

`boringcache/one`, benchmarks, release scripts, and customer automation consume
CLI JSON as an API. If a fixture changes, review the consumer impact before
blessing the new output.

Update these only when the corresponding feature inventory entry under
`web/.planning/features/cli-machine-output-contracts.md` explains the contract
change and the consuming surfaces have been checked.
