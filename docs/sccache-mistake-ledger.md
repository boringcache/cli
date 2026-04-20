# sccache / WebDAV Mistake Ledger

This ledger captures the first source-backed guardrails for the next adapter rewrite pass. The source column is the authority; current BoringCache behavior only shows where to preserve or improve compatibility.

| Failure class | False assumption | Source-backed invariant | Owning layer | Guardrail test | Residual risk |
| --- | --- | --- | --- | --- | --- |
| WebDAV keys treated as arbitrary URL paths | The proxy can normalize or reshape sccache paths freely | sccache stores by `normalize_key(key)`, which maps a cache key to `a/b/c/<key>` under the WebDAV root/key prefix | sccache WebDAV engine boundary | Round-trip test preserves the exact path sccache sends and reads only the internal root tag | Future wrappers must not add a second normalization layer |
| `.sccache_check` stored like a user artifact | Capability probes are ordinary cache entries | sccache storage `check` reads and writes `.sccache_check` to determine read/write capability | sccache WebDAV route/probe handling | Probe tests accept `GET`, `HEAD`, and `PUT` without publishing a normal cache object | A richer engine should keep probe metrics separate from artifact metrics |
| WebDAV key prefix only applied to artifacts | sccache probes always hit `/.sccache_check` at the endpoint root | sccache config delegates key prefix/root to OpenDAL, so `.sccache_check` is read and written under the configured root too | sccache WebDAV route/probe handling and adapter env planning | Prefixed probe route test accepts `/rust/ci/.sccache_check`; dry-run JSON includes `SCCACHE_WEBDAV_KEY_PREFIX` from `[adapters.sccache].sccache-key-prefix` | Basic/bearer auth remains intentionally unconfigured for the local proxy because BoringCache's local WebDAV endpoint is anonymous |
| `MKCOL` treated as unsupported noise | sccache only sends object `GET`/`HEAD`/`PUT` | WebDAV/OpenDAL may create parent collections before writes; compatible cache servers differ on directory creation behavior | sccache WebDAV route handling | `MKCOL` returns success as a no-op | Some WebDAV clients may use `PROPFIND`; add only when real sccache/OpenDAL traffic requires it |
| Read backend errors fail the build by default | Any failed read must become a hard proxy error | sccache storage maps not found and unexpected read errors to cache misses, allowing compilation to continue | sccache read engine and BoringCache strictness policy | Miss/error tests distinguish cache miss, timeout, and strict proxy errors | Product decision remains open for how visibly infrastructure read failures should surface outside strict mode |
| Cache payload inspected as a filesystem archive | sccache artifact bytes can be interpreted by BoringCache | sccache cache entries are opaque binary payloads produced by sccache, internally a cache-entry zip of compressed compile outputs | sccache WebDAV engine | PUT/GET tests preserve exact bytes | Future diagnostics must report byte movement and hit/miss state without parsing payload contents |
| Auth shape narrowed to anonymous endpoint only | Adapter support only needs `SCCACHE_WEBDAV_ENDPOINT` | sccache supports endpoint, key prefix, basic auth username/password, and bearer token configuration | adapter command env wiring and manual proxy docs | Adapter env tests cover endpoint and key prefix; docs name basic/bearer auth as source behavior but not local-proxy config | Current `boringcache sccache` wrapper intentionally does not configure basic or bearer auth because the local proxy endpoint is anonymous |

## Research Sources

- sccache WebDAV docs: endpoint, key prefix/root, and credentials.
- sccache configuration docs: file and environment variables for WebDAV endpoint, key prefix, username/password, and bearer token.
- sccache `WebdavCache::build`: delegation to OpenDAL WebDAV with endpoint/root/auth configuration.
- sccache `Storage` implementation: read miss handling, write behavior, `.sccache_check`, and key normalization.
- OpenDAL WebDAV behavior: parent collection creation and compatible server differences.

Add a row before or with each sccache/WebDAV engine change. The row should name the official source, the corrected invariant, the test that prevents regression, and whether the remaining risk is CLI, proxy, or user workflow.
