# Runtime security sources

Python 3.12.16 is the official Docker Library linux/amd64 image pinned in `sources.lock.json`.
Its CPython/PSF license and third-party licenses remain in the image.

`http-client.patch` is a local security backport based on CPython's PSF-licensed
commit `1c8d928392cf0b4e84e392eb12f34557c9a0373f` (3.12 PR #160772, still open when reviewed)
and the optional-whitespace correction in merged main commit
`9f52b443c002cccfb54bda0706a9276b6b4a109d`. Original release file, patch and result
SHA-256 values are checked before installation. It is not described as an official
3.12 release patch or a complete HTTP parser rewrite.

- https://github.com/python/cpython/pull/160772
- https://github.com/python/cpython/commit/9f52b443c002cccfb54bda0706a9276b6b4a109d
- https://docs.python.org/3.12/license.html

SQLite 3.54.1 is compiled from the official source archive after SHA-256 and the
publisher's SHA3-256 check. SQLite is in the public domain. No SQLite CLI, zipfile
extension, compiler or source archive is copied to the application runtime.

- https://www.sqlite.org/download.html
- https://www.sqlite.org/copyright.html

pip 26.3 is installed from its exact hash-verified PyPI wheel. Its MIT license is
retained in the distribution metadata. Locks apply to the selected linux/amd64
container build; Windows host Python and its environment are not modified.

The CPython ensurepip bundle is locally updated to the same verified pip 26.3
wheel, and its single version constant is updated after before/after digest
checks. This is a local packaging change, not an upstream CPython release.
The ensurepip bootstrap algorithm remains unchanged.
