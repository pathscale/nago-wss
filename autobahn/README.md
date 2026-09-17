# Autobahn

[Autobahn](https://github.com/crossbario/autobahn-testsuite) is the conformance
suite for RFC 6455. It drives an echo server through about five hundred cases
and records what each one did.

`examples/autobahn_server.rs` is that echo server. The suite itself runs in CI,
because it ships as a Docker image and `wstest` needs Python 2, neither of which
belongs on a development machine.

## What is excluded, and why

Sections 12 and 13 only. They are `permessage-deflate`, which this crate does
not implement: nothing negotiates the extension, so a peer that sets a reserved
bit is speaking a protocol that was never agreed to and the frame is refused.
That is the correct answer to those cases, but the suite scores them against a
compressor, so running them would only measure a feature that is deliberately
absent.

Everything else runs, including the 9.x throughput cases.

## Passing

A case passes with `OK`, or with `NON-STRICT` where the RFC allows more than one
answer. Anything else is a failure. The suite writes its verdict per case into
`reports/servers/index.json`; read that, and treat any behavior that is not one
of those two as a failure.

## Running it yourself

    cargo run --release --example autobahn_server &
    docker run --rm --network host \
        -v "$PWD/autobahn:/config" \
        -v "$PWD/autobahn/reports:/config/reports" \
        crossbario/autobahn-testsuite \
        wstest --mode fuzzingclient --spec /config/fuzzingclient.json

The report lands in `autobahn/reports/servers/index.html`.
