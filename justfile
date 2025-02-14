default:
    just --list

init-network:
    ./scripts/setup_dummy_interface.sh

assign-capabilities script:
    #!/usr/bin/env sh
    for file in $( .{{script}}); do
    ./scripts/setup_net_raw.sh "$file"
    done

assign-test-capabilities:
    just assign-capabilities /scripts/find_test_files.sh


assign-examples-capabilities:
    just assign-capabilities /scripts/find_example_files.sh

build-tests:
    cargo test --no-run

run-tests:
    cargo test

test: && init-network build-tests assign-test-capabilities run-tests

publish:
    cargo build --all-targets
    just test
    cargo publish

run-example name interface:
    cargo build --examples
    just assign-examples-capabilities
    cargo run --example {{name}} -- -i {{interface}}

run-spinner:
    just run-example probe-spinner wlp4s0

run-client:
    just run-example probe-client wlp4s0