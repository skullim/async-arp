default:
    just --list

_create-interface interface_name:
    ./scripts/create_interface.sh {{ interface_name }}

_init-network interface_name:
    just _create-interface {{ interface_name }}
    ./scripts/setup_interface.sh {{ interface_name }}

_remove-interface interface_name:
    ./scripts/remove_interface.sh {{ interface_name }}

_assign-capabilities script:
    #!/usr/bin/env sh
    for file in $( .{{ script }}); do
    ./scripts/setup_net_raw.sh "$file"
    done

_assign-test-capabilities:
    just _assign-capabilities /scripts/find_test_files.sh

_assign-examples-capabilities:
    just _assign-capabilities /scripts/find_example_files.sh

_build-tests:
    cargo test --no-run

_run-tests:
    cargo test

test:
    just _init-network dummy0
    just _create-interface down_dummy
    just _build-tests
    just _assign-test-capabilities
    just _run-tests
    just _remove-interface down_dummy
    just _remove-interface dummy0

publish:
    cargo build --all-targets
    just test
    cargo publish

run-example name interface:
    cargo build --examples
    just _assign-examples-capabilities
    cargo run --example {{ name }} -- -i {{ interface }}

run-spinner:
    just run-example probe-spinner wlp4s0

run-client:
    just run-example probe-client wlp4s0
