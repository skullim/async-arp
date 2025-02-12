init-network:
    ./scripts/setup_dummy_interface.sh

assign-capabilities:
    #!/usr/bin/env sh
    for file in $(./scripts/find_test_files.sh); do
    ./scripts/setup_net_raw.sh "$file"
    done

build-tests:
    cargo test --no-run

run-tests:
    cargo test

test: && init-network build-tests assign-capabilities run-tests

publish:
    just test
    cargo publish

    
