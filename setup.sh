
#!/bin/bash
set -e

echo "[?] Checking submodules ..."
git submodule init
git submodule update

echo "[?] Checking rust_fuzzer ..."
cd rust_fuzzer
cargo build --release
cd -

echo "[?] Checking rust_fuzzer_debug ..."
cd rust_fuzzer_debug
cargo build --release
cd -

echo "[*] Done ... "