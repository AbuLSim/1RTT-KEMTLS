Running the version on Linux-like systems:

First add to the file /etc/hosts the following:
	127.0.0.1	servername


Then install dependencies:
Install Rust from: https://www.rust-lang.org/tools/install
Install Pipenv (Python virtualenv manager), libssl-dev (C crypto library)
cmake (packaging installer), Clang and LLVM (cross compilor and linker); 
The compilation *might* work without clang and llvm.

	sudo apt-get install -qq -y pipenv libssl-dev cmake clang-12 llvm-12
	
Then go to:
	cd rustls/rustls-mio

And build/run the implementation by typing:
	cargo run --example tlsclient -- -p 10001 --http --auth-certs ../../certificates/1RTT-KEMTLS/client.crt --auth-key ../../certificates/1RTT-KEMTLS/client.key --1rtt-pk ../../certificates/1RTT-KEMTLS/kem.pub --1rtt-epoch ../../certificates/1RTT-KEMTLS/client.epoch --cached-certs ../../certificates/1RTT-KEMTLS/kem.crt servername
The previous command connects the client to the server on port 10001 with http mode, and asks it to authenticate itself
and to use the semi-static one round trip KEMTLS mode with some pre-distributed server certificate.

This should allow the client to run 1RTT-KEMTLS. **Note** : the client should output something like

START: 802 ns
CREATED PDK ENCAPSULATION: 3769335 ns
CREATED PDK 1RTT-KEMTLS ENCAPSULATION: 3802500 ns
CREATING KEYSHARES: 3815137 ns
CREATED KEYSHARES: 3847169 ns
SENDING CHELO: 3877561 ns
EMIT CERT: 4164007 ns

with a panic at the end this is because we do not have a server running.

To run the server type :

	cargo run --example tlsserver -- --certs ../../certificates/1RTT-KEMTLS/kem.crt --key ../../certificates/1RTT-KEMTLS/kem.key --1rtt-key ../../certificates/1RTT-KEMTLS/kem.key --port 10001 --require-auth --1rtt-epoch ../../certificates/1RTT-KEMTLS/server.epoch  --auth ../../certificates/1RTT-KEMTLS/client-ca.crt http

Then rerun the client.