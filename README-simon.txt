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
	cargo run --example tlsserver -- --certs ../../certificates/1RTT-KEMTLS/kem.crt --key ../../certificates/1RTT-KEMTLS/kem.key --1rtt-key ../../certificates/1RTT-KEMTLS/kem_ssrttkemtls.key --port 10001 --require-auth --1rtt-pk ../../certificates/1RTT-KEMTLS/kem_ssrttkemtls.pub --1rtt-epoch ../../certificates/1RTT-KEMTLS/server.epoch  --auth ../../certificates/1RTT-KEMTLS/client-ca.crt http

The previous command connects starts the server server on port 10001 with http mode, and requires the client to authenticate itself
and to use the semi-static one round trip KEMTLS mode with some pre-distributed server certificate.
(This might take some time to build)

Run the client:

	cargo run --example tlsclient -- -p 10001 --http --cafile ../../certificates/1RTT-KEMTLS/kem.chain.crt --auth-key ../../certificates/1RTT-KEMTLS/client.key --auth-certs ../../certificates/1RTT-KEMTLS/client.crt --1rtt-pk ../../certificates/1RTT-KEMTLS/kem_ssrttkemtls.pub --1rtt-epoch ../../certificates/1RTT-KEMTLS/client.epoch --cached-certs ../../certificates/1RTT-KEMTLS/kem.crt servername


The handshake should occurr and client should receive the message
"Hello world from rustls tlsserver"
