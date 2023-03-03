# Server/client authenticated and encrypted file transfer 

# Build and run

Install the rust development toolchain using [rustup](https://rustup.rs/).



## Server

```
RUST_LOG=debug cargo run --bin ftserv -- -c server-conf/ -l 127.0.0.1:8080
```

## Client

### Copy from client to server

```
RUST_LOG=debug cargo run --bin ftclient -- -c client-conf/ testpic.jpg 127.0.0.1:8080:testpic_on_server.jpg
```

### Copy from server to client

```
RUST_LOG=debug cargo run --bin ftclient -- -c client-conf/ 127.0.0.1:8080:testpic.jpg testpic_on_client.jpg
```
