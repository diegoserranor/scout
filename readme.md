# scout
Network discovery tool

## Usage
```bash
# Scan the 192.168.1.0/24 subnet from port 1 to 100
cargo run -- probe 192.168.1.0/24 1 100

# Scan the 192.168.1.50 ip from port 1 to 100
cargo run -- probe 192.168.1.50 1 100

# Get a list of the networks you are connected to
cargo run -- networks
```

