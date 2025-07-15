# ethereum_ecdsa_verifier

> A simple, no-frills ECDSA verifier for Ethereum signatures in Rust.

This crate allows you to verify Ethereum ECDSA signatures against known Ethereum addresses using the standard signing prefix and recovery method. It's ideal for validating signatures produced by wallets like MetaMask.

---

## ✨ Features

- Verifies Ethereum-style ECDSA signatures (`0x...` format).
- Recovers Ethereum addresses from message + signature.
- Implements Ethereum's signed message prefix and Keccak256 hashing.
- Fully tested with `libsecp256k1`.

---

## 📦 Installation

Add this crate to your `Cargo.toml`:

```toml
[dependencies]
ethereum-ecdsa-verifier = "0.1.0"
```

> Note: You will also need `libsecp256k1` and `easy-hasher` dependencies (these are re-exported).

---

## 🚀 Usage

```rust
use ethereum_ecdsa_verifier::validate_ecdsa_signature;

fn main() {
    let message = "4RvWUp3E9YerY78Kn5UyyEQPTiFs0tIr/mhAeCbwIpY=".to_string();
    let address = "0xd1798d6b74ef965d6a60f45e0036f44aed3dfa1b".to_string();
    let signature = "0x88bd1f104e132178aea55731be455a5c91b3e15b46f2599e9472d926270d458f4116eea0273fb5dc36238992154afc652aa7c1d91569b596db00146b4e5443fa1b".to_string();

    let is_valid = validate_ecdsa_signature(&signature, &message, &address)
        .expect("Validation failed");

    println!("Is signature valid? {}", is_valid);
}
```

---

## 📖 How it works

- Hashes the message using Ethereum’s prefix:
  ```
  "\x19Ethereum Signed Message:\n" + message.length + message
  ```
- Computes Keccak256 of the prefixed message.
- Recovers the public key from the signature using `libsecp256k1`.
- Hashes the uncompressed public key (excluding 0x04 prefix) and extracts the last 20 bytes to get the address.
- Compares the recovered address with the given one.

---

## ✅ Tests

Run:

```bash
cargo test
```

---

## 🔒 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.# ethereum-ecdsa-verifier
