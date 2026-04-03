# Noir Array Helpers

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Noir Array Helpers** is a Noir function library to manipulate arrays. This library serves a kitchen sink for various array functions the Noir community finds useful.

## WARNING!

| **It is not recommended to use versions of this library < `v0.30.0`**

This library was related to a vulnerability in [ecrecover](https://github.com/colinnielsen/ecrecover-noir) found by @olehmisar.
Vulnerability details can be found [here](https://gist.github.com/olehmisar/4cfe6128eaac2bfbe1fa8eb46f0116d6).

## Installation

In your `Nargo.toml` file, add the following dependency:

```toml
[dependencies]
array_helpers = { tag = "v0.30.2", git = "https://github.com/colinnielsen/noir-array-helpers" }
```

then `use` it in your circuits:

```rust
use dep::std;
use dep::array_helpers;

fn main(){
    let pub_key: [u8; 64] = [...];

    let (pub_key_x, pub_key_y) = split_u8_64(pub_key);
    std::println(pub_key_x);
    std::println(pub_key_y);
}
```

or

```rust
use dep::std;
use dep::array_helpers::split_u8_64;

fn main(){
let eth_addr_u8: [u8;20] = [...];

    let addr = array_helpers::u8_to_eth_address(pub_key_x, pub_key_y);
    std::println(addr);

}

```

## Usage

Here are the methods available in the library:

### `split_u8_64`

Splits an array of `u8` values, with a length of 64, into two arrays of `u8` values, each with a length of 32.

```rust
fn split_u8_64(arr: [u8; 64]) -> ([u8; 32], [u8; 32])
```

### `u8_32_to_u8_64`

Combines two arrays of `u8` values, each of length 32, into a single array of `u8` values, with a length of 64.

```rust
fn u8_32_to_u8_64(arr_a: [u8; 32], arr_b: [u8; 32]) -> [u8; 64]
```

### `u8_to_u160`

Converts an array of `u8` values to a `Field` value, representing a u160 value.

**NOTE**: These are also aliased to `u8_to_eth_address`, for readability.

```rust
fn u8_to_u160(array: [u8]) -> Field

fn u8_to_eth_address(array: [u8]) -> Field
```

### `u8_32s_to_u64_16`

Converts two arrays of `u8` values, each of length 32, to a single array of `u64` values, with a length of 16.

```rust
fn u8_32s_to_u64_16(arr_a: [u8; 32], arr_b: [u8; 32]) -> [u64; 16]
```

### `u64_4_to_u8_32`

Converts an array of `u64` values, with a length of 4, to an array of `u8` values, with a length of 32.

```rust
fn u64_4_to_u8_32(array: [u64; 4]) -> [u8; 32]
```

## License

This project is licensed under the MIT License. See the [LICENSE](https://github.com/colinnielsen/noir-array-helpers/blob/main/LICENSE) file for details.
