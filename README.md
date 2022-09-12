# _Massayo_

Massayo is a small proof-of-concept Rust library based on [UnhookingPOC], which removes AV/EDR hooks in a given system DLL. I tried to reduce fingerprints by obfuscating strings and resolving any Windows API functions used dynamically. It loads a freshy copy of a chosen system DLL from System32 directory and replaces the .text section of the currently loaded DLL by its own. I'm not a Rust expert so I'm open to any kind of suggestions or help. 

## Usage

The function module::unhook_ntdll() is used to load a freshy copy of NTDLL.DLL, but you can also use module::unhook_system_dll in order to select a different one.

```rust
use massayo;
fn main() {
    if (massayo::module::unhook_ntdll()) {
        // Success
    } else {
        // Ooops! :(
    }
}
```

## License

MIT

   [UnhookingPOC]: <https://github.com/SolomonSklash/UnhookingPOC>
