# CurveX25519 elliptic curve cryptography

This is a pure-Rust implementation of the [Curve25519/X25519](https://en.wikipedia.org/wiki/Curve25519) elliptic curve.
It's a constant-time algorithm, transliterated from the provided C as I worked through the superb explanatory text:

[Martin Kleppmann. 2022. Implementing Curve25519/X25519: A Tutorial on Elliptic Curve Cryptography. 1, 1 (October 2022), 34 pages.](https://martin.kleppmann.com/papers/curve25519.pdf)

It's a pretty faithful mapping of the C code, with some minor amendments. Notably, I've re-ordered the `out` buffer to come last in the function signatures, so watch out with your function calls! To be more idiomatic, you could `impl` methods on a `FieldElem`, if desired.

Note that the code was handwritten (no LLMs were harmed in the making of).

> ![WARNING]
> It should go without saying, but please don't use this for real-world applications. The code here is purely for educative purposes.
