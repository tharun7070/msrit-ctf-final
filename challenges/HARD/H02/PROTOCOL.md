# The Recursive Freeway: Routing Protocol
No other missions or external data are needed.

Define F(junction) recursively. All arithmetic is over 32-bit unsigned integers.

- If `kind == "terminal"`: `F(junction) = seed`.
- If `kind == "branch"`: `F(junction) = (((17*F(left) + 31*F(right) + salt) XOR mask) AND 0xffffffff)`.

Compute `v = F(destination)` using memoization. Format `v` as exactly eight lowercase hexadecimal digits: `h = f"{v:08x}"`.
Compute `sha256(h.encode("ascii")).hexdigest()[:8]`.

Submit the single string `FLAG{h_digest8}` where `h` and `digest8` are replaced by their computed values. No spaces. Do **not** submit the literal placeholder.
