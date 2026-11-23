# Final getaway: intercepted encoding notes
All paths, names and systems are fictional.

Route rule: select the **one** car with `wanted = 0`, `clearance = YES`, and `fuel_km >= route_km`.

Derive a 32-byte key: `SHA256((plate + ":" + terminal).encode("ascii")).digest()`.
The sender encrypted the plain text with repeating XOR against the key bytes, then applied zlib compression, then ASCII85 encoding.

Reverse those three layers on the packet body (between markers). Submit the recovered message, including its exact braces.
