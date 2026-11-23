# PROTOCOL - Freeway Ring Recovery

Two handoffs are attached to this job:

* `template.json` - a 12-node ring reference ("the template").
* `junctions.json` - a large freeway-junction network.

Exactly one set of 12 junctions in the network forms an **induced** subgraph
isomorphic to the template (two of your twelve are linked here if and only if
the matching template pair is linked there). Each junction in `junctions.json`
carries a short `label` fragment.

## 1. Fingerprint (uniqueness check)

To confirm you have the right twelve, compute the **Laplacian eigenvalue
fingerprint** of the induced subgraph they form:

* build the graph `L = D - A` over your twelve junctions, where `D` is the
  diagonal degree matrix and `A` is the adjacency matrix (of the induced
  twelve-node subgraph only);
* take its eigenvalues, sort them ascending, and round each to 4 decimals;
* this 12-number signature is the fingerprint. It must match the fingerprint
  of `template.json` computed the same way. A wrong twelve will not match.

## 2. Flag construction

Let each template node have canonical order `tpl_index` (0..11). Follow the
isomorphism from the template onto your twelve junctions and read their
`label` fragments in ascending `tpl_index` order. Concatenate the fragments
verbatim (no separators) to get the flag body, then wrap it as
`FTA{<body>}`.

Report the fingerprint you used and the assembled token.
