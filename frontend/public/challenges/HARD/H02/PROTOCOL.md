# PROTOCOL - Freeway Ring Recovery

Two handoffs are attached to this job:

* `template.json` - a **weighted** 12-node ring reference ("the blueprint").
  Each edge is `[u, v, w]` with an integer weight `w`.
* `junctions.json` - a large weighted freeway-junction network.  Each edge is
  `[u, v, w]`; each junction carries a short `label` fragment.

Work on the induced 12-junction district that matches the blueprint.  A district
is a set of twelve junctions; the edges considered are only those that run
**between two of the twelve** (weighted).

## What makes this hard

The network is deliberately adversarial:

* every junction has the **same total degree**, so degree filtering prunes
  nothing; only local structure (triangle / clustering counts) and, finally,
  weights distinguish districts;
* several districts are **near-misses** - some share the blueprint's exact
  topology but differ in a single edge weight, others differ by a single edge.
  A topology-only (unweighted) search will therefore return *several*
  plausible candidates.  Exactly one is correct.

## 1. Weighted spectral fingerprint (the decision)

For a candidate district build its weighted adjacency matrix `A` (12x12,
`A[i][j] = w` if the two junctions are linked, else 0) and the weighted degree
vector `d[i] = sum_j A[i][j]`.  Form the **weighted normalised Laplacian**

    L = I - D^(-1/2) A D^(-1/2)      (D = diag(d))

Take its eigenvalues, sort them **ascending** and round each to **4 decimals**.
This 12-number signature is the fingerprint.  Compute the same signature for
`template.json`; the correct district matches it exactly.  Every near-miss
except one fails this check; it is the only admissible uniqueness test.

## 2. Flag construction

Ordering rule (not node index): work inside the matched district and compute
the **weighted eigenvector centrality** of its twelve junctions - the principal
eigenvector of the district's weighted adjacency matrix `A` (the eigenvector of
its largest eigenvalue), scaled so that all of its entries are positive.

Sort the twelve junctions by **descending** centrality value.  Read their
`label` fragments in that order and concatenate them verbatim (no separators)
to obtain the flag body; wrap it as `FTA{<body>}`.

Report the fingerprint you used and the assembled token.
