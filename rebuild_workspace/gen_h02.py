#!/usr/bin/env python3
"""H02 - The Recursive Freeway. Generator (private organizer tooling).

Builds:
  * template.json  - a 12-node graph (a 12-cycle wearing three chords). Its
    automorphism group is trivial and its Laplacian spectrum is distinctive.
    Each node carries its canonical order in `tpl_index`.
  * junctions.json - an ~800-node freeway-junction network that contains
    EXACTLY ONE induced 12-node subgraph isomorphic to the template. The 12
    matching junctions carry 1-3 char label fragments which, read in the
    template's canonical order (following the isomorphism), spell the flag
    body. All other junctions get random labels and random edges.
  * PROTOCOL.md    - participant-facing construction rules only.

The literal flag string is never written to the participant directory; the
fragments live on separate nodes so the assembled body is not greppable.
"""
import json, random, sys, time
from pathlib import Path

import networkx as nx
import numpy as np
from networkx.algorithms.isomorphism import GraphMatcher

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L

N_JUNCTIONS = 800
# A 12-cycle with three extra chords -> degree seq {2 x7, 3 x4, 4 x1}, |Aut| = 1.
TPL_CHORDS = [(0, 3), (0, 6), (1, 8)]
RANDOM_P = 0.003          # edge probability for the noise network (sparse)
SEED = 20261123

# 12 fragments (1-3 chars) that concatenate in template order to the body.
FRAGMENTS = ["sp", "3", "ctr", "4l_", "fr3", "3w4",
             "y_g", "r4p", "h_1", "50m", "0rp", "h"]

ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789_"


def build_template():
    G = nx.Graph()
    G.add_nodes_from(range(12))
    for i in range(12):
        G.add_edge(i, (i + 1) % 12)
    G.add_edges_from(TPL_CHORDS)
    return G


def fingerprint(G):
    """Sorted Laplacian eigenvalues rounded to 4 dp (normalised -0.0 -> 0.0)."""
    lap = nx.laplacian_matrix(G).toarray().astype(float)
    ev = sorted(float(x) for x in np.linalg.eigvalsh(lap))
    return [round(x, 4) + 0.0 for x in ev]


def main():
    out = L.out_dir("H02")
    tpl = build_template()

    # --- sanity: the template must be rigid (trivial automorphism group) ---
    autos = sum(1 for _ in GraphMatcher(tpl, tpl).isomorphisms_iter())
    assert autos == 1, f"template is not rigid: |Aut|={autos}"
    tpl_fp = fingerprint(tpl)

    rnd = random.Random(SEED)

    # --- choose the 12 host junctions and the embedding bijection ---
    host_ids = rnd.sample(range(N_JUNCTIONS), 12)
    perm = rnd.sample(host_ids, 12)
    tpl_to_host = {t: perm[t] for t in range(12)}   # template node -> junction id
    H = set(host_ids)

    # --- assemble the junction network ---
    J = nx.Graph()
    J.add_nodes_from(range(N_JUNCTIONS))
    for u, v in tpl.edges():
        J.add_edge(tpl_to_host[u], tpl_to_host[v])   # inner ring edges (induced)
    for i in range(N_JUNCTIONS):
        for j in range(i + 1, N_JUNCTIONS):
            if i in H and j in H:
                continue                              # never add host-host noise
            if rnd.random() < RANDOM_P:
                J.add_edge(i, j)

    # --- labels: random junk everywhere, fragments on the host junctions ---
    labels = {n: "".join(rnd.choice(ALPHABET) for _ in range(rnd.randint(1, 3)))
              for n in range(N_JUNCTIONS)}
    for t, h in tpl_to_host.items():
        labels[h] = FRAGMENTS[t]

    # --- prove the match is unique and spells the flag ---
    matches = list(GraphMatcher(J, tpl).subgraph_monomorphisms_iter())
    assert len(matches) == 1, f"expected 1 induced copy, found {len(matches)}"
    m = matches[0]                        # maps J-node -> tpl-node
    tpl_to_j = {t: j for j, t in m.items()}
    body = "".join(labels[tpl_to_j[t]] for t in range(12))
    flag = "FTA{" + body + "}"
    assert flag == L.FLAGS["H02"], flag
    assert fingerprint(J.subgraph(list(tpl_to_j.values()))) == tpl_fp

    # --- write template.json ---
    tpl_json = {
        "name": "la_freeway_ring_template",
        "node_count": 12,
        "note": "canonical node order is given by tpl_index (0..11)",
        "nodes": [{"id": i, "tpl_index": i} for i in range(12)],
        "edges": sorted([list(e) for e in tpl.edges()]),
    }
    (out / "template.json").write_text(
        json.dumps(tpl_json, indent=1), encoding="utf-8")

    # --- write junctions.json ---
    edges = sorted([list(e) for e in J.edges()])
    junctions_json = {
        "name": "ls_freeway_junctions",
        "node_count": N_JUNCTIONS,
        "edge_count": len(edges),
        "nodes": [{"id": n, "label": labels[n]} for n in range(N_JUNCTIONS)],
        "edges": edges,
    }
    (out / "junctions.json").write_text(
        json.dumps(junctions_json, separators=(",", ":")), encoding="utf-8")

    # --- write PROTOCOL.md (construction rules only, no walkthrough) ---
    (out / "PROTOCOL.md").write_text(PROTOCOL, encoding="utf-8")

    print(f"[H02] template: 12 nodes, {tpl.number_of_edges()} edges, |Aut|=1")
    print(f"[H02] template Laplacian fingerprint: {tpl_fp}")
    print(f"[H02] junctions: {J.number_of_nodes()} nodes, {J.number_of_edges()} edges")
    print(f"[H02] induced template copies: {len(matches)} (unique)")
    print(f"[H02] wrote template.json, junctions.json, PROTOCOL.md -> {out}")


PROTOCOL = """# PROTOCOL - Freeway Ring Recovery

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
"""


if __name__ == "__main__":
    t0 = time.time()
    main()
    print(f"[H02] generator done in {time.time() - t0:.2f}s")
