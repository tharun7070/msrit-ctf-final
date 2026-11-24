#!/usr/bin/env python3
"""H02 - The Recursive Freeway. Generator (private organizer tooling).

Builds a *weighted, near-regular* freeway-junction network and a small weighted
blueprint ("template").  Exactly ONE induced 12-junction district in the
network is isomorphic to the blueprint **including edge weights**; several
near-miss districts are planted that are indistinguishable from the real one by
degree sequence, triangle counts or plain topology.

Hardening layers baked in here:

  1. near-regular graph - every junction has degree == BASE_DEGREE, so a
     degree-sequence filter prunes nothing.  The template's local structure
     (triangle / clustering counts) is necessary but NOT sufficient.
  2. weighted structure - edges carry weights from a tiny discrete set
     {1,2,3}; the uniqueness fingerprint is the **weighted normalised
     Laplacian** spectrum, so exact weights must be matched.
  3. near-miss decoys - N_WEIGHT_DECOYS districts share the template's topology
     but differ in a single edge weight (a plain isomorphic search *does* find
     them -> plausible-but-wrong candidates); N_EDGE_DECOYS differ by a single
     edge.  Only one district matches the weighted fingerprint.
  4. non-trivial flag assembly - the flag body is read from the matched
     district's node labels ordered by **weighted eigenvector centrality**
     (principal eigenvector of the weighted adjacency), not by node index.
  5. sizes kept small (a few thousand nodes) but n**k brute force is hopeless.

The literal flag string is never written to the participant directory; the 12
fragments live on separate junctions so the assembled body is not greppable.
"""
import json
import random
import sys
import time
from pathlib import Path

import networkx as nx
import numpy as np
from networkx.algorithms.isomorphism import GraphMatcher

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L  # noqa: E402

N_JUNCTIONS = 2500          # network size (a few thousand -> n**k infeasible)
BASE_DEGREE = 4             # every junction has this total degree (near-regular)
WEIGHTS = (1, 2, 3)         # discrete edge-weight alphabet
TPL_N = 12                  # blueprint size
TPL_CYCLE = 12
TPL_CHORDS = [(0, 3), (0, 6), (1, 8)]   # rigid 12-cycle wearing three chords
SEED = 20261124

N_WEIGHT_DECOYS = 4         # topology-identical, one weight changed
N_EDGE_DECOYS = 3           # one edge removed

# 12 fragments (1-3 chars) that concatenate (in centrality order) to the body.
FRAGMENTS = ["sp", "3", "ctr", "4l_", "fr3", "3w4",
             "y_g", "r4p", "h_1", "50m", "0rp", "h"]

ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789_"


# ---------------------------------------------------------------------------
# graph-invariant helpers (shared semantics with the reference solver)
# ---------------------------------------------------------------------------
def weighted_adjacency(nodes, G):
    idx = {n: i for i, n in enumerate(nodes)}
    A = np.zeros((len(nodes), len(nodes)), dtype=float)
    for u, v, data in G.edges(data=True):
        if u in idx and v in idx:
            w = float(data.get("weight", 1.0))
            A[idx[u], idx[v]] = w
            A[idx[v], idx[u]] = w
    return A


def spectral_fingerprint(nodes, G):
    """Weighted normalised Laplacian spectrum, ascending, rounded to 4 dp."""
    A = weighted_adjacency(nodes, G)
    d = A.sum(axis=1)
    dinv = 1.0 / np.sqrt(d)
    Dinv = np.diag(dinv)
    Ln = np.eye(len(nodes)) - Dinv @ A @ Dinv
    ev = np.linalg.eigvalsh(Ln)
    return tuple(round(float(x), 4) + 0.0 for x in ev)


def centrality_scores(nodes, G):
    """Principal eigenvector (weighted) of the adjacency, sign-fixed positive."""
    A = weighted_adjacency(nodes, G)
    _, vecs = np.linalg.eigh(A)
    v = vecs[:, -1]                       # eigenvector of the largest eigenvalue
    if v.sum() < 0:                       # Perron vector -> all entries positive
        v = -v
    return {n: float(v[i]) for i, n in enumerate(nodes)}


def centrality_order(nodes, G):
    """Junctions sorted by descending weighted eigenvector centrality."""
    sc = centrality_scores(nodes, G)
    return sorted(nodes, key=lambda n: -sc[n])


# ---------------------------------------------------------------------------
# blueprint construction
# ---------------------------------------------------------------------------
def template_edges():
    edges = [(i, (i + 1) % TPL_CYCLE) for i in range(TPL_CYCLE)]
    edges += TPL_CHORDS
    return [tuple(sorted(e)) for e in edges]


def choose_template_weights(edges, seed):
    """Pick discrete weights so the principal eigenvector has well-separated
    coordinates (a stable, unambiguous centrality ordering)."""
    rnd = random.Random(seed)
    best, best_gap = None, -1.0
    for _ in range(4000):
        ws = {e: rnd.choice(WEIGHTS) for e in edges}
        G = nx.Graph()
        G.add_nodes_from(range(TPL_N))
        for e in edges:
            G.add_edge(e[0], e[1], weight=ws[e])
        vals = sorted(centrality_scores(list(range(TPL_N)), G).values())
        gap = min(vals[i + 1] - vals[i] for i in range(len(vals) - 1))
        if gap > best_gap:
            best_gap, best = gap, ws
        if gap > 1e-3:
            break
    return best


def build_template(edges, weights):
    G = nx.Graph()
    G.add_nodes_from(range(TPL_N))
    for e in edges:
        G.add_edge(e[0], e[1], weight=weights[e])
    return G


# ---------------------------------------------------------------------------
# network construction
# ---------------------------------------------------------------------------
def build_external_edges(need, set_id, rnd, attempts=400):
    """Random simple graph realising the per-node external-degree vector `need`,
    never placing an edge between two nodes of the same planted district."""
    N = len(need)
    for _ in range(attempts):
        remaining = list(need)
        edges = set()
        ok = True
        while True:
            active = [n for n in range(N) if remaining[n] > 0]
            if not active:
                break
            u = max(active, key=lambda n: (remaining[n], rnd.random()))
            cands = [v for v in active
                     if v != u and remaining[v] > 0
                     and (min(u, v), max(u, v)) not in edges
                     and not (set_id[u] is not None and set_id[u] == set_id[v])]
            if not cands:
                ok = False
                break
            v = max(cands, key=lambda n: (remaining[n], rnd.random()))
            edges.add((min(u, v), max(u, v)))
            remaining[u] -= 1
            remaining[v] -= 1
        if ok:
            return sorted(edges)
    raise RuntimeError("could not realise external-degree sequence")


def main():
    out = L.out_dir("H02")

    edges = template_edges()
    weights = choose_template_weights(edges, SEED)
    tpl = build_template(edges, weights)
    tpl_fp = spectral_fingerprint(list(range(TPL_N)), tpl)

    autos = sum(1 for _ in GraphMatcher(tpl, tpl).isomorphisms_iter())
    assert autos == 1, f"blueprint is not rigid: |Aut|={autos}"
    vals = sorted(centrality_scores(list(range(TPL_N)), tpl).values())
    assert min(vals[i + 1] - vals[i] for i in range(len(vals) - 1)) > 1e-3

    rnd = random.Random(SEED)

    # --- district structures: real template + near-miss decoys ---------------
    def variant_weights(changed_edge, new_weight):
        ws = dict(weights)
        ws[changed_edge] = new_weight
        return ws

    structures = []   # list of dicts: {edges, weights, kind}
    structures.append({"edges": list(edges), "weights": dict(weights), "kind": "real"})

    for e in edges[:N_WEIGHT_DECOYS]:
        alt = next(w for w in WEIGHTS if w != weights[e])
        structures.append({"edges": list(edges),
                           "weights": variant_weights(e, alt),
                           "kind": f"weight-decoy:{e}"})
    for e in edges[:N_EDGE_DECOYS]:
        sub = [x for x in edges if x != e]
        structures.append({"edges": sub, "weights": dict(weights),
                           "kind": f"edge-decoy:-{e}"})

    # sanity: decoy weighted spectra must differ from the template's
    for st in structures:
        if st["kind"] == "real":
            continue
        sub = nx.Graph()
        sub.add_nodes_from(range(TPL_N))
        for a, b in st["edges"]:
            sub.add_edge(a, b, weight=st["weights"][(a, b)])
        assert spectral_fingerprint(list(range(TPL_N)), sub) != tpl_fp, st["kind"]

    # --- allocate disjoint junction ids for every district -------------------
    ids = list(range(N_JUNCTIONS))
    rnd.shuffle(ids)
    set_id = [None] * N_JUNCTIONS
    needs = [BASE_DEGREE] * N_JUNCTIONS
    districts = []
    cursor = 0
    for si, st in enumerate(structures):
        members = ids[cursor:cursor + TPL_N]
        cursor += TPL_N
        for m in members:
            set_id[m] = si
        deg = {m: 0 for m in members}
        for a, b in st["edges"]:
            deg[members[a]] += 1
            deg[members[b]] += 1
        for m in members:
            needs[m] = BASE_DEGREE - deg[m]
            assert needs[m] >= 0, (st["kind"], needs[m])
        districts.append({"members": members, "structure": st})

    # --- build the junction network ------------------------------------------
    ext = build_external_edges(needs, set_id, rnd)
    J = nx.Graph()
    J.add_nodes_from(range(N_JUNCTIONS))
    for a, b in ext:
        J.add_edge(a, b, weight=rnd.choice(WEIGHTS))
    for d in districts:
        members, st = d["members"], d["structure"]
        for a, b in st["edges"]:
            J.add_edge(members[a], members[b], weight=st["weights"][(a, b)])

    # every junction must have degree == BASE_DEGREE (near-regular)
    degrees = {n: J.degree(n) for n in range(N_JUNCTIONS)}
    assert all(dd == BASE_DEGREE for dd in degrees.values()), "not near-regular"

    # --- labels: junk everywhere, the real fragments ordered by centrality ---
    labels = {n: "".join(rnd.choice(ALPHABET) for _ in range(rnd.randint(1, 3)))
              for n in range(N_JUNCTIONS)}
    real_members = districts[0]["members"]
    real_sub = J.subgraph(real_members)
    ordered = centrality_order(real_members, real_sub)
    for rank, node in enumerate(ordered):
        labels[node] = FRAGMENTS[rank]
    body = "".join(FRAGMENTS)
    flag = "FTA{" + body + "}"
    assert flag == L.FLAGS["H02"], flag

    # --- prove: topology finds several, only the weights pick one -----------
    topo = list(GraphMatcher(J, tpl).subgraph_monomorphisms_iter())
    winners = []
    for m in topo:                       # m maps junction-node -> template-node
        cand = list(m.keys())
        if spectral_fingerprint(cand, J.subgraph(cand)) == tpl_fp:
            winners.append(set(cand))
    assert len(winners) == 1, f"expected 1 weighted match, got {len(winners)}"
    assert winners[0] == set(real_members)
    win_order = centrality_order(list(winners[0]), J.subgraph(winners[0]))
    assert "".join(labels[n] for n in win_order) == body

    # --- write participant artefacts ----------------------------------------
    tpl_json = {
        "name": "la_freeway_ring_template",
        "node_count": TPL_N,
        "weighted": True,
        "note": "weighted blueprint; induced subgraph of junctions.json",
        "nodes": [{"id": i} for i in range(TPL_N)],
        "edges": sorted([[a, b, weights[(a, b)]] for (a, b) in edges]),
    }
    (out / "template.json").write_text(
        json.dumps(tpl_json, indent=1), encoding="utf-8")

    jn_edges = sorted([min(a, b), max(a, b), int(J.edges[a, b]["weight"])]
                      for a, b in J.edges())
    junctions_json = {
        "name": "ls_freeway_junctions",
        "weighted": True,
        "node_count": N_JUNCTIONS,
        "edge_count": len(jn_edges),
        "nodes": [{"id": n, "label": labels[n]} for n in range(N_JUNCTIONS)],
        "edges": jn_edges,
    }
    (out / "junctions.json").write_text(
        json.dumps(junctions_json, separators=(",", ":")), encoding="utf-8")

    (out / "PROTOCOL.md").write_text(PROTOCOL, encoding="utf-8")

    print(f"[H02] blueprint: {TPL_N} nodes, {len(edges)} weighted edges, |Aut|=1")
    print(f"[H02] blueprint weighted-norm-Laplacian fingerprint: {tpl_fp}")
    print(f"[H02] junctions: {J.number_of_nodes()} nodes, "
          f"{J.number_of_edges()} edges (all degree {BASE_DEGREE})")
    print(f"[H02] decoys planted: {N_WEIGHT_DECOYS} weight + {N_EDGE_DECOYS} edge")
    print(f"[H02] topological induced copies found: {len(topo)} "
          f"(weight-consistent: {len(winners)})")
    print(f"[H02] wrote template.json, junctions.json, PROTOCOL.md -> {out}")


PROTOCOL = """# PROTOCOL - Freeway Ring Recovery

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
"""


if __name__ == "__main__":
    t0 = time.time()
    main()
    print(f"[H02] generator done in {time.time() - t0:.2f}s")
