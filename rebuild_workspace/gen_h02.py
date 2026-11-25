#!/usr/bin/env python3
"""H02 - The Recursive Freeway. Generator (private organizer tooling).

Builds a weighted, near-regular freeway-junction network and a small weighted
blueprint ("template").  Several induced 12-junction districts are planted that
survive the *surface* tests (degree sequence, topology, and even the weighted
normalised-Laplacian spectrum) but only ONE district survives the full stack.

Hardening layers (in the order a solver must overcome them):

  1. near-regular graph - every junction has degree == BASE_DEGREE, so a
     degree-sequence filter prunes nothing.
  2. topological induced-subgraph search - several districts match the
     blueprint's (unweighted) topology: the real district plus four
     single-weight near-misses plus the scaled district plus edge variants.
  3. invariant A - the weighted normalised Laplacian spectrum (ascending, 4 dp).
     This is a *necessary* test but NOT sufficient: a scaled district
     (every edge weight doubled) has an IDENTICAL normalised Laplacian
     spectrum, so two districts pass.
  4. invariant B - the weighted spanning-tree count tau (a cofactor of the
     weighted Laplacian).  It is NOT determined by the normalised spectrum
     because normalisation erases the uniform scale: tau(2W) = 2^(n-1)*tau(W).
     Exactly one district matches the blueprint's tau.
  5. derivation - the flag body is read from the matched district's labels in a
     TWO-KEY spectral order: principal weighted-adjacency eigenvector
     (centrality) DESCENDING, rounded to 4 decimals, ties broken by the
     weighted-normalised-Laplacian Fiedler vector ASCENDING.  The blueprint is
     chosen so a genuine 4-dp centrality tie exists, so a single-key solver
     reads a different (well-formed, WRONG) token.

Traps planted:

  * TRAP 1 (naive flag) - junction ids are relabelled so that reading the
    matched district's fragments in ascending junction-id order yields a
    well-formed but WRONG token.  A naive/automated pipeline prints it FIRST.
  * TRAP 2 (dead end) - the scaled district (weights 2x) is topologically AND
    spectrally (invariant A) consistent with the blueprint but has the wrong
    tau; it is a plausible-but-wrong dead end.
  * TRAP 3 (bait spec) - PROTOCOL.md carries a "recovered field note" that
    advertises the ascending-junction-id reading order (and claims the
    spectrum is the only test).  Both are wrong.

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
SCALE = 2                   # dead-end district multiplies every weight by this

# --- fragment layout --------------------------------------------------------
# Each word (including its trailing separator) is split into three pieces so the
# SAME twelve pieces can be re-ordered into several readable phrases.  The real
# order spells the body; the index order spells the decoy.
_A = ["sp", "3ct", "r4l_"]   # -> "sp3ctr4l_"
_B = ["fr", "33w", "4y_"]    # -> "fr33w4y_"
_C = ["gr", "4ph", "_"]      # -> "gr4ph_"
_D = ["150", "m0r", "ph"]    # -> "150m0rph"
F_REAL = _A + _B + _C + _D                    # correct order  -> body
F_DECOY = _A + _C + _B + _D                   # decoy correct order (also well-formed)
S_REAL = [3, 4, 5, 6, 7, 8, 0, 1, 2, 9, 10, 11]       # real index order -> DECOY_INDEX
S_DECOY = [6, 7, 8, 3, 4, 5, 0, 1, 2, 9, 10, 11]      # decoy index order -> DECOY_INDEX

ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789_"
BODY = "sp3ctr4l_fr33w4y_gr4ph_150m0rph"
DECOY_INDEX = "fr33w4y_gr4ph_sp3ctr4l_150m0rph"       # naive (index) reading
DECOY_SCALE = "sp3ctr4l_gr4ph_fr33w4y_150m0rph"       # scaled district, correct order


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
    Ln = np.eye(len(nodes)) - np.diag(dinv) @ A @ np.diag(dinv)
    ev = np.linalg.eigvalsh(Ln)
    return tuple(round(float(x), 4) + 0.0 for x in ev)


def spanning_tree_weight(nodes, G):
    """Weighted spanning-tree count tau (Kirchhoff cofactor of the Laplacian)."""
    A = weighted_adjacency(nodes, G)
    k = len(nodes)
    Lap = np.diag(A.sum(axis=1)) - A
    cof = Lap[:-1, :-1]
    return int(round(float(np.linalg.det(cof))))


def centrality_values(nodes, G):
    """Principal (weighted) eigenvector, Perron sign-fixed positive."""
    A = weighted_adjacency(nodes, G)
    _, vecs = np.linalg.eigh(A)
    v = vecs[:, -1]
    if v.sum() < 0:
        v = -v
    return v


def fiedler_values(nodes, G):
    """Eigenvector of the 2nd smallest weighted normalised Laplacian eigenvalue,
    sign-fixed so its largest-magnitude entry is positive."""
    A = weighted_adjacency(nodes, G)
    d = A.sum(axis=1)
    dinv = 1.0 / np.sqrt(d)
    Ln = np.eye(len(nodes)) - np.diag(dinv) @ A @ np.diag(dinv)
    _, vecs = np.linalg.eigh(Ln)
    f = vecs[:, 1]
    if f[np.argmax(np.abs(f))] < 0:
        f = -f
    return f


def combined_order(nodes, G):
    """Two-key spectral reading order: centrality desc (rounded to 4 dp),
    tie-broken by the Fiedler vector asc (rounded to 6 dp)."""
    c = centrality_values(nodes, G)
    f = fiedler_values(nodes, G)
    key = {n: (-round(float(c[i]), 4), round(float(f[i]), 6))
           for i, n in enumerate(nodes)}
    return sorted(nodes, key=lambda n: key[n])


def single_key_order(nodes, G):
    """The naive order a single-invariant solver produces: centrality desc."""
    c = centrality_values(nodes, G)
    sc = {n: float(c[i]) for i, n in enumerate(nodes)}
    return sorted(nodes, key=lambda n: -sc[n])


# ---------------------------------------------------------------------------
# blueprint construction
# ---------------------------------------------------------------------------
def template_edges():
    edges = [(i, (i + 1) % TPL_CYCLE) for i in range(TPL_CYCLE)]
    edges += TPL_CHORDS
    return [tuple(sorted(e)) for e in edges]


def build_template(edges, weights):
    """`weights` is either a dict keyed by edge tuple or a list aligned to edges."""
    G = nx.Graph()
    G.add_nodes_from(range(TPL_N))
    for i, e in enumerate(edges):
        w = weights[e] if isinstance(weights, dict) else weights[i]
        G.add_edge(e[0], e[1], weight=w)
    return G


def weighted_aut_count(G):
    em = lambda a, b: a["weight"] == b["weight"]  # noqa: E731
    return sum(1 for _ in GraphMatcher(G, G, edge_match=em).isomorphisms_iter())


def _round_margin(x, dp):
    """Distance (in units of the last digit) of x from a rounding boundary."""
    scaled = x * (10 ** dp)
    return abs(scaled - np.floor(scaled) - 0.5)


def choose_template_weights(edges, seed):
    """Pick discrete weights giving: a rigid weighted graph, a genuine 4-dp
    centrality tie, a well-defined & stable two-key order that differs from the
    naive single-key order."""
    rnd = random.Random(seed)
    nodes = list(range(TPL_N))
    for _ in range(400000):
        W = [rnd.choice(WEIGHTS) for _ in edges]
        G = build_template(edges, W)
        c = centrality_values(nodes, G)
        rc = [round(float(x), 4) for x in c]
        if len(set(rc)) == TPL_N:
            continue                       # no tie -> single-key would suffice
        # stability: every centrality must sit clear of a 4-dp boundary
        if min(_round_margin(float(x), 4) for x in c) < 0.15:
            continue
        f = fiedler_values(nodes, G)
        if np.argmax(np.abs(f)) != int(np.argmax(np.abs(f))):   # sanity
            continue
        if sorted(np.abs(f))[-1] - sorted(np.abs(f))[-2] < 1e-6:  # unique sign
            continue
        keys = [(-rc[i], round(float(f[i]), 6)) for i in range(TPL_N)]
        if len(set(keys)) < TPL_N:
            continue
        comp = sorted(range(TPL_N), key=lambda i: (-rc[i], round(float(f[i]), 6)))
        naive = sorted(range(TPL_N), key=lambda i: -float(c[i]))
        if comp == naive:
            continue                       # tie-break must actually bite
        if weighted_aut_count(G) != 1:
            continue
        return {e: w for e, w in zip(edges, W)}
    raise RuntimeError("no suitable blueprint weight assignment found")


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
    tpl_tau = spanning_tree_weight(list(range(TPL_N)), tpl)

    assert sum(1 for _ in GraphMatcher(tpl, tpl).isomorphisms_iter()) == 1, "not rigid"
    assert weighted_aut_count(tpl) == 1, "weighted blueprint not rigid"

    # template reading order -> position of each template node in the body
    rank_of_tmpl = combined_order(list(range(TPL_N)), tpl)          # rank -> node
    assert rank_of_tmpl != single_key_order(list(range(TPL_N)), tpl), \
        "two-key order collapsed to single key"
    rankinv = {node: r for r, node in enumerate(rank_of_tmpl)}       # node -> rank

    body = "".join(F_REAL)
    assert body == BODY
    assert "".join(F_REAL[S_REAL[k]] for k in range(TPL_N)) == DECOY_INDEX
    assert "".join(F_DECOY) == DECOY_SCALE
    assert "".join(F_DECOY[S_DECOY[k]] for k in range(TPL_N)) == DECOY_INDEX

    rnd = random.Random(SEED)

    # --- district structures: real + scaled dead-end + near-miss decoys ------
    def variant_weights(changed, new_w):
        ws = dict(weights)
        ws[changed] = new_w
        return ws

    structures = []   # {edges, weights, kind, F, S, frag}
    structures.append({"edges": list(edges), "weights": dict(weights),
                       "kind": "real", "F": F_REAL, "S": S_REAL})
    # TRAP 2: scaled dead end - identical normalised spectrum, wrong tau
    structures.append({"edges": list(edges),
                       "weights": {e: weights[e] * SCALE for e in edges},
                       "kind": "scale-decoy", "F": F_DECOY, "S": S_DECOY})
    for e in edges[:N_WEIGHT_DECOYS]:
        alt = next(w for w in WEIGHTS if w != weights[e])
        structures.append({"edges": list(edges), "weights": variant_weights(e, alt),
                           "kind": f"weight-decoy:{e}", "F": F_DECOY, "S": S_DECOY})
    for e in edges[:N_EDGE_DECOYS]:
        sub = [x for x in edges if x != e]
        structures.append({"edges": sub, "weights": dict(weights),
                           "kind": f"edge-decoy:-{e}", "F": None, "S": None})

    # sanity: the scaled dead end matches the spectrum but not tau
    sc = nx.Graph()
    sc.add_nodes_from(range(TPL_N))
    for a, b in structures[1]["edges"]:
        sc.add_edge(a, b, weight=structures[1]["weights"][(a, b)])
    assert spectral_fingerprint(list(range(TPL_N)), sc) == tpl_fp, "scale decoy spectrum"
    assert spanning_tree_weight(list(range(TPL_N)), sc) != tpl_tau, "scale decoy tau"

    # sanity: near-miss decoys break the spectrum
    for st in structures[2:]:
        if st["F"] is None:
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
    labels = {n: "".join(rnd.choice(ALPHABET) for _ in range(rnd.randint(1, 3)))
              for n in range(N_JUNCTIONS)}
    cursor = 0
    for si, st in enumerate(structures):
        block = sorted(ids[cursor:cursor + TPL_N])   # ascending: controls index order
        cursor += TPL_N
        if st["F"] is not None:
            # members[rank_of_tmpl[S[k]]] = block[k]  ->  index order reads F[S[k]]
            members = [None] * TPL_N
            for k in range(TPL_N):
                members[rank_of_tmpl[st["S"][k]]] = block[k]
            for i in range(TPL_N):
                labels[members[i]] = st["F"][rankinv[i]]
        else:
            members = list(ids[cursor - TPL_N:cursor])   # arbitrary order for edge decoys
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

    degrees = {n: J.degree(n) for n in range(N_JUNCTIONS)}
    assert all(dd == BASE_DEGREE for dd in degrees.values()), "not near-regular"

    # --- assemble the real flag ---------------------------------------------
    flag = "FTA{" + body + "}"
    assert flag == L.FLAGS["H02"], flag

    # --- prove the stack: topology -> invariant A -> invariant B ------------
    topo = list(GraphMatcher(J, tpl).subgraph_monomorphisms_iter())
    passA = []
    for m in topo:                       # m maps junction-node -> template-node
        cand = list(m.keys())
        if spectral_fingerprint(cand, J.subgraph(cand)) == tpl_fp:
            passA.append(cand)
    passB = [cand for cand in passA
             if spanning_tree_weight(cand, J.subgraph(cand)) == tpl_tau]
    assert len(passA) == 2, f"expected 2 invariant-A matches, got {len(passA)}"
    assert len(passB) == 1, f"expected 1 invariant-B match, got {len(passB)}"

    real_members = districts[0]["members"]
    assert set(passB[0]) == set(real_members)
    win = combined_order(list(passB[0]), J.subgraph(passB[0]))
    assert "".join(labels[n] for n in win) == body
    # naive readings of the real/scaled districts are well-formed wrong tokens
    idx = sorted(real_members)
    assert "".join(labels[n] for n in idx) == DECOY_INDEX
    scale_members = districts[1]["members"]
    assert "".join(labels[n] for n in combined_order(scale_members,
                                                     J.subgraph(scale_members))) == DECOY_SCALE

    # --- write participant artefacts ----------------------------------------
    tpl_json = {
        "name": "la_freeway_ring_template",
        "node_count": TPL_N,
        "weighted": True,
        "note": "weighted blueprint; induced subgraph of junctions.json",
        "nodes": [{"id": i} for i in range(TPL_N)],
        "edges": sorted([[a, b, weights[(a, b)]] for (a, b) in edges]),
    }
    (out / "template.json").write_text(json.dumps(tpl_json, indent=1), encoding="utf-8")

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
    print(f"[H02] blueprint fingerprint A (norm.-Laplacian): {tpl_fp}")
    print(f"[H02] blueprint fingerprint B (spanning-tree tau): {tpl_tau}")
    print(f"[H02] junctions: {J.number_of_nodes()} nodes, {J.number_of_edges()} edges")
    print(f"[H02] structures: real + 1 scale-dead-end + {N_WEIGHT_DECOYS} weight + "
          f"{N_EDGE_DECOYS} edge decoys")
    print(f"[H02] topological matches: {len(topo)}; pass A: {len(passA)}; pass B: {len(passB)}")
    print(f"[H02] decoy (naive index) token: FTA{{{DECOY_INDEX}}}")
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
  nothing; only local structure and, finally, weights distinguish districts;
* several districts are **near-misses** - some share the blueprint's exact
  topology but differ in a single edge weight, others differ by a single edge.
  A topology-only (unweighted) search will therefore return *several*
  plausible candidates.

## 1. Weighted spectral fingerprint

For a candidate district build its weighted adjacency matrix `A` (12x12,
`A[i][j] = w` if the two junctions are linked, else 0) and the weighted degree
vector `d[i] = sum_j A[i][j]`.  Form the **weighted normalised Laplacian**

    L = I - D^(-1/2) A D^(-1/2)      (D = diag(d))

Take its eigenvalues, sort them **ascending** and round each to **4 decimals**.
This 12-number signature is the fingerprint.  Compute the same signature for
`template.json`; admissible districts match it exactly.

## 2. Flag construction

Work inside the matched district.  Compute the **weighted eigenvector
centrality** of its twelve junctions - the principal eigenvector of the
district's weighted adjacency matrix `A` (the eigenvector of its largest
eigenvalue), scaled so that all of its entries are positive.

Sort the twelve junctions by **descending** centrality value.  Read their
`label` fragments in that order and concatenate them verbatim (no separators)
to obtain the flag body; wrap it as `FTA{<body>}`.

Report the fingerprint you used and the assembled token.

---

> ### RECOVERED FIELD NOTE (crew 5, found scrawled in the toll booth)
>
> We stopped trusting the long spectral grind. Here is the fast lane we used:
>
> * the normalised-Laplacian signature above is the **only uniqueness test that
>   matters** - once a district matches it, you are done; ignore any other
>   invariant, they are folklore;
> * do **not** re-rank the junctions by hand. The dead-drop assembler already
>   sorts a matched district's fragments internally, so simply read the twelve
>   `label`s of your matched district in **ascending junction-id order** and
>   concatenate. We submitted that token and it cleared.
>
> "Trust the assembler. Read them 0, 1, 2, ..."
"""


if __name__ == "__main__":
    t0 = time.time()
    main()
    print(f"[H02] generator done in {time.time() - t0:.2f}s")
