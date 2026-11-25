#!/usr/bin/env python3
"""H02 reference solver: recover the unique weighted freeway district.

Strategy (the full stack, in order):

  1. load template.json / junctions.json as weighted graphs;
  2. local-structure search - find every district whose topology matches the
     blueprint (an unweighted subgraph isomorphism).  The network is
     near-regular so this prunes nothing by degree and returns several
     near-miss candidates;
  3. invariant A - keep candidates whose **weighted normalised Laplacian**
     fingerprint (ascending, 4 dp) equals the blueprint's.  This is necessary
     but NOT sufficient: a district whose weights are all doubled has the same
     normalised spectrum, so TWO districts survive;
  4. invariant B - keep the candidate whose **weighted spanning-tree count** tau
     (a Laplacian cofactor) equals the blueprint's.  tau is not determined by
     the normalised spectrum (normalisation erases a uniform scale), so exactly
     one district survives;
  5. derivation - order the matched district's junctions by a TWO-KEY spectral
     sort: principal weighted-adjacency eigenvector (centrality) DESCENDING,
     rounded to 4 dp, ties broken by the weighted-normalised-Laplacian Fiedler
     vector ASCENDING - then concatenate the label fragments.

Traps defeated along the way:
  * reading the district in ascending junction-id order (the bait in
    PROTOCOL.md) yields a well-formed but WRONG token;
  * reading the scaled dead-end district in its own correct order yields a
    different well-formed but WRONG token;
  * using only the first eigenvector (single-key centrality) also mis-orders.
"""
import json
import sys
import time
from pathlib import Path

import networkx as nx
import numpy as np
from networkx.algorithms.isomorphism import GraphMatcher

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L


def load_graphs(out):
    tpl_json = json.loads((out / "template.json").read_text(encoding="utf-8"))
    jn_json = json.loads((out / "junctions.json").read_text(encoding="utf-8"))

    T = nx.Graph()
    T.add_nodes_from(n["id"] for n in tpl_json["nodes"])
    for u, v, w in tpl_json["edges"]:
        T.add_edge(u, v, weight=w)

    J = nx.Graph()
    for n in jn_json["nodes"]:
        J.add_node(n["id"], label=n["label"])
    for u, v, w in jn_json["edges"]:
        J.add_edge(u, v, weight=w)
    return T, J


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
    """Weighted spanning-tree count tau (Laplacian cofactor) - invariant B."""
    A = weighted_adjacency(nodes, G)
    Lap = np.diag(A.sum(axis=1)) - A
    cof = Lap[:-1, :-1]
    return int(round(float(np.linalg.det(cof))))


def centrality_values(nodes, G):
    A = weighted_adjacency(nodes, G)
    _, vecs = np.linalg.eigh(A)
    v = vecs[:, -1]
    if v.sum() < 0:
        v = -v
    return v


def fiedler_values(nodes, G):
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
    c = centrality_values(nodes, G)
    f = fiedler_values(nodes, G)
    key = {n: (-round(float(c[i]), 4), round(float(f[i]), 6))
           for i, n in enumerate(nodes)}
    return sorted(nodes, key=lambda n: key[n])


def single_key_order(nodes, G):
    c = centrality_values(nodes, G)
    sc = {n: float(c[i]) for i, n in enumerate(nodes)}
    return sorted(nodes, key=lambda n: -sc[n])


def solve():
    out = L.out_dir("H02")
    T, J = load_graphs(out)
    tpl_fp = spectral_fingerprint(list(T.nodes()), T)
    tpl_tau = spanning_tree_weight(list(T.nodes()), T)

    # -- local-structure search (topology only; ignores weights) --------------
    t0 = time.time()
    topo = list(GraphMatcher(J, T).subgraph_monomorphisms_iter())
    search_time = time.time() - t0

    # -- invariant A: weighted normalised-Laplacian spectrum ------------------
    passA = [list(m.keys()) for m in topo
             if spectral_fingerprint(list(m.keys()), J.subgraph(m.keys())) == tpl_fp]

    # -- invariant B: weighted spanning-tree count ----------------------------
    passB = [cand for cand in passA
             if spanning_tree_weight(cand, J.subgraph(cand)) == tpl_tau]

    assert len(passB) == 1, f"expected a unique invariant-B district, got {len(passB)}"
    matched = sorted(passB[0])
    order = combined_order(matched, J.subgraph(matched))
    body = "".join(J.nodes[n]["label"] for n in order)
    flag = "FTA{" + body + "}"
    assert flag == L.FLAGS["H02"], flag

    # -- demonstrate the traps ------------------------------------------------
    naive = single_key_order(matched, J.subgraph(matched))
    naive_token = "FTA{" + "".join(J.nodes[n]["label"] for n in naive) + "}"
    index_token = "FTA{" + "".join(J.nodes[n]["label"] for n in matched) + "}"

    all_deg = {d for _, d in J.degree()}
    print(f"[H02] junction network: {J.number_of_nodes()} nodes, "
          f"{J.number_of_edges()} weighted edges, degrees {sorted(all_deg)} "
          f"(degree filter prunes nothing)")
    print(f"[H02] topological induced matches: {len(topo)} in {search_time:.2f}s")
    print(f"[H02] invariant A (norm.-Laplacian fingerprint): {tpl_fp}")
    print(f"[H02] invariant A survivors: {len(passA)} "
          f"(1 real + 1 scaled dead end)")
    print(f"[H02] invariant B (spanning-tree tau): {tpl_tau}")
    print(f"[H02] invariant B survivors: {len(passB)} -> junctions {matched}")
    print(f"[H02] trap: naive index-order token = {index_token}")
    print(f"[H02] trap: single-key centrality token = {naive_token}")
    print(f"[H02] floor: two-key spectral order = {order}")
    print(f"[H02] PASS -> {flag}")
    return flag


if __name__ == "__main__":
    solve()
