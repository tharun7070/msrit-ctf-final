#!/usr/bin/env python3
"""H02 reference solver: recover the unique weighted freeway district.

Strategy (mirrors PROTOCOL.md):

  1. load template.json / junctions.json as weighted graphs;
  2. local-structure search - find every induced 12-junction district whose
     topology matches the blueprint (an unweighted induced subgraph
     isomorphism).  Because the network is near-regular this prunes nothing by
     degree and returns several near-miss candidates (the weight-only decoys);
  3. weighted spectral verification - keep the candidate whose **weighted
     normalised Laplacian** fingerprint equals the blueprint's.  Exactly one
     survives;
  4. flag assembly - order the matched district's junctions by descending
     weighted eigenvector centrality and concatenate their label fragments.
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


def centrality_order(nodes, G):
    """Junctions sorted by descending weighted eigenvector centrality."""
    A = weighted_adjacency(nodes, G)
    _, vecs = np.linalg.eigh(A)
    v = vecs[:, -1]
    if v.sum() < 0:
        v = -v
    sc = {n: float(v[i]) for i, n in enumerate(nodes)}
    return sorted(nodes, key=lambda n: -sc[n])


def solve():
    out = L.out_dir("H02")
    T, J = load_graphs(out)
    tpl_fp = spectral_fingerprint(list(T.nodes()), T)

    # -- local-structure search (topology only; ignores weights) --------------
    t0 = time.time()
    topo = list(GraphMatcher(J, T).subgraph_monomorphisms_iter())
    search_time = time.time() - t0

    # -- weighted spectral verification --------------------------------------
    winners = []
    for m in topo:                              # m maps junction-node -> template
        cand = list(m.keys())
        if spectral_fingerprint(cand, J.subgraph(cand)) == tpl_fp:
            winners.append(cand)

    assert len(winners) == 1, f"expected a unique weighted district, got {len(winners)}"
    matched = sorted(winners[0])
    order = centrality_order(matched, J.subgraph(matched))
    body = "".join(J.nodes[n]["label"] for n in order)
    flag = "FTA{" + body + "}"
    assert flag == L.FLAGS["H02"], flag

    all_deg = {d for _, d in J.degree()}
    print(f"[H02] junction network: {J.number_of_nodes()} nodes, "
          f"{J.number_of_edges()} weighted edges, degrees {sorted(all_deg)} "
          f"(degree filter prunes nothing)")
    print(f"[H02] topological induced matches: {len(topo)} "
          f"({len(topo) - 1} near-miss decoys) in {search_time:.2f}s")
    print(f"[H02] weighted-normalised-Laplacian fingerprint: {tpl_fp}")
    print(f"[H02] unique spectral match -> junctions {matched}")
    print(f"[H02] PASS -> {flag}")
    return flag


if __name__ == "__main__":
    solve()
