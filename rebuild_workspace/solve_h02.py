#!/usr/bin/env python3
"""H02 reference solver: recover the freeway ring by induced subgraph iso.

Strategy:
  1. load template.json / junctions.json;
  2. degree pre-filter - drop junctions whose degree is below the smallest
     template degree (they cannot appear in any induced copy);
  3. find the unique induced subgraph isomorphism with networkx GraphMatcher
     (subgraph_monomorphisms_iter == induced);
  4. verify the matched subgraph's Laplacian eigenvalue fingerprint equals the
     template's (the uniqueness check);
  5. assemble the flag body from the labels in canonical tpl_index order.
"""
import json, sys, time
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
    for n in tpl_json["nodes"]:
        T.add_node(n["id"], tpl_index=n["tpl_index"])
    T.add_edges_from(tpl_json["edges"])

    J = nx.Graph()
    for n in jn_json["nodes"]:
        J.add_node(n["id"], label=n["label"])
    J.add_edges_from(jn_json["edges"])
    return T, J


def fingerprint(G):
    """Sorted Laplacian eigenvalues rounded to 4 dp (-0.0 normalised to 0.0)."""
    lap = nx.laplacian_matrix(G).toarray().astype(float)
    ev = sorted(float(x) for x in np.linalg.eigvalsh(lap))
    return [round(x, 4) + 0.0 for x in ev]


def solve():
    out = L.out_dir("H02")
    T, J = load_graphs(out)
    order = sorted(T.nodes(), key=lambda n: T.nodes[n]["tpl_index"])
    tpl_fp = fingerprint(T)

    # -- degree pre-filter: every matched node has total degree >= min template degree
    min_deg = min(d for _, d in T.degree())
    cand = [n for n, d in J.degree() if d >= min_deg]
    Jc = J.subgraph(cand)

    t0 = time.time()
    matches = list(GraphMatcher(Jc, T).subgraph_monomorphisms_iter())
    search_time = time.time() - t0

    solutions = []
    for m in matches:                      # m maps junction-node -> template-node
        t_to_j = {t: j for j, t in m.items()}
        matched = [t_to_j[t] for t in order]
        sub_fp = fingerprint(J.subgraph(matched))
        if sub_fp != tpl_fp:
            continue
        body = "".join(J.nodes[t_to_j[t]]["label"] for t in order)
        solutions.append(("FTA{" + body + "}", sub_fp, matched))

    assert len(solutions) == 1, f"expected a unique solution, got {len(solutions)}"
    flag, sub_fp, matched = solutions[0]
    assert flag == L.FLAGS["H02"], flag

    print(f"[H02] junction network: {J.number_of_nodes()} nodes, "
          f"{J.number_of_edges()} edges")
    print(f"[H02] degree pre-filter: {len(cand)} candidate junctions "
          f"(>= degree {min_deg}); found {len(matches)} induced copy in "
          f"{search_time:.2f}s")
    print(f"[H02] matched junctions: {sorted(matched)}")
    print(f"[H02] Laplacian fingerprint: {sub_fp}")
    print(f"[H02] PASS -> {flag}")
    return flag


if __name__ == "__main__":
    solve()
