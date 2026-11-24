DEPOT DISPATCH NODE - field manual
=================================

dispatch_packets.json
    The outbound freight log.  Every entry is one tagged packet:
        { "id": <ordinal>, "tag": <64-bit lane tag>, "lane": <lane index> }
    Packets are delivered to the node in file order.

broken_dispatch.py
    The depot node binary.  Run it with:

        python broken_dispatch.py

    It reads dispatch_packets.json from its own directory and writes out.bin.

Threading model
---------------
    * One FIFO queue holds every packet.
    * WORKER_THREADS worker threads each pull packets until the queue drains.
    * The node maintains two shared process-wide structures: a per-lane tally
      of cleared packets, and a running ledger of the cleared lane tags.
    * Every worker touches both structures as it clears a packet.
    * When every worker has drained the queue the node seals a manifest: the
      reported dispatch count is the sum of the lane tallies, and the ledger is
      the tagged total.  It writes that manifest to out.bin.

    out.bin is base85(zlib(json)) of the sealed manifest.  The manifest carries
    a stage-2 program masked by a keystream keyed on the node's final
    (ledger, dispatched) pair.

Reconciliation
--------------
    A clean run must clear every packet in the log exactly once: the tally
    totals and the ledger both have to balance against the freight on the lane.
    Numbers that drift between runs, or a run whose totals fall short of the
    log, are signs that the node has not finished the dispatch.

    The stage-2 program is not the answer.  It unmasks one further record whose
    trailer must agree with its own payload; the payload that survives is still
    wrapped by an additional reversible layer (a run-length stream under a
    rotating key) before the flag can be read.
