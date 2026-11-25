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
    * The node maintains THREE shared process-wide structures: a per-lane tally
      of cleared packets, a running ledger of the cleared lane tags, and a
      running mix (a hashed tally) of the cleared tags.
    * Every worker touches all three as it clears a packet.
    * When every worker has drained the queue the node seals a manifest: the
      reported dispatch count is the sum of the lane tallies, the ledger is the
      tagged total and the mix is the hashed tag tally.  It writes that manifest
      to out.bin.

    out.bin is base85(zlib(json)) of the sealed manifest.  The manifest carries
    two programs (a stage-2 reconciler and an assembler) masked by a keystream
    keyed on a digest of the node's final (ledger, mix, dispatched) triple.

Reconciliation
--------------
    A clean run must clear every packet in the log exactly once: the tally
    totals, the ledger AND the mix all have to balance against the freight on
    the lane.  Numbers that drift between runs, or a run whose totals fall
    short of the log, are signs that the node has not finished the dispatch.

    The stage-2 program is not the answer.  It unmasks two lane records whose
    trailer must agree with their payload; the two payloads are combined, keyed
    again on the sealed ledger and then unwrapped twice (an outer rotating-key
    wrap and an inner run-length stream) before the flag can be read.
