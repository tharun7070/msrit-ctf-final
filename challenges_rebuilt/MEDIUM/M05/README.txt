DEPOT DISPATCH NODE - field manual
=================================

dispatch_packets.json
    The outbound freight log.  Every entry is one tagged packet:
        { "id": <ordinal>, "tag": <64-bit lane tag> }
    Packets are delivered to the node in file order.

broken_dispatch.py
    The depot node binary.  Run it with:

        python broken_dispatch.py

    It reads dispatch_packets.json from its own directory and writes out.bin.

Threading model
---------------
    * One FIFO queue holds every packet.
    * WORKER_THREADS worker threads each pull packets until the queue drains.
    * The node maintains two process-wide counters: the number of cleared
      packets and the ledger of cleared tags.
    * Workers share those counters; each worker applies its own update as it
      clears a packet.
    * When every worker has drained the queue the node seals a manifest and
      writes it to out.bin.

    out.bin is base85(zlib(json)) of the sealed manifest.

Reconciliation
--------------
    The sealed manifest is only meaningful when the node reports that every
    packet in the log was cleared, and that the ledger balances against the
    tags recorded on the lane.  A node that prints a short count has not
    finished the run.
