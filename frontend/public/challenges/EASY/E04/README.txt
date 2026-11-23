DEL PERRO CCTV EXPORT
----------------------
Still #4471 recovered from a burnt dashcam of the Vinewood security
contractor.

The operator's dead-drop tooling packs recon notes into images:
  - 2 least-significant bits per colour channel, R then G then B.
  - Pixels are read COLUMN by column (down a column, then next column).
  - Bits fill each byte most-significant first.
  - The first 2 decoded bytes are a big-endian length, then that many
    bytes of the message (the message alphabet is UTF-7).
