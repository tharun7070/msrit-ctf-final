#!/usr/bin/env python3
"""Build H05_PRINTABLE_RIDDLE.pdf - a single-A4-sheet offline deduction puzzle.

Private organizer tooling. No third-party libraries (reportlab/fpdf are not
available in this environment), so the PDF is assembled by hand using the
base-14 Helvetica fonts only.

Run:
    python build_h05_riddle_pdf.py
Output:
    H05_PRINTABLE_RIDDLE.pdf  (next to this script)
"""
from pathlib import Path

HERE = Path(__file__).resolve().parent

# --- page geometry (A4, points) --------------------------------------------
PW, PH = 595.28, 841.89
MARGIN = 48.0
MAXW = PW - 2 * MARGIN

# --- standard base-14 width tables (units / 1000), chars 32..126 -----------
_HELV = [
    278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278,
    556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556,
    1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778,
    667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556,
    333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556,
    556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584,
]
_HELVB = [
    278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278,
    556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 333, 333, 584, 584, 584, 611,
    975, 722, 722, 722, 722, 667, 611, 778, 722, 278, 556, 722, 611, 833, 722, 778,
    667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 333, 278, 333, 584, 556,
    333, 556, 611, 556, 611, 556, 333, 611, 611, 278, 278, 556, 278, 889, 611, 611,
    611, 611, 389, 556, 333, 611, 556, 778, 556, 556, 500, 389, 280, 389, 584,
]


def _width(text, bold):
    table = _HELVB if bold else _HELV
    total = 0
    for ch in text:
        code = ord(ch)
        if 32 <= code <= 126:
            total += table[code - 32]
        else:
            total += 556  # conservative fallback
    return total / 1000.0


# --- content model ----------------------------------------------------------
class Doc:
    """Collects text/rule operations and emits a PDF content stream."""

    def __init__(self):
        self.ops = []
        self.y = PH - MARGIN

    def _ensure(self, needed):
        if self.y - needed < MARGIN:
            self.ops.append("/PAGESTOP")

    def space(self, h):
        self.y -= h

    def rule(self):
        self.ops.append("%.2f %.2f m %.2f %.2f l S" % (MARGIN, self.y, PW - MARGIN, self.y))
        self.y -= 8

    def text(self, s, size=10.5, bold=False, gap_after=4.0, indent=0.0, lead=None):
        font = "/F2" if bold else "/F1"
        lead = lead if lead is not None else size + 3.0
        words = s.split(" ")
        line = ""
        for w in words:
            trial = (line + " " + w) if line else w
            avail = MAXW - indent
            if _width(trial, bold) * size / 1000.0 > avail and line:
                self._emit(font, size, indent, line)
                line = w
            else:
                line = trial
        if line:
            self._emit(font, size, indent, line)
        self.y -= gap_after

    def _emit(self, font, size, indent, line):
        self._ensure(size + 2)
        self.ops.append("BT %s %.2f Tf 1 0 0 1 %.2f %.2f Tm (%s) Tj ET"
                        % (font, size, MARGIN + indent, self.y, _esc(line)))
        self.y -= size + 3.0


def _esc(s):
    return s.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")


def build_content():
    d = Doc()
    d.text("FLAG THEFT AUTO", size=12, bold=True, gap_after=0)
    d.text("LAST RIDE OUT  -  CLASSIFIED OFFLINE INTEL (hand-out)", size=11, bold=True, gap_after=6)
    d.rule()
    d.text("Codename: THE NIGHT SHIFT LOG", size=10.5, bold=True, gap_after=2)
    d.text(
        "On the last night before the crew scattered, three couriers each moved a single "
        "code-word across Los Santos, one transmission each, through three relay stations. "
        "Signals Intelligence recovered a torn page of the relay log. Rebuild the night: "
        "work out which courier spoke from which relay, and in what order.", gap_after=8)

    d.text("THE CREW", size=10.5, bold=True, gap_after=2)
    d.text("Couriers (callsigns):  RICO  .  HALO  .  ECHO", indent=10, gap_after=2)
    d.text("Relay stations:  ELYSIAN ISLAND (E)  .  DEL PERRO PIER (D)  .  VINEWOOD TOWER (V)", indent=10, gap_after=2)
    d.text("Transmission slots:  1 (first)  .  2 (middle)  .  3 (last, immediately before the blackout)", indent=10, gap_after=8)

    d.text("RELAY RULES (printed on the protocol page)", size=10.5, bold=True, gap_after=2)
    d.text("- Each courier transmits exactly once, from a different relay, in a different slot.", indent=10, gap_after=2)
    d.text("- A relay carries exactly one transmission.", indent=10, gap_after=2)
    d.text("- If the wire catches the same courier twice, only the most recent call is authoritative.", indent=10, gap_after=8)

    d.text("INTERCEPTED CLUES", size=10.5, bold=True, gap_after=2)
    d.text("1.  RICO transmitted from ELYSIAN ISLAND.", indent=10, gap_after=2)
    d.text("2.  HALO's call was the second transmission of the night.", indent=10, gap_after=2)
    d.text("3.  The DEL PERRO PIER transmission happened immediately after the ELYSIAN ISLAND one.", indent=10, gap_after=2)
    d.text("4.  ECHO was not the first to transmit.", indent=10, gap_after=2)
    d.text("(The raw wire also caught a faint earlier call from ECHO that was cut off before it "
           "ever reached a relay. It was superseded - do not let it mislead you.)", indent=10, gap_after=8)

    d.text("RELAY KEY  -  each relay stamps its own code-word on every call it carries:", size=10.5, bold=True, gap_after=2)
    d.text("ELYSIAN ISLAND  ->  NEWEST", indent=10, gap_after=2)
    d.text("DEL PERRO PIER  ->  WORD", indent=10, gap_after=2)
    d.text("VINEWOOD TOWER  ->  WINS", indent=10, gap_after=8)

    d.rule()
    d.text("YOUR ANSWER", size=10.5, bold=True, gap_after=2)
    d.text("Decide the one night that satisfies every clue, then read the three relay code-words "
           "in transmission order (slot 1, then 2, then 3). The resulting three-word pass-phrase "
           "is your key. Also be ready to name the courier who made the final transmission.", gap_after=4)
    d.text("There is exactly one solution. Take the pass-phrase to the organizer desk to claim a "
           "private hint for this mission. No computers or internet are required.", gap_after=8)
    d.text("FLAG THEFT AUTO  .  organizer use only  .  do not photocopy off-site", size=8.5, gap_after=0)
    return d


def build_pdf(doc, out_path):
    # Render the collected ops, splitting into pages at explicit page breaks.
    pages = [[]]
    for op in doc.ops:
        if op == "/PAGESTOP":
            pages.append([])
        else:
            pages[-1].append(op)
    # trim a possible trailing empty page
    pages = [p for p in pages if p] or [[]]

    objects = []  # 1-indexed strings (without "N 0 obj" wrapper)

    n_pages = len(pages)
    # object numbering:
    #  1 catalog, 2 pages, 3 font F1, 4 font F2, then per page: content, page
    first_page_obj = 5 + 2 * n_pages  # dummy, recomputed below
    objs = {}
    objs[1] = "<< /Type /Catalog /Pages 2 0 R >>"
    kids = []
    page_content_ids = {}
    base = 5
    for i, ops in enumerate(pages):
        content_id = base + 2 * i
        page_id = base + 2 * i + 1
        kids.append("%d 0 R" % page_id)
        stream = "\n".join(ops)
        page_content_ids[page_id] = content_id
        objs[content_id] = stream
    objs[2] = "<< /Type /Pages /Count %d /Kids [%s] >>" % (n_pages, " ".join(kids))
    objs[3] = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"
    objs[4] = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>"
    for page_id, content_id in page_content_ids.items():
        objs[page_id] = ("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %.2f %.2f] "
                         "/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> "
                         "/Contents %d 0 R >>" % (PW, PH, content_id))

    max_id = max(objs)
    out = bytearray()
    out += b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"
    offsets = {}
    for oid in range(1, max_id + 1):
        offsets[oid] = len(out)
        out += ("%d 0 obj\n" % oid).encode("latin-1")
        body = objs.get(oid, "<< >>")
        if isinstance(body, str) and not body.lstrip().startswith("<<"):
            # content stream
            data = body.encode("latin-1")
            out += ("<< /Length %d >>\nstream\n" % len(data)).encode("latin-1")
            out += data + b"\nendstream"
        else:
            out += body.encode("latin-1")
        out += b"\nendobj\n"
    xref_pos = len(out)
    out += ("xref\n0 %d\n" % (max_id + 1)).encode("latin-1")
    out += b"0000000000 65535 f \n"
    for oid in range(1, max_id + 1):
        out += ("%010d 00000 n \n" % offsets[oid]).encode("latin-1")
    out += ("trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n"
            % (max_id + 1, xref_pos)).encode("latin-1")

    Path(out_path).write_bytes(bytes(out))
    return n_pages


def main():
    doc = build_content()
    out = HERE / "H05_PRINTABLE_RIDDLE.pdf"
    n = build_pdf(doc, out)
    print("wrote %s (%d page(s), %d bytes)" % (out.name, n, out.stat().st_size))


if __name__ == "__main__":
    main()
