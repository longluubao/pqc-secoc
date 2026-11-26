"""Markdown and LaTeX (booktabs tabular, no preamble) table writers and cell formatters."""
import math
from decimal import ROUND_HALF_EVEN, Context, Decimal
from pathlib import Path

DASH = "–"
_TEX = {"\\": r"\textbackslash{}", "%": r"\%", "_": r"\_", "&": r"\&", "#": r"\#", "µ": r"$\mu$", "δ": r"$\delta$",
        "≥": r"$\geq$", "–": "--", "±": r"$\pm$", "|": r"\textbar{}", "<": r"\textless{}", ">": r"\textgreater{}",
        "{": r"\{", "}": r"\}", "$": r"\$", "^": r"\textasciicircum{}", "~": r"\textasciitilde{}"}


_EXACT = Context(prec=400, rounding=ROUND_HALF_EVEN)  # room for the 35 decimals of a bound near 1e-33 and beyond


def rounded(v, places, sign=False):
    """`v` with `places` decimals, as text: THE rounding of every number the toolkit prints with a fixed number of
    decimals, of every unit, in a number key and in a table cell. Decimal arithmetic, half to even, from the value at
    its twelve significant digits (the precision a value is taken to have). A time is a whole or half number of
    nanoseconds, so that is its exact value in us and in ms alike, and a tie is a tie wherever the value is printed;
    the binary formats of Python round the stored value, which lies beside the tie (2.675 is 2.67499...). `sign`
    always prints the sign."""
    if not math.isfinite(v):
        return f"{v:{'+' if sign else ''}.{places}f}"  # nan and inf have no digits to round
    text = format(Decimal(f"{v:.12g}").quantize(Decimal(1).scaleb(-places), context=_EXACT), "f")
    return ("+" if sign and text[0] != "-" else "") + text


def significant(v, digits):
    """`v` with `digits` significant digits, printed as the format 'g' prints it, after the rounding of rounded()."""
    if not math.isfinite(v):
        return f"{v:.{digits}g}"
    d = Decimal(f"{v:.12g}")
    if d:
        d = d.quantize(Decimal(1).scaleb(d.adjusted() - digits + 1), context=_EXACT)
    return f"{float(d):.{digits}g}"  # the rounded value has no further digit, so 'g' only lays it out


def num(v, nd=2):
    return DASH if v is None else rounded(v, nd)


def sig(v, digits=3):
    return DASH if v is None else significant(v, digits)


def pct(v, digits=3):
    return DASH if v is None else significant(100 * v, digits) + "%"


def ci(pair, f=num):
    return DASH if pair is None or None in pair else f"[{f(pair[0])}, {f(pair[1])}]"


def write(out_dir, name, headers, rows, note="", banner=None):
    """Write <name>.md (pipe table) and <name>.tex (one booktabs tabular, first column left-aligned,
    the rest right-aligned). `note` becomes an HTML comment / TeX comment above the table. `banner`
    (for example 'DRY RUN: not a result') is printed visibly at the top of both: a bold line in
    Markdown, a bold row spanning the table in TeX."""
    out_dir = Path(out_dir)
    rows = [[str(c) for c in row] for row in rows]
    md = [f"**{banner}**", ""] if banner else []
    md += [f"<!-- {note} -->"] if note else []
    md += ["| " + " | ".join(headers) + " |", "|" + "|".join(["---"] + ["---:"] * (len(headers) - 1)) + "|"]
    md += ["| " + " | ".join(c.replace("|", "\\|") for c in row) + " |" for row in rows]
    (out_dir / f"{name}.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    def tex(cell):
        return "".join(_TEX.get(ch, ch) for ch in cell)

    lines = [f"% {note}"] if note else []
    lines += [r"\begin{tabular}{l" + "r" * (len(headers) - 1) + "}", r"\toprule"]
    lines += [rf"\multicolumn{{{len(headers)}}}{{l}}{{\textbf{{{tex(banner)}}}}} \\"] if banner else []
    lines += [" & ".join(map(tex, headers)) + r" \\", r"\midrule"]
    lines += [" & ".join(map(tex, row)) + r" \\" for row in rows]
    lines += [r"\bottomrule", r"\end{tabular}"]
    (out_dir / f"{name}.tex").write_text("\n".join(lines) + "\n", encoding="utf-8")
