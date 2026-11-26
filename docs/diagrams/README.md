# Diagrams

Four diagrams of this repository. Each exists as a light and a dark SVG; the top-level `README.md`
shows them.

| Diagram | Files | What it shows |
|---|---|---|
| Who calls whom | `architecture.light.svg`, `architecture.dark.svg` | the modules on the path of a secured PDU and the calls between them; where the post-quantum parts sit |
| Handshake | `handshake.light.svg`, `handshake.dark.svg` | the four messages of `PQC-SecOC-HS-v1`, the operations of each side in the order of the code, and when each side installs the session |
| One Secured I-PDU | `pdu-path.light.svg`, `pdu-path.dark.svg` | one Secured I-PDU of the signature variant from the application on board A to the application on board B, and where a bad PDU is stopped |
| From a run to a number | `measurement-pipeline.light.svg`, `measurement-pipeline.dark.svg` | how a two-board run becomes a number of the article, and who checks it on the way |

## What they rest on

The diagrams were drawn from the code at commit `4ba87d9e5df84b6fee36c0514c618a4a28f081ea` (tag
`dataset-v2.0.0`). Their editable sources are the JSON files in `src/`. Every box, participant or
node of a source carries `sources`: file and line range, at that commit, of the code the statement
rests on. Each `cards` list in a source holds further statements that the images do not show; the
captions in the top-level `README.md` give the ones a reader needs.

After they were drawn, each diagram was compared once more with the code, statement by statement,
and corrected.

The diagrams carry no measured values. Sizes of protocol fields and names of configuration constants
are not measurements. Where a module is placed in a layer, the layer is that of the module's AUTOSAR
namesake: a placement by name, not a statement of conformance with any standard.

## How to make them again

The images were rendered with Archify 3.3.2 (https://github.com/tt-a1i/archify, Apache License 2.0),
which checks a source against its schema, checks that every cited file and line range exists at the
cited commit, and lays the diagram out. Whether the cited lines say what the diagram says is not
something a tool checks; that was the comparison described above. With the Archify package unpacked
at `<archify>`, Node 18 or later, and Chrome or Chromium:

    cd docs/diagrams/src
    node <archify>/bin/archify.mjs finalize architecture architecture.json architecture.html --repo-root ../../.. --quality showcase
    node <archify>/bin/export-svg.mjs architecture.html ../architecture.light.svg light
    node <archify>/bin/export-svg.mjs architecture.html ../architecture.dark.svg dark

The diagram types are `architecture` (architecture.json), `sequence` (handshake.json, pdu-path.json)
and `dataflow` (measurement-pipeline.json). `finalize` writes an HTML file with an interactive view of
the diagram, with its cards and with links to the cited lines, and a few receipt files beside it
(`*.finalize.json` and others). None of these is kept in the repository. The exporter refuses to
overwrite an existing SVG: remove the old file first.

`finalize` checks two things about the checkout. The `origin` remote has to be the repository named
in `meta.repository.url` of the source, so a fork or a local copy is refused until one of the two is
changed. The cited files are read from Git at the commit named in `meta.repository.revision`, which
has to be in the checkout; later commits on top do not disturb it. A source that is changed to describe
later code needs that field and its line ranges brought up to date.

Run on the machine that made them (Node 22, Chrome 158), these commands gave the eight SVG files
again byte for byte.

The SVG files embed a subset of the JetBrains Mono typeface; its licence notice is inside the files.
