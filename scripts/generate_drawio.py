#!/usr/bin/env python3
"""
draw.io (diagrams.net) XML generator for appsec-threat-modeler.

Builds two kinds of diagrams from a single JSON spec format:
  - Data Flow Diagram (DFD): entities, processes, data stores, numbered flows
  - Threat Model Diagram: the same layout plus trust-boundary swimlanes and
    threat-actor nodes with dashed red arrows into each boundary crossing

Both are valid mxGraphModel XML, importable directly at https://app.diagrams.net
or the draw.io desktop app -- fully editable after import, not a flattened image.

Usage:
  python3 generate_drawio.py spec.json output.drawio

Spec JSON shape (see skills/threat-modeling/references/examples/*.json for
worked examples):
{
  "title": "Payment Onboarding Service",
  "trust_boundaries": [
    {"id": "tb_external", "label": "External / Untrusted", "x":20,"y":80,"width":220,"height":520, "color":"#6c6c6c"},
    {"id": "tb_internal", "label": "Internal Trust Boundary", "x":260,"y":80,"width":760,"height":520, "color":"#185FA5"}
  ],
  "nodes": [
    {"id":"client","label":"Customer","type":"external_entity","x":40,"y":120,"width":160,"height":60},
    {"id":"api_gw","label":"API Gateway","type":"process","x":300,"y":120,"width":160,"height":60},
    {"id":"db","label":"Customer DB","type":"data_store","x":300,"y":260,"width":160,"height":50}
  ],
  "flows": [
    {"id":"f1","label":"(1) Submit application","source":"client","target":"api_gw","threats":["S-1","E-1"]},
    {"id":"f2","label":"(2) Persist record","source":"api_gw","target":"db","dashed":false}
  ],
  "threat_actors": [
    {"id":"actor1","label":"Unauthenticated\\nExternal Attacker","target":"api_gw","x":40,"y":420,"width":170,"height":70}
  ],
  "boundary_crossings": [
    {"x": 255, "y": 148}
  ]
}
"""
import json
import sys
import html

NODE_STYLES = {
    "external_entity": "rounded=0;whiteSpace=wrap;html=1;fillColor=#dae8fc;strokeColor=#6c8ebf;fontSize=12;",
    "process": "rounded=1;whiteSpace=wrap;html=1;fillColor=#d5e8d4;strokeColor=#5DCAA5;fontSize=12;arcSize=30;",
    "data_store": "shape=process;whiteSpace=wrap;html=1;backgroundOutline=1;fillColor=#f5f5f5;strokeColor=#666666;fontSize=12;",
    "external_system": "rounded=1;whiteSpace=wrap;html=1;fillColor=#fff2cc;strokeColor=#EF9F27;fontSize=12;arcSize=12;",
}

THREAT_ACTOR_STYLE = (
    "shape=mxgraph.basic.diamond;whiteSpace=wrap;html=1;fillColor=#f8cecc;"
    "strokeColor=#E24B4A;fontSize=11;fontStyle=1;fontColor=#7f1d1d;"
)

BOUNDARY_CROSSING_STYLE = "ellipse;whiteSpace=wrap;html=1;fillColor=none;strokeColor=#E24B4A;strokeWidth=2;"

TAG_STYLE = (
    "text;html=1;strokeColor=#FF8000;fillColor=#FFE6CC;rounded=1;arcSize=50;"
    "fontSize=9;fontColor=#993300;fontStyle=1;"
)


def _esc(s: str) -> str:
    return html.escape(str(s), quote=True).replace("\n", "&#10;")


def _cell(id_, value, style, x, y, w, h, vertex=True, parent="1"):
    tag = "vertex" if vertex else "edge"
    return (
        f'<mxCell id="{_esc(id_)}" value="{_esc(value)}" style="{style}" '
        f'{tag}="1" parent="{parent}">'
        f'<mxGeometry x="{x}" y="{y}" width="{w}" height="{h}" as="geometry"/>'
        f"</mxCell>"
    )


def _edge(id_, value, style, source, target, parent="1"):
    return (
        f'<mxCell id="{_esc(id_)}" value="{_esc(value)}" style="{style}" '
        f'edge="1" source="{_esc(source)}" target="{_esc(target)}" parent="{parent}">'
        f'<mxGeometry relative="1" as="geometry"/>'
        f"</mxCell>"
    )


def build_drawio_xml(spec: dict, mode: str = "threat_model") -> str:
    """mode: 'dfd' omits trust boundaries/threat actors; 'threat_model' includes them."""
    cells = []

    if mode == "threat_model":
        for tb in spec.get("trust_boundaries", []):
            style = (
                "rounded=1;whiteSpace=wrap;html=1;dashed=1;dashPattern=8 4;"
                f"fillColor=none;strokeColor={tb.get('color', '#6c6c6c')};strokeWidth=1.5;"
                "fontSize=11;fontStyle=1;verticalAlign=top;align=left;spacingLeft=6;"
            )
            cells.append(_cell(tb["id"], tb["label"], style, tb["x"], tb["y"], tb["width"], tb["height"]))

    for node in spec.get("nodes", []):
        style = NODE_STYLES.get(node.get("type", "process"), NODE_STYLES["process"])
        label = f"<b>{_esc(node['label'])}</b>"
        if node.get("description"):
            label += f"<br>{_esc(node['description'])}"
        cells.append(_cell(node["id"], label, style, node["x"], node["y"], node["width"], node["height"]))

    for flow in spec.get("flows", []):
        style = (
            "edgeStyle=orthogonalEdgeStyle;html=1;fontSize=10;rounded=0;"
            + ("dashed=1;strokeColor=#534AB7;" if flow.get("dashed") else "")
        )
        label = flow.get("label", "")
        cells.append(_edge(flow["id"], label, style, flow["source"], flow["target"]))
        if mode == "threat_model" and flow.get("threats"):
            tag_id = f"tag_{flow['id']}"
            tx, ty = flow.get("tag_x"), flow.get("tag_y")
            if tx is not None and ty is not None:
                cells.append(_cell(tag_id, f"[{', '.join(flow['threats'])}]", TAG_STYLE, tx, ty, 90, 18))

    if mode == "threat_model":
        for actor in spec.get("threat_actors", []):
            cells.append(
                _cell(actor["id"], actor["label"], THREAT_ACTOR_STYLE, actor["x"], actor["y"], actor["width"], actor["height"])
            )
            if actor.get("target"):
                cells.append(
                    _edge(
                        f"{actor['id']}_edge",
                        "",
                        "endArrow=block;dashed=1;strokeColor=#E24B4A;strokeWidth=2;html=1;",
                        actor["id"],
                        actor["target"],
                    )
                )

        for i, crossing in enumerate(spec.get("boundary_crossings", [])):
            cells.append(
                _cell(f"tb_marker_{i}", "", BOUNDARY_CROSSING_STYLE, crossing["x"], crossing["y"], 14, 14)
            )

    body = "".join(cells)
    return (
        '<mxGraphModel dx="1422" dy="762" grid="1" gridSize="10" guides="1" tooltips="1" '
        'connect="1" arrows="1" fold="1" page="1" pageScale="1" pageWidth="1169" pageHeight="827" '
        'math="0" shadow="0">'
        "<root>"
        '<mxCell id="0"/>'
        '<mxCell id="1" parent="0"/>'
        f"{body}"
        "</root>"
        "</mxGraphModel>"
    )


def main():
    if len(sys.argv) < 3:
        print("Usage: python3 generate_drawio.py <spec.json> <output.drawio> [dfd|threat_model]", file=sys.stderr)
        sys.exit(1)
    spec_path, out_path = sys.argv[1], sys.argv[2]
    mode = sys.argv[3] if len(sys.argv) > 3 else "threat_model"
    with open(spec_path, "r", encoding="utf-8") as f:
        spec = json.load(f)
    xml = build_drawio_xml(spec, mode=mode)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(xml)
    print(f"Wrote {out_path} ({len(xml)} bytes, mode={mode})")


if __name__ == "__main__":
    main()
