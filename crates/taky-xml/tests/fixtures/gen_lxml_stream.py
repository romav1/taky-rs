#!/usr/bin/env python3
"""Generate lxml_stream.json: the lxml oracle for taky-xml's TreeBuilder (S-303).

For every input (a list of byte chunks) the original pipeline is run:
XMLDeclStrip + XMLPullParser(tag="event", resolve_entities=False) pre-fed with b"<root>",
reading events after every chunk and calling elm.clear(keep_tail=True) like TAKClient.feed.
Recorded per input: the events emitted after each chunk (structural dump) and the index of
the chunk whose feed() raised XMLSyntaxError (or null).

Inputs: (1) every CoT connection in shared/spec/vectors/cot/*.json (chunks per connection, in
step order); (2) the hand-written CASES below (edge cases of cot-server.md §5 / ADR-002).
DOC_CASES are whole documents for parse_element, checked against etree.fromstring.

Usage (needs lxml; the an01 venv works):
  /tmp/venv-an01/bin/python -B gen_lxml_stream.py --taky-src ../../../../../taky \
      --vectors ../../../../../shared/spec/vectors > lxml_stream.json
"""
import argparse, base64, glob, json, os, sys

CASES = {
    # declarations (xmldeclstrip quirks)
    "decl_no_space": ["<?xml?><event a='1'/>"],
    "decl_tab": ["<?xml\tversion='1.0'?><event a='1'/>"],
    "decl_upper": ["<?XML v?><event a='1'/>"],
    "decl_split_each_byte": list("<?xml version='1.0'?><event a='1'/>"),
    "decl_qmark_gt_in_value": ["<?xml a='?>'?><event a='1'/>"],
    "pi_xmlfoo": ["<?xmlfoo?><?xml-stylesheet h?><event a='1'/>"],
    "decl_between_events": ["<event a='1'/><?xml version='1.0'?><event a='2'/>"],
    # structure
    "nested_in_wrap": ["junk <foo a='1'/><wrap><event a='1'/></wrap> more"],
    "nested_in_detail": ["<event a='o'><detail><event a='i'><x/></event>tl</detail></event>"],
    "namespaced": ["<event xmlns='urn:x'/><a:event xmlns:a='u'/><a:event/><event b='1'/>"],
    "ns_attrs": ["<event xmlns:a='u' a:x='1' xml:lang='en' b='2'><a:y/><z xmlns='d'><w/></z><q/></event>"],
    "text_tail_comment_pi": ["<event>t<!-- c -->ct<?p d?>pt<d>x</d>dt<![CDATA[a<b]]></event>"],
    "eol": ["<event a='x\r\ny\tz&#10;w&#9;'>a\r\nb\rc&#13;d</event>"],
    "refs": ["<event a='&amp;&lt;&gt;&quot;&apos;&#65;&#x42;'>&amp;lt;&#x10FFFF;</event>"],
    "utf8_split": [b"<event a='\xc3".decode('latin-1'), b"\x84'>\xd0".decode('latin-1'), b"\x96</event>".decode('latin-1')],
    "end_tag_space": ["<event></event >"],
    "root_close": ["<event a='1'/></root>  <!-- c --><?p?>", "<event a='2'/>"],
    "empty_comment": ["<event><!----></event>"],
    "pi_no_data": ["<event><?p?><?q  d ?></event>"],
    # errors
    "doctype": ["<!DOCTYPE x [<!ENTITY e 'boom'>]><event a='1'/>"],
    "doctype_in_event": ["<event><!DOCTYPE x></event>"],
    "dup_attr": ["<event a='1'/>", "<event a='1' a='2'/>"],
    "dup_attr_undeclared_prefix": ["<event p:q='1' p:q='2'/><event b='1'/>"],
    "dup_attr_declared_prefix": ["<event xmlns:p='u' p:q='1' p:q='2'/>"],
    "dup_expanded_name": ["<event xmlns:p='u' xmlns:r='u' p:q='1' r:q='2'/>"],
    "dup_xmlns": ["<event xmlns:p='u' xmlns:p='v'/>"],
    "mismatch": ["<event></eve>"],
    "stray_end": ["<event a='1'/></x><event a='2'/>"],
    "ctrl_char": ["<event>\x01</event>"],
    "cdata_end_in_text": ["<event>]]></event>"],
    "lt_in_attr": ["<event a='<'/><event a='1'/>"],
    "unquoted": ["<event a=1/>"],
    "no_space_attrs": ["<event a='1'b='2'/>"],
    "double_hyphen": ["<event><!-- a -- b --></event>"],
    "bad_charref": ["<event>&#0;</event>"],
    "surrogate_charref": ["<event>&#xD800;</event>"],
    "fffe": ["<event>￾</event>"],
    "bad_name": ["<1event/>"],
    "space_name": ["< event/>"],
    "after_root_close": ["</root><event a='1'/>"],
    "depth_255": ["<a>" * 255 + "</a>" * 255 + "<event a='1'/>"],
    "depth_256": ["<a>" * 256 + "</a>" * 256 + "<event a='1'/>"],
    # unknown entity (V017): the event disappears, nothing else in the same chunk is visible
    "unknown_entity_text": ["<event a='1'><r>&foo;</r></event>"],
    "unknown_entity_attr": ["<event a='&foo;'/>"],
    # known divergences (listed in tests/lxml_oracle.rs DIVERGENCES, Rust outcome in tests/stream.rs)
    "quirk_unknown_entity_restart": ["<event a='1'>&foo;</event><event a='2'/>", "<event a='3'/>", "<event a='4'/>"],
    "quirk_bare_amp_zombie": ["<event>&</event>", "<event a='1'/>"],
    "quirk_unterminated_charref": ["<event>&#65</event>", "<event a='1'/>"],
}

# Whole documents for parse_element (etree.fromstring with resolve_entities=False).
DOC_CASES = {
    "simple": "<event a='1'><point/>t<detail>x</detail>tl</event>",
    "decl": "<?xml version='1.0' encoding='UTF-8' standalone='yes'?>\n<event/>\n<!-- c -->",
    "bom": "\ufeff<event/>",
    "decl_not_first": " <?xml version='1.0'?><event/>",
    "doctype": "<!DOCTYPE e [<!ENTITY a 'b'>]><event>&a;</event>",
    "unknown_entity": "<event>&foo;</event>",
    "extra_content": "<event/>x",
    "two_roots": "<event/><event/>",
    "no_root": "  ",
    "unclosed": "<event><a>",
    "undeclared_prefix": "<p:event/>",
    "undeclared_attr_prefix": "<event p:q='1'/>",
    "empty_prefix_ns": "<event xmlns:p=''/>",
    "ns": "<m xmlns='urn:m' xmlns:p='urn:p' p:a='1' b='2'><p:c/><d xmlns=''/></m>",
    "dup_attr": "<event a='1' a='2'/>",
    "pi_comment_around": "<?pi x?><!-- a --><event/><?pi y?>",
    "upper_xml_pi": "<?XML v?><event/>",
    "text_before_root": "x<event/>",
    "eol_refs": "<e a='1\r\n2&#10;'>a\r\nb&#13;&amp;&lt;</e>",
}



def dump(e, etree):
    if e.tag is etree.Comment:
        return {"comment": e.text, "tail": e.tail}
    if e.tag is etree.PI:
        return {"pi": e.target, "data": e.text, "tail": e.tail}
    if e.tag is etree.Entity:
        return {"entity": e.text, "tail": e.tail}
    # xpath('@*') gives the real value of every attribute node (attrib.items() repeats the
    # first value when a name occurs twice, e.g. with an undeclared prefix).
    return {"tag": e.tag, "attrs": [[a.attrname, str(a)] for a in e.xpath("@*")], "text": e.text,
            "tail": e.tail, "children": [dump(c, etree) for c in e]}


def run(chunks, etree, XMLDeclStrip):
    parser = etree.XMLPullParser(tag="event", resolve_entities=False)
    parser.feed(b"<root>")
    xdc = XMLDeclStrip(parser)
    out = []
    for i, c in enumerate(chunks):
        try:
            xdc.feed(c)
        except etree.XMLSyntaxError:
            return {"events": out, "error_at": i}
        evs = []
        for _, elm in xdc.read_events():
            evs.append(dump(elm, etree))
            elm.clear(keep_tail=True)
        out.append(evs)
    return {"events": out, "error_at": None}


def vector_sessions(vdir):
    """{"V003/A#1": [chunk bytes, ...]} for every connection that sends data."""
    sessions = {}
    for path in sorted(glob.glob(os.path.join(vdir, "cot", "V*.json"))):
        with open(path, encoding="utf-8") as f:
            v = json.load(f)
        n = {}
        cur = {}
        for st in v["steps"]:
            if st["op"] == "connect":
                c = st["client"]
                n[c] = n.get(c, 0) + 1
                cur[c] = f"{v['id']}/{c}#{n[c]}"
            elif st["op"] == "send":
                key = cur[st["client"]]
                if "chunks_b64" in st:
                    chunks = [base64.b64decode(x) for x in st["chunks_b64"]]
                else:
                    chunks = [x.encode("utf-8") for x in st["chunks"]]
                sessions.setdefault(key, []).extend(chunks)
    return sessions


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--taky-src", required=True)
    ap.add_argument("--vectors", required=True)
    a = ap.parse_args()
    sys.dont_write_bytecode = True
    sys.path.insert(0, a.taky_src)
    from lxml import etree
    from taky.util.xmldeclstrip import XMLDeclStrip

    items = []
    for key, chunks in vector_sessions(a.vectors).items():
        r = run(chunks, etree, XMLDeclStrip)
        items.append({"id": key, "source": "vector",
                      "chunks_b64": [base64.b64encode(c).decode() for c in chunks], **r})
    for key, chunks in CASES.items():
        bs = [c.encode("latin-1") if key == "utf8_split" else c.encode("utf-8") for c in chunks]
        r = run(bs, etree, XMLDeclStrip)
        items.append({"id": key, "source": "case",
                      "chunks_b64": [base64.b64encode(c).decode() for c in bs], **r})
    docs = []
    parser = etree.XMLParser(resolve_entities=False)
    for key, text in DOC_CASES.items():
        raw = text.encode("utf-8")
        try:
            res = {"ok": dump(etree.fromstring(raw, parser), etree)}
        except etree.XMLSyntaxError:
            res = {"ok": None}
        docs.append({"id": key, "input_b64": base64.b64encode(raw).decode(), **res})
    json.dump({"generated_by": "gen_lxml_stream.py", "lxml": ".".join(map(str, etree.LXML_VERSION)),
               "libxml2": ".".join(map(str, etree.LIBXML_VERSION)), "items": items, "documents": docs},
              sys.stdout, indent=1, ensure_ascii=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
