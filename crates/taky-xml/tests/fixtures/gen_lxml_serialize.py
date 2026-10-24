#!/usr/bin/env python3
"""Generate lxml_serialize.json: the lxml oracle for taky_xml::serialize (S-304).

Every item yields one or more serialized byte strings per `etree.tostring` option set (OPTS):
  * kind "stream": chunks fed to the original pipeline (XMLDeclStrip + XMLPullParser(tag="event")
    pre-fed with b"<root>", events read after every chunk, then elm.clear(keep_tail=True));
    expect = tostring(event) for every emitted event, in order. Inputs: every CoT connection of
    shared/spec/vectors/cot/*.json plus STREAM_CASES.
  * kind "doc": etree.fromstring(input) serialized as a whole (DOC_CASES).
  * kind "moved": etree.fromstring(input), its `detail` child appended to a fresh
    Element("event") (what Event.as_element does), tostring(new event) (MOVED_CASES).
  * kind "tree": an element built in code from a JSON spec (TREE_CASES; same builder in Rust).

Usage (needs lxml; the an01 venv works):
  /tmp/venv-an01/bin/python -B gen_lxml_serialize.py --taky-src ../../../../../taky \
      --vectors ../../../../../shared/spec/vectors > lxml_serialize.json
"""
import argparse, base64, glob, json, os, sys

OPTS = {
    "default": {},
    "pretty": {"pretty_print": True},
    "no_tail": {"with_tail": False},
    "pretty_no_tail": {"pretty_print": True, "with_tail": False},
    "decl": {"xml_declaration": True},
    "decl_pretty": {"xml_declaration": True, "pretty_print": True},
    "decl_sa": {"xml_declaration": True, "standalone": True},
    "decl_sa_no": {"xml_declaration": True, "standalone": False},
    "pref": {"xml_declaration": True, "standalone": True, "pretty_print": True},
}
STREAM_OPTS = ["default", "pretty", "no_tail"]

STREAM_CASES = {
    "escapes": ["<event a='&quot;&apos;&lt;&gt;&amp;&#9;&#10;&#13; Ж\U0001F600'>&quot;&apos;&lt;&gt;&amp;"
                "&#9;&#10;&#13;]]&gt;Ж\U0001F600<![CDATA[<x>&]]><!--cЖ--><?pi dЖ?></event>"],
    "eol": ["<event a='x\r\ny\tz'>a\r\nb\rc</event>"],
    "quote_in_apos": ["<event a='x\"y' b=\"it's\"/>"],
    "empty_elems": ["<event><b></b><c/><d> </d></event>tail<event/>"],
    "tail_same_chunk": ["<event a='1'/>tail text<x/>"],
    "nested_event": ["<event a='o'><detail><event a='i' xmlns:z='q' z:k='1'>x<b/></event>tl</detail></event>"],
    "nested_event_pretty": ["<event><detail><event><b/></event><c/></detail></event>"],
    "inherit_ns": ["<a xmlns:x='u' xmlns:y='v'><event x:k='1'><x:b/></event></a>"],
    "inherit_shadow": ["<a xmlns:x='u'><b xmlns:y='v' xmlns:x='w'><event xmlns:z='q'/></b></a>"],
    "inherit_own_first": ["<a xmlns:p='u'><event xmlns:q='w'><p:b/></event></a>"],
    "inherit_attr_ns_first": ["<b xmlns:x='u' xmlns:y='v' xmlns:z='w'><event z:k='' y:j=''/></b>"],
    "inherit_attr_ns_before_unbind": ["<b xmlns:p='w'>t<a xmlns=''><event p:j=''/></a></b>"],
    "inherit_default_unbind": ["<a xmlns='u'><b xmlns=''><event><c/></event></b></a>"],
    "same_uri_two_prefixes": ["<a xmlns:x='u' xmlns:y='u'><event><y:b x:k='1' y:j='2'/></event></a>"],
    "same_uri_dup_attr": ["<event xmlns:p='u' xmlns:q='u' p:a='1' q:a='2'/>"],
    "default_ns_inside": ["<event><detail xmlns='d'><b/><c xmlns=''/></detail></event>"],
    "default_and_prefix_same_uri": ["<event><d xmlns='u' xmlns:p='u'><b/><p:c p:k='1'/></d></event>"],
    "rebind_inside": ["<event xmlns:p='u'><p:b xmlns:p='z'><c/></p:b></event>"],
    "undeclared_prefix": ["<event><q:b q:x='1'>t</q:b></event>"],
    "xml_prefix": ["<event xmlns:xml='http://www.w3.org/XML/1998/namespace' xml:lang='en'><d xml:space='p'/></event>"],
    "empty_prefix_decl": ["<event xmlns:p=''><c/></event>"],
    "empty_default_decl": ["<event xmlns=''><c/></event>"],
    "empty_cdata": ["<event><b><![CDATA[]]></b><![CDATA[]]><c/></event>"],
    "pi_forms": ["<event><?p?><?q ?><?r  d ?><!----></event>"],
    "whitespace_layout": ["<event>\n  <point lat='1'/>\n  <detail>\n    <x/>\n  </detail>\n</event>\n"],
    "mixed_pretty": ["<event><a><b/>t<c><d/></c></a><e><f/></e><!--c--><?p d?><g/></event>"],
    "deep_pretty": ["<event>" + "<a>" * 70 + "</a>" * 70 + "</event>"],
}

DOC_CASES = {
    "simple": "<a><b><c/></b><d>t</d><e><f/>x</e><!--c--><?p d?><g/></a>",
    "nonascii_names": "<Ж З='И'>Й</Ж>",
    "decl_input": "<?xml version='1.0' encoding='UTF-8'?>\n<a x='1'>é</a>",
    "ws": "<a>\n  <b/>\n</a>",
    "deep": "<a>" * 70 + "</a>" * 70,
    "empty_default": "<a xmlns=''/>",
    "xml_decl_ns": "<a xmlns:xml='http://www.w3.org/XML/1998/namespace'/>",
    "ns_mix": "<r xmlns='d' xmlns:p='u'><p:a p:k='1' k='2'><b xmlns=''/></p:a></r>",
    "cdata_only": "<a><![CDATA[]]></a>",
    "comment_tail": "<a><b/><!--x-->t<c/></a>",
    "redis_value": "<event version=\"2.0\" uid=\"U\" type=\"a-f-G\" how=\"m-g\" time=\"2030-01-01T00:00:00.000Z\" "
                   "start=\"2030-01-01T00:00:00.000Z\" stale=\"2030-01-01T00:10:00.000Z\"><point lat=\"1.000000\" "
                   "lon=\"2.000000\" hae=\"0.0\" ce=\"9999999.0\" le=\"9999999.0\"/><detail><contact callsign=\"Ж&amp;\"/>"
                   "</detail></event>",
}

MOVED_CASES = {
    "plain_with_tail": "<event><point/><detail><b/></detail>\n</event>",
    "outer_ns": "<event xmlns:x='u'><detail><x:foo x:k='1'/></detail></event>",
    "use_order": "<event xmlns:x='u' xmlns:y='v'><detail y:k='2'><x:foo x:k='1'><x:bar/></x:foo><y:z/></detail></event>",
    "shadowed_on_detail": "<event xmlns:x='u'><detail xmlns:x='v'><x:foo/></detail></event>",
    "same_uri": "<event xmlns:p='u' xmlns:q='u'><detail><p:b/><q:c/></detail></event>",
    "xml_attr": "<event xml:lang='en'><detail xml:space='x'/></event>",
    "inner_decl_kept": "<event xmlns:x='u'><detail><a xmlns:y='v'><y:b/></a><x:c/></detail></event>",
    "redundant_after_use": "<event xmlns:x='u'><detail><x:c/><a xmlns:x='u'><x:b/></a></detail></event>",
    "redundant_before_use": "<event xmlns:x='u'><detail><a xmlns:x='u'><x:b/></a><x:c/></detail></event>",
    "strip_other_prefix": "<event xmlns:x='u'><detail><x:c/><a xmlns:y='u'><y:b/></a></detail></event>",
    "strip_vs_detail": "<event><detail xmlns:y='u'><a xmlns:y='u'><y:b/></a></detail></event>",
    "strip_remap": "<event><detail xmlns:y='u'><a xmlns:x='u'><x:b/></a></detail></event>",
    "found_by_href": "<event xmlns:x='u'><detail xmlns:q='u'><x:c/></detail></event>",
    "found_by_href_shadowed": "<event xmlns:x='u'><detail xmlns:q='u'><a xmlns:q='w'><x:c/></a></detail></event>",
    "inner_y_then_outer": "<event xmlns:x='u'><detail><a xmlns:y='u'><y:b/><x:c/></a></detail></event>",
    "partial_strip": "<event xmlns:x='u'><detail><x:c/><a xmlns:x='u' xmlns:z='v'><x:b z:k='1'/></a></detail></event>",
    "empty_default": "<event xmlns:x='u'><detail xmlns=''><x:c/></detail></event>",
    "inner_empty_default": "<event xmlns:x='u'><detail><a xmlns=''/></detail></event>",
    "attrs_only": "<event xmlns:x='u'><detail><b x:k='1'><c x:j='2'/></b></detail></event>",
    "triple_redundant": "<event xmlns:x='u'><detail xmlns:x='u'><a xmlns:x='u'/></detail></event>",
    "ancestor_own_ns_found": "<event xmlns:q='u'><detail><event xmlns='u'><q:e><detail><q:t xmlns:q='u'/></detail></q:e></event></detail></event>",
    "in_scope_quirk": "<event><detail><b xmlns:q='w' xmlns:p='v'><p:a xmlns:p='w' xmlns:q='v'><c><p xmlns:q='w'/></c></p:a></b></detail></event>",
    "remap_to_default_unbound": "<event><detail><a xmlns='u'><c><p:t xmlns:p='u' xmlns=''/></c></a></detail></event>",
    "strip_to_default": "<event xmlns:p='u'><detail><event xmlns='v'><detail xmlns='' xmlns:q='v'><q:l/></detail></event></detail></event>",
    "ns0_taken": "<event xmlns:x='u' xmlns:ns0='z'><detail><a xmlns:x='w'><x:b/><y:c xmlns:y='w2'/></a><x:c x:k='1'/></detail></event>",
}


def T(tag, attrs=(), text=None, tail=None, children=(), nsmap=None):
    d = {"tag": tag, "attrs": [list(a) for a in attrs], "text": text, "tail": tail, "children": list(children)}
    if nsmap:
        d["nsmap"] = [list(x) for x in nsmap]
    return d


def C(text, tail=None):
    return {"comment": text, "tail": tail}


TS = "2030-01-01T00:00:00.000Z"
POINT = T("point", [("lat", "1.234568"), ("lon", "-2.000000"), ("hae", "0.0"), ("ce", "9999999.0"), ("le", "9999999.0")])
TREE_CASES = {
    "event_full": T("event", [("version", "2.0"), ("uid", "U-1"), ("type", "a-f-G-U-C"), ("how", "m-g"), ("time", TS),
                              ("start", TS), ("stale", TS)],
                    children=[POINT, T("detail", children=[T("contact", [("callsign", "Жuk & <co>")])])]),
    "event_missing_version_how": T("event", [("uid", "U-1"), ("type", ""), ("time", TS), ("start", TS), ("stale", TS)],
                                   children=[POINT]),
    "pong": T("event", [("version", "2.0"), ("uid", "takPong"), ("type", "t-x-c-t-r"), ("how", "h-g-i-g-o"),
                        ("time", TS), ("start", TS), ("stale", TS)], children=[POINT]),
    "taky_err": T("event", [("uid", "U")], children=[POINT, T("__taky_err", children=[C("Date parsing error \u0416 <x> &amp;")])]),
    "preference_pref": T("preferences", children=[
        T("preference", [("version", "1"), ("name", "cot_streams")], children=[
            T("entry", [("key", "count"), ("class", "class java.lang.Integer")], text="1"),
            T("entry", [("key", "enabled0"), ("class", "class java.lang.Boolean")], text="true"),
            T("entry", [("key", "connectString0"), ("class", "class java.lang.String")], text="taky.example:8089:ssl")]),
        T("preference", [("version", "1"), ("name", "com.atakmap.app_preferences")], children=[
            T("entry", [("key", "caLocation"), ("class", "class java.lang.String")], text="/storage/emulated/0/atak/cert/server.p12")])]),
    "manifest": T("MissionPackageManifest", [("version", "2")], children=[
        T("Configuration", children=[T("Parameter", [("name", "uid"), ("value", "abc")]),
                                     T("Parameter", [("name", "name"), ("value", "taky Ж.zip")])]),
        T("Contents", children=[T("Content", [("ignore", "false"), ("zipEntry", "certs/a.p12")])])]),
    "video_empty": T("videoConnections"),
    "video_feeds": T("videoConnections", children=[T("feed", text="\n  ", children=[T("uid", text="x", tail="\n")])]),
    "escape_all": T("x", [("k", "\r\n\t\"'<>&é\U0001F600")], text="a\r\nb\t\"'<>&]]>é\U0001F600", tail="t&<\r"),
    "empty_text": T("a", text=""),
    "empty_text_child": T("a", text="", children=[T("b")]),
    "empty_tail_child": T("a", children=[T("b", tail="")]),
    "comment_tail_root": T("a", children=[C("x", "t")]),
    "comments_pretty": T("a", children=[C(""), T("b", children=[C("in")])]),
    "pretty_tail_root": T("a", tail="\n", children=[T("b")]),
    "ns_clark_root": T("{u}a"),
    "ns_clark_child_attr": T("{u}a", children=[T("{u}b", [("{v}k", "1")])]),
    "ns_default_given": T("{u}a", nsmap=[(None, "u")], children=[T("{u}b", [("{u}k", "1")])]),
    "ns_prefix_given": T("{u}a", nsmap=[("p", "u")], children=[T("{w}b", [("{u}k", "1"), ("{w}j", "2")])]),
    "xml_attr_built": T("a", [("{http://www.w3.org/XML/1998/namespace}lang", "en")]),
}


def build(spec, etree, parent=None):
    if "comment" in spec:
        c = etree.Comment(spec["comment"])
        c.tail = spec["tail"]
        parent.append(c)
        return c
    nsmap = {p: u for p, u in spec.get("nsmap", [])} or None
    e = etree.Element(spec["tag"], nsmap=nsmap) if parent is None else etree.SubElement(parent, spec["tag"], nsmap=nsmap)
    for k, v in spec["attrs"]:
        e.set(k, v)
    e.text = spec["text"]
    e.tail = spec["tail"]
    for c in spec["children"]:
        build(c, etree, e)
    return e


def tostr(e, etree, name):
    b = etree.tostring(e, **OPTS[name])
    return b.decode("ascii")  # US-ASCII output by construction


def stream_events(chunks, etree, XMLDeclStrip, name):
    parser = etree.XMLPullParser(tag="event", resolve_entities=False)
    parser.feed(b"<root>")
    xdc = XMLDeclStrip(parser)
    out = []
    for c in chunks:
        try:
            xdc.feed(c)
        except etree.XMLSyntaxError:
            break
        for _, elm in xdc.read_events():
            out.append(tostr(elm, etree, name))
            elm.clear(keep_tail=True)
    return out


def vector_sessions(vdir):
    """{"V003/A#1": [chunk bytes, ...]} for every connection that sends data."""
    sessions = {}
    for path in sorted(glob.glob(os.path.join(vdir, "cot", "V*.json"))):
        with open(path, encoding="utf-8") as f:
            v = json.load(f)
        n, cur = {}, {}
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

    def stream_item(key, source, chunks):
        outs = [{"opts": OPTS[n], "expect": stream_events(chunks, etree, XMLDeclStrip, n)} for n in STREAM_OPTS]
        if outs[0]["expect"]:
            items.append({"id": key, "kind": "stream", "source": source,
                          "chunks_b64": [base64.b64encode(c).decode() for c in chunks], "outputs": outs})

    for key, chunks in vector_sessions(a.vectors).items():
        stream_item(key, "vector", chunks)
    for key, chunks in STREAM_CASES.items():
        stream_item(key, "case", [c.encode("utf-8") for c in chunks])
    parser = etree.XMLParser(resolve_entities=False)
    for key, text in DOC_CASES.items():
        e = etree.fromstring(text.encode("utf-8"), parser)
        items.append({"id": key, "kind": "doc", "input": text,
                      "outputs": [{"opts": o, "expect": etree.tostring(e, **o).decode("ascii")} for o in OPTS.values()]})
    for key, text in MOVED_CASES.items():
        e = etree.fromstring(text.encode("utf-8"), parser)
        n = etree.Element("event")
        n.append(e.find("detail"))
        items.append({"id": key, "kind": "moved", "input": text,
                      "outputs": [{"opts": OPTS[k], "expect": tostr(n, etree, k)} for k in ("default", "pretty")]})
    for key, spec in TREE_CASES.items():
        e = build(spec, etree)
        items.append({"id": key, "kind": "tree", "tree": spec,
                      "outputs": [{"opts": o, "expect": etree.tostring(e, **o).decode("ascii")} for o in OPTS.values()]})
    json.dump({"generated_by": "gen_lxml_serialize.py", "lxml": ".".join(map(str, etree.LXML_VERSION)),
               "libxml2": ".".join(map(str, etree.LIBXML_VERSION)), "items": items},
              sys.stdout, indent=1, ensure_ascii=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
