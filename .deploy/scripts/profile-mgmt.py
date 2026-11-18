#!/usr/bin/env python3
"""
profile-mgmt.py - open5gs subscriber profile manager (AuC: 4G HSS + 5G UDM/UDR)

Based on open5gs-utils/ctrl-imsi-profile.py; extends it with:
  - ALL open5gs profile parameters (see --help / .deploy/profiles/README.md)
  - single and BULK editing of existing profiles
  - EKI-TK encrypted profiles (.deploy/profiles/*.csv via import-profiles.sh)
  - fail-closed: a single bad row stops the whole batch, nothing is written
  - dry-run, backups (.deploy/backups), no secrets ever printed

Usage (run from ~/open5gs-compose):
  python3 .deploy/scripts/profile-mgmt.py show  <imsi>
  python3 .deploy/scripts/profile-mgmt.py list
  python3 .deploy/scripts/profile-mgmt.py add    <imsi> [--msisdn N --apn N --qos 9 ...]
  python3 .deploy/scripts/profile-mgmt.py update <imsi> [--<param> V ...]
  python3 .deploy/scripts/profile-mgmt.py edit   <profile.csv|profile.json>   # bulk
  python3 .deploy/scripts/profile-mgmt.py del    <imsi>
  python3 .deploy/scripts/profile-mgmt.py revoke <imsi>

Bulk profile files (CSV or JSON) describe the FULL target state of a
subscriber; only fields present in the file are changed (absent fields
keep their current value).  Row formats:

  CSV (header row required, empty cells = keep current value):
        imsi,msisdn,imeisv,mme_host,mme_realm,apn,apn_type,qos,arp,
        ambr_d,ambr_u,sst,sd,ue_ambr_d,ue_ambr_u,ue_ambr,
        access_restriction,nam,status,barring,tau,purge,
        security_k,security_opc,create
  JSON: [{"imsi": "...", "msisdn": "...",
        "sessions": [{"sst":1,"sd":"ffffff","default":true,
                      "session":[{"name":"internet","type":3,"qos":"8",
                                  "arp":"best-effort","ambr_d":"1G"}]}],
        "ue_ambr": "500M", "access_restriction": 32, "nam": "packet",
        "status": "granted", "barring": "all ps barred", "tau": 12,
        "purge": false, "create": false,
        "security": {"k":"<32hex>","opc":"<32hex>","amf":"8000"}}, ...]

A row describes the desired state; only fields present in the row are
changed. 'sessions' (or the apn/qos/arp/ambr_d/ambr_u short form) REPLACES
the whole slice. edit never creates a subscriber unless "create": true /
CSV create=yes, which additionally requires security k+opc.

security = plaintext Ki/OPc hex (32) - LOUD WARNING is printed; for encrypted
key loading use import-profiles.sh with .deploy/profiles/*.csv
(columns IMSI,EKI,E_KI,AMF[,HMAC]); the 'ekiprofile' field is reserved
and rejected here.
"""

import os, re, sys, json, argparse, shutil, subprocess, time
from collections import OrderedDict



BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DBCTL = os.path.join(BASE, "open5gs-dbctl")
BACKUP_DIR = os.path.join(BASE, ".deploy", "backups")

# --- parameter models (open5gs 2.7.7, lib/proto/types.h + lib/dbi/ogs-mongoc.c) ---
APN_TYPES = OrderedDict([
    ("default", 1), ("optimized", 2), ("internet", 3),
    ("ims", 4), ("dedicated", 5), ("emergency", 6)])
QOS_ARPS = OrderedDict([
    ("conversational", [2, 1, 1]), ("video", [4, 1, 1]), ("voice", [5, 1, 1]),
    ("vector-video", [6, 1, 2]), ("non-interactive", [7, 1, 2]),
    ("best-effort", [8, 1, 2]), ("supplementary-services", [9, 1, 2]),
    ("reserved-10", [9, 1, 1]), ("reserved-11", [9, 1, 1]),
    ("gps", [6, 2, 2]), ("nrtolr", [8, 2, 2])])
SUBSCRIBER_STATUSES = OrderedDict([
    ("granted", 0), ("barring", 1)])
ACCESS_RESTRICTIONS = [
    (1, "UTRAN not allowed"), (2, "GERAN not allowed"), (4, "GAN not allowed"),
    (8, "I-HSPA+ not allowed"), (16, "WB eUTRAN not allowed"),
    (32, "ho to non-3GPP not allowed"), (64, "NB-IoT not allowed")]
BARRING_FLAGS = [
    (1, "all PS barred"), (2, "roam HPLMN AP barred"),
    (4, "roam VPLMN AP barred"), (8, "all outgoing calls barred"),
    (16, "all outgoing intl calls barred"),
    (32, "intl calls excl HPLMN country"),
    (64, "interzone calls barred"), (128, "interzone excl HPLMN country"),
    (256, "intl excl HPLMN country and interzone")]


def warn(msg):
    print("WARN: " + str(msg), file=sys.stderr)


def die(msg):
    print("FAIL: " + str(msg), file=sys.stderr)
    sys.exit(1)


def ambr_to_mb(m):
    m = (m or "1G").strip().upper()
    if m.endswith("G"):
        try:
            v = int(m[:-1])
        except ValueError:
            die("ambr: bad value " + m)
        return (v * 1024) << 20
    if m.endswith("M"):
        try:
            v = int(m[:-1])
        except ValueError:
            die("ambr: bad value " + m)
        return v << 20
    die("ambr: use like 1G / 500M (got " + m + ")")


def ambr_to_bytes(m):
    m = (m or "1G").strip().upper()
    if m.endswith("G"):
        return int(m[:-1]) * 1024 * 1024 * 1024
    if m.endswith("M"):
        return int(m[:-1]) * 1024 * 1024
    die("ambr: use like 1G / 500M (got " + m + ")")


def build_ambr(a, b):
    out = OrderedDict()
    for k, v in (("downlink", a), ("uplink", b)):
        if v:
            out[k] = OrderedDict([("value", ambr_to_mb(v)), ("unit", 0)])
    return out


def parse_qos(spec):
    parts = (spec or "8").strip().split(",")
    if len(parts) not in (1, 3):
        die("qos: expect index or index,preempt,preemptvuln (got " + spec + ")")
    qos = OrderedDict([
        ("index", int(parts[0])),
        ("arp", OrderedDict([
            ("priority_level", 8 if len(parts) == 1 else int(parts[1])),
            ("pre_emption_capability", 8 if len(parts) == 1 else int(parts[2])),
            ("pre_emption_vulnerability", 2)])),
    ])
    return qos


class Stack:
    """Compose context: repo root + active compose files + auto-detect of
    MongoDB TLS mode and DB_URI (same pattern as .deploy/scripts/import-profiles.sh)."""

    DBCTL_IMAGE = "gradiant/open5gs-dbctl:0.10.3"

    def __init__(self):
        import re
        self.root = BASE
        self.dc_files = []
        env = os.path.join(BASE, ".env")
        if os.path.exists(env):
            for line in open(env, encoding="utf-8"):
                m = re.match(r"^COMPOSE_FILE=(.*)$", line.strip())
                if m:
                    self.dc_files = m.group(1).split(":")
        self.tls = False
        self.db_uri = "mongodb://mongodb/open5gs"
        self.net_id = None

    def _dc(self, *args):
        cmd = ["docker", "compose"]
        for f in self.dc_files:
            cmd += ["-f", f]
        cmd += list(args)
        return subprocess.run(cmd, capture_output=True, text=True, cwd=self.root)

    def detect(self):
        r = self._dc("ps", "-q", "mongodb")
        cids = r.stdout.strip().splitlines()
        if not cids:
            die("mongodb container not found - is the stack up?")
        m = self._dc("exec", "-T", "mongodb", "grep", "-c",
                     "requireTLS", "/etc/mongod.conf")
        self.tls = (m.returncode == 0 and m.stdout.strip().isdigit()
                    and int(m.stdout.strip()) > 0)
        h = self._dc("exec", "-T", "hss", "sh", "-c", "echo $DB_URI")
        if h.returncode == 0 and h.stdout.strip().startswith("mongodb"):
            self.db_uri = h.stdout.strip()
        i = subprocess.run(
            ["docker", "inspect", "-f",
             "{{range $k,$v := .NetworkSettings.Networks}}"
             "{{$v.NetworkID}}{{end}}", cids[0]],
            capture_output=True, text=True)
        self.net_id = (i.stdout.strip().split() or [None])[0]
        return self

    def mongo_eval(self, js):
        """Run JS in the mongodb container (JS via stdin, not process args)."""
        args = ["exec", "-T", "mongodb", "mongo"]
        if self.tls:
            args += ["--tls", "--tlsCAFile", "/etc/mongodb-tls-ca/ca.crt"]
        args += ["127.0.0.1:27017/open5gs", "--quiet"]
        cmd = ["docker", "compose"]
        for f in self.dc_files:
            cmd += ["-f", f]
        cmd += args
        r = subprocess.run(cmd, input=js, capture_output=True, text=True,
                           cwd=self.root)
        if r.returncode != 0:
            die("mongo eval failed: " + (r.stderr or r.stdout).strip())
        return r.stdout

    def dbctl(self, *args):
        """One-shot open5gs-dbctl on the core network (import-profiles.sh trick)."""
        ca = []
        if self.tls:
            ca = ["-v", BASE + "/.deploy/docker/mongodb-tls/ca.crt:"
                                "/etc/mongodb-tls-ca/ca.crt:ro"]
        r = subprocess.run(
            ["docker", "run", "--rm", "--entrypoint", "",
             "--network", self.net_id or "host"] + ca +
            ["-e", "DB_URI=" + self.db_uri, self.DBCTL_IMAGE,
             "open5gs-dbctl"] + list(args),
            capture_output=True, text=True)
        return r


def msisdn_to_bcd(d):
    """E.212 BCD (open5gs lib/core/ogs-conv.c, ogs_bcd_to_buffer): the first
    digit goes to the high nibble, odd length is padded with F in the low
    nibble. The DB stores the BCD bytes as a hex ASCII string."""
    s = str(d).strip()
    if not s or not s.isdigit():
        die("msisdn: digits only, 1-15 (got %r)" % s)
    if len(s) > 15:
        die("msisdn: 1-15 digits expected (got %d)" % len(s))
    d = s
    out = []
    for i in range(0, len(d), 2):
        out.append(d[i] + (d[i + 1] if i + 1 < len(d) else "F"))
    return "".join(out)


def bcd_to_msisdn(h):
    return "".join(ch for ch in str(h) if ch != "F")


def parse_mask(v, table):
    """'32' or 'ho to non-3GPP access not allowed,nb-iot not allowed' -> bitmask."""
    if v is None or v == "":
        return None
    s = str(v).strip()
    if s.isdigit():
        return int(s)
    total = 0
    for part in s.split(","):
        part = part.strip().lower()
        for val, label in table:
            lp = label.lower().replace(" ", "-")
            if part == lp or part.replace("-", " ") == label.lower() \
                    or part.replace("_", " ") == label.lower():
                total |= val
                break
        else:
            die("unknown flag %r (options: %s)" % (
                part, ", ".join(l for _, l in table)))
    return total


def parse_nam(v):
    if v is None or v == "":
        return None
    s = str(v).strip()
    if s.isdigit():
        n = int(s)
        if n not in (0, 1, 2):
            die("bad nam: 0/1/2 expected (got " + s + ")")
        return n
    r = {"packet": 0, "reserved": 1, "only-packet": 2}.get(
        s.lower().replace(" ", "-"))
    if r is None:
        die("bad nam: " + s)
    return r


def parse_status(v):
    if v is None or v == "":
        return None
    s = str(v).strip()
    if s.isdigit():
        n = int(s)
        if n not in (0, 1):
            die("bad status: 0/1 expected (got " + s + ")")
        return n
    r = {"granted": 0, "barring": 1}.get(s.lower())
    if r is None:
        die("bad status: " + s)
    return r


def parse_apn_type(v):
    if v is None or v == "":
        return None
    s = str(v).strip()
    if s.isdigit():
        return int(s)
    for name, val in APN_TYPES.items():
        if s.lower().replace(" ", "-") == name:
            return val
    die("bad apn type: " + s)


def build_session(name, apn_type, qos_spec, arp, ambr_d, ambr_u):
    t = parse_apn_type(apn_type)
    if t is None:
        t = APN_TYPES["internet"]
    qos = parse_qos(qos_spec or "8")
    if arp:
        s = str(arp).strip()
        if s.isdigit() or "," in s:
            tri = [int(x) for x in s.split(",")]
            if len(tri) != 3:
                die("arp: index or pri,cap,vuln (got " + s + ")")
        else:
            tri = QOS_ARPS.get(s.lower().replace(" ", "-"))
            if not tri:
                die("unknown arp name: " + s)
        qos["arp"] = OrderedDict([
            ("priority_level", tri[0]),
            ("pre_emption_capability", tri[1]),
            ("pre_emption_vulnerability", tri[2])])
    ambr = build_ambr(ambr_d, ambr_u)
    if not ambr:
        ambr = build_ambr("1G", "1G")
    return OrderedDict([("name", name), ("type", t), ("qos", qos),
                        ("ambr", ambr), ("pcc_rule", [])])


def js_literal(v):
    """Render a Python value as a mongo-shell JS literal.
    Ints become NumberInt(...) - REQUIRED: the PSMDB 5.0 shell has no
    EJSON and a plain JSON round-trip stores ints as double, while the
    open5gs readers demand BSON int32 (lib/dbi/subscription.c checks
    BSON_ITER_HOLDS_INT32). $oid markers (from JSON.stringify of
    ObjectId) become ObjectId(...)."""
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return "NumberInt(%d)" % int(v)
    if isinstance(v, float):
        return repr(v)
    if isinstance(v, str):
        return json.dumps(v)
    if isinstance(v, dict):
        if set(v.keys()) == {"$oid"}:
            return 'ObjectId("%s")' % v["$oid"]
        if set(v.keys()) == {"$numberInt"}:
            return "NumberInt(%s)" % int(v["$numberInt"])
        if set(v.keys()) == {"$numberLong"}:
            return "NumberLong(%s)" % int(v["$numberLong"])
        return "{" + ", ".join(
            "%s: %s" % (json.dumps(k), js_literal(x)) for k, x in v.items()) + "}"
    if isinstance(v, list):
        return "[" + ", ".join(js_literal(x) for x in v) + "]"
    die("js_literal: unsupported value type %r" % type(v))


def ejson_unwrap(v):
    """Inverse of EJSON markers for display (int32/int64 -> int)."""
    if isinstance(v, dict):
        if set(v.keys()) in ({"$numberInt"}, {"$numberLong"}):
            key = next(iter(v.keys()))
            try:
                return int(v[key])
            except (TypeError, ValueError):
                return v
        return {k: ejson_unwrap(x) for k, x in v.items()}
    if isinstance(v, list):
        return [ejson_unwrap(x) for x in v]
    return v


def mask_doc(doc):
    d = ejson_unwrap(json.loads(json.dumps(doc)))
    sec = d.get("security") or {}
    for k in ("k", "opc", "op"):
        if sec.get(k):
            v = str(sec[k])
            sec[k] = v[:4] + "*" * max(0, len(v) - 8) + v[-4:] \
                + " (len=%d)" % len(v)
    return d




def fetch(stack, imsi):
    out = stack.mongo_eval(
        'JSON.stringify(db.subscribers.findOne({imsi:"' + imsi + '"})||null)')
    return json.loads(out.strip() or "null")


def all_subs(stack):
    out = stack.mongo_eval(
        "JSON.stringify(db.subscribers.find().limit(1000).toArray())")
    return [ejson_unwrap(d) for d in json.loads(out.strip() or "[]")]


def build_set(row):
    """row dict -> ({$set} document, [notes]). edit never creates; 'create'
    is handled separately in apply_row. Unknown keys are an error
    (fail-closed)."""
    s = OrderedDict()
    notes = []
    known = {"imsi", "create", "msisdn", "imeisv", "mme_host", "mme_realm",
             "apn", "apn_type", "qos", "arp", "ambr_d", "ambr_u", "sst", "sd",
             "sessions", "ue_ambr", "ue_ambr_d", "ue_ambr_u",
             "access_restriction",
             "nam", "status", "barring", "tau", "purge", "security",
             "security_k", "security_opc", "ekiprofile"}
    for k in row:
        if k not in known:
            die("unknown profile field %r (fail-closed; see --help)" % k)
    if row.get("ekiprofile"):
        die("ekiprofile column is reserved: use import-profiles.sh for "
            "EKI-TK encrypted files")
    if row.get("msisdn") is not None:
        v = str(row["msisdn"]).strip()
        s["msisdn"] = [msisdn_to_bcd(v)] if v else []
    if row.get("imeisv") is not None:
        s["imeisv"] = str(row["imeisv"]).strip()
    if row.get("mme_host") is not None:
        s["mme_host"] = str(row["mme_host"]).strip()
    if row.get("mme_realm") is not None:
        s["mme_realm"] = str(row["mme_realm"]).strip()
    if row.get("sessions") is not None:
        slices = []
        sess = row["sessions"]
        if isinstance(sess, dict):
            sess = [sess]
        for ss in sess:
            if not isinstance(ss, dict):
                die("sessions: list of objects expected")
            sl = OrderedDict()
            sl["sst"] = int(ss.get("sst", 1))
            sd = str(ss.get("sd", "ffffff"))
            sl["sd"] = sd if sd != "default" else "ffffff"
            sl["default_indicator"] = bool(ss.get("default", True))
            sl["session"] = [
                build_session(str(x.get("name", "internet")),
                              x.get("type"), x.get("qos"), x.get("arp"),
                              x.get("ambr_d"), x.get("ambr_u"))
                for x in (ss.get("session") or [{}])]
            slices.append(sl)
        s["slice"] = slices
        notes.append("slice replaced (%d slice(s))" % len(slices))
    elif row.get("apn") is not None or row.get("qos") is not None \
            or row.get("arp") is not None or row.get("ambr_d") \
            or row.get("ambr_u"):
        name = str(row.get("apn") or "internet").strip()
        sess = build_session(name, row.get("apn_type"), row.get("qos"),
                             row.get("arp"), row.get("ambr_d"),
                             row.get("ambr_u"))
        sst = int(row.get("sst", 1))
        sd = str(row.get("sd", "ffffff")).strip() or "ffffff"
        s["slice"] = [OrderedDict([
            ("sst", sst), ("sd", sd), ("default_indicator", True),
            ("session", [sess])])]
        notes.append("slice replaced: apn=%s sst=%s sd=%s" % (name, sst, sd))
    if row.get("ue_ambr_d") or row.get("ue_ambr_u") or row.get("ue_ambr"):
        d = row.get("ue_ambr_d")
        u = row.get("ue_ambr_u")
        if row.get("ue_ambr"):
            d = u = row["ue_ambr"]
        s["ambr"] = build_ambr(d, u) or build_ambr("1G", "1G")
    if row.get("access_restriction") is not None:
        m = parse_mask(row["access_restriction"], ACCESS_RESTRICTIONS)
        if m is not None:
            s["access_restriction_data"] = m
    if row.get("nam") is not None:
        s["network_access_mode"] = parse_nam(row["nam"])
    if row.get("status") is not None:
        s["subscriber_status"] = parse_status(row["status"])
    if row.get("barring") is not None:
        m = parse_mask(row["barring"], BARRING_FLAGS)
        if m is not None:
            s["operator_determined_barring"] = m
    if row.get("tau") is not None:
        s["subscribed_rau_tau_timer"] = int(row["tau"])
        notes.append("tau written as-is (stack convention: minutes, "
                     "dbctl default 12)")
    if row.get("purge") is not None:
        s["purge_flag"] = bool(row["purge"])
    sec = {}
    if row.get("security") is not None and isinstance(row["security"], dict):
        sec.update(row["security"])
    if row.get("security_k") is not None:
        sec["k"] = str(row["security_k"]).strip()
    if row.get("security_opc") is not None:
        sec["opc"] = str(row["security_opc"]).strip()
    if sec:
        if bool(sec.get("k")) != bool(sec.get("opc")):
            die("security: k and opc must be set together "
                "(changing Ki without OPC is unsafe)")
        if sec.get("k"):
            for kk in ("k", "opc"):
                if not re.fullmatch(r"[0-9a-fA-F]{32}", str(sec[kk])):
                    die("security.%s: 32 hex expected" % kk)
            warn("plaintext Ki/OPc on CLI/file - prefer import-profiles.sh "
                 "(EKI-TK) for keys")
            s["security.k"] = sec["k"].lower()
            s["security.opc"] = sec["opc"].lower()
        if sec.get("amf"):
            if not re.fullmatch(r"[0-9a-fA-F]{4}", str(sec["amf"])):
                die("security.amf: 4 hex expected")
            s["security.amf"] = sec["amf"].lower()
    return s, notes



def backup_file():
    os.makedirs(BACKUP_DIR, exist_ok=True)
    p = os.path.join(
        BACKUP_DIR, "profile-mgmt-%s.json" % time.strftime("%Y%m%d-%H%M%S"))
    return p


def backup_doc(path, imsi, doc, op):
    if doc is None:
        return
    rec = json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                      "imsi": imsi, "op": op, "doc": doc},
                     separators=(",", ":"))
    with open(path, "a", encoding="utf-8") as f:
        f.write(rec + "\n")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def apply_row(stack, row, dry=False, backup=None):
    imsi = str(row.get("imsi", "")).strip()
    if not re.fullmatch(r"[0-9]{14,15}", imsi):
        die("bad IMSI %r" % imsi)
    setdoc, notes = build_set(row)
    existing = fetch(stack, imsi)
    if existing is None:
        if not row.get("create"):
            die("subscriber %s does not exist - 'edit'/'update' never "
                "create profiles; use 'add' or import-profiles.sh" % imsi)
        sec = row.get("security") or {}
        k = str(sec.get("k") or row.get("security_k") or "").strip()
        opc = str(sec.get("opc") or row.get("security_opc") or "").strip()
        if not (re.fullmatch(r"[0-9a-fA-F]{32}", k)
                and re.fullmatch(r"[0-9a-fA-F]{32}", opc)):
            die("create requires security k+opc (32 hex each) - for "
                "EKI-TK loading use import-profiles.sh")
        if dry:
            print("dry-run: dbctl add_ue_with_slice %s *** ***" % imsi)
            if setdoc:
                print("dry-run: $set %s" % json.dumps(mask_doc(setdoc)))
            return "dry"
        name = str(row.get("apn") or "internet").strip()
        sst = int(row.get("sst", 1))
        sd = str(row.get("sd") or "ffffff").strip()
        r = stack.dbctl("add_ue_with_slice", imsi, k, opc, name,
                        str(sst), sd)
        if r.returncode != 0:
            die("open5gs-dbctl add failed:\n"
                + (r.stdout or r.stderr).strip())
        if setdoc:
            out = stack.mongo_eval(
                'db.subscribers.updateOne({imsi:"' + imsi
                + '"},{$set:' + js_literal(setdoc) + '})')
            if '"matchedCount":1' not in out.replace(" ", ""):
                die("post-add $set failed: " + out.strip())
        print("added %s (%s)" % (imsi, "; ".join(notes) or "defaults"))
        return "added"
    if not setdoc:
        print("%s: nothing to apply" % imsi)
        return "nochange"
    if dry:
        print("dry-run: $set %s" % json.dumps(mask_doc(setdoc)))
        return "dry"
    if backup:
        backup_doc(backup, imsi, existing,
                   "pre-" + ",".join(setdoc.keys()))
    out = stack.mongo_eval(
        'db.subscribers.updateOne({imsi:"' + imsi
        + '"},{$set:' + js_literal(setdoc) + '})')
    j = out.replace(" ", "")
    if '"matchedCount":1' not in j:
        die("updateOne failed for %s: %s" % (imsi, out.strip()))
    if '"modifiedCount":0' in j:
        print("%s: nochange" % imsi)
        return "nochange"
    print("%s: updated (%s)" % (imsi, "; ".join(notes)
                                or ", ".join(setdoc.keys())))
    return "updated"


def restore(stack, path, imsi=None, dry=False):
    recs = [json.loads(l) for l in open(path, encoding="utf-8")
            if l.strip()]
    n = 0
    for r in recs:
        if imsi and r.get("imsi") != imsi:
            continue
        if dry:
            print("dry-run: restore %s (%s)" % (r.get("imsi"), r.get("op")))
            n += 1
            continue
        doc = r.get("doc") or {}
        # js_literal re-wraps ints as NumberInt and _id ($oid) as
        # ObjectId, so the restored document keeps the BSON types the
        # open5gs readers require (int32, not double).
        out = stack.mongo_eval(
            "JSON.stringify(db.subscribers.replaceOne("
            + json.dumps({"imsi": r.get("imsi")}) + ", "
            + js_literal(doc) + ", {upsert:true}))")
        print("restored %s: %s" % (r.get("imsi"), out.strip()))
        n += 1
    print("restore: %d record(s) from %s"
          % (n, os.path.basename(path)))
    return n



CSV_HEADER = ["imsi", "msisdn", "imeisv", "mme_host", "mme_realm",
              "apn", "apn_type", "qos", "arp", "ambr_d", "ambr_u",
              "sst", "sd", "ue_ambr_d", "ue_ambr_u", "ue_ambr",
              "access_restriction", "nam", "status", "barring", "tau",
              "purge", "security_k", "security_opc", "create"]


def read_rows(path):
    if path.lower().endswith(".json"):
        data = json.load(open(path, encoding="utf-8"))
        if isinstance(data, dict):
            data = [data]
        rows = []
        for d in data:
            if not isinstance(d, dict):
                die("JSON: list of objects expected")
            # JSON: empty string is meaningful (clears the field);
            # null / absent = keep current value
            rows.append({k: v for k, v in d.items() if v is not None})
        return rows
    rows = []
    with open(path, encoding="utf-8") as f:
        hdr = None
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if hdr is None:
                h = [x.strip().lower() for x in line.split(",")]
                if h[0] != "imsi":
                    die("CSV: first column must be 'imsi' "
                        "(header row required)")
                hdr = h
                continue
            cells = [c.strip() for c in line.split(",")]
            row = {}
            for i, name in enumerate(hdr):
                if i < len(cells) and cells[i]:
                    row[name] = cells[i]
            if row:
                rows.append(row)
    return rows


def cmd_show(stack, imsi):
    d = fetch(stack, imsi)
    if d is None:
        die("subscriber %s not found" % imsi)
    print(json.dumps(mask_doc(d), indent=2, ensure_ascii=False))


def cmd_list(stack):
    subs = all_subs(stack)
    print("%-15s %-15s %-10s %-8s %-8s %-6s %-5s %-5s" % (
        "IMSI", "MSISDN", "APN", "STATUS", "BARRING", "ACCESS", "NAM",
        "TAU"))
    for d in subs:
        imsi = d.get("imsi", "?")
        ms = ""
        if d.get("msisdn"):
            ms = bcd_to_msisdn(str(d["msisdn"][0]))
        apn = ""
        for sl in d.get("slice") or []:
            for se in sl.get("session") or []:
                apn += se.get("name", "?") + " "
        print("%-15s %-15s %-10s %-8s %-8s %-6s %-5s %-5s" % (
            imsi, ms, apn.strip(), d.get("subscriber_status", 0),
            d.get("operator_determined_barring", 0),
            d.get("access_restriction_data", 0),
            d.get("network_access_mode", 0),
            d.get("subscribed_rau_tau_timer", "")))
    print("(%d subscriber(s))" % len(subs))


def cmd_del(stack, imsi, dry, backup):
    d = fetch(stack, imsi)
    if d is None:
        die("subscriber %s not found" % imsi)
    if dry:
        print("dry-run: open5gs-dbctl remove %s" % imsi)
        return
    if backup:
        backup_doc(backup, imsi, d, "pre-delete")
    r = stack.dbctl("remove", imsi)
    if r.returncode != 0:
        die("remove failed:\n" + (r.stdout or r.stderr).strip())
    if fetch(stack, imsi) is not None:
        die("subscriber %s still present after remove" % imsi)
    print("%s: deleted (backup: %s)" % (imsi, backup))


def cmd_revoke(stack, imsi, barring, dry, backup):
    row = {"imsi": imsi, "status": "barring"}
    if barring:
        row["barring"] = barring
    apply_row(stack, row, dry=dry, backup=backup)
    if not dry:
        print("%s: revoked (subscriber_status=1)" % imsi)


def cmd_purge(stack, imsi, dry, backup):
    apply_row(stack, {"imsi": imsi, "purge": "true"}, dry=dry,
              backup=backup)


def cmd_edit(stack, path, dry, backup):
    rows = read_rows(path)
    if not rows:
        die("no rows in %s" % path)
    upd = created = 0
    for i, row in enumerate(rows, 1):
        res = apply_row(stack, row, dry=dry, backup=backup)
        if res == "updated":
            upd += 1
        elif res == "added":
            created += 1
        print("  [row %d] imsi=%s -> %s" % (i, row.get("imsi"), res))
    print("edit complete: file=%s rows=%d created=%d updated=%d"
          % (path, len(rows), created, upd))



def row_from_cli(args):
    row = {"imsi": args.imsi}
    for attr in ("msisdn", "imeisv", "mme_host", "mme_realm", "apn",
                 "apn_type", "qos", "arp", "ambr_d", "ambr_u",
                 "ue_ambr_d", "ue_ambr_u", "ue_ambr", "access_restriction",
                 "nam", "status", "barring", "tau", "sst", "sd"):
        v = getattr(args, attr.replace("-", "_"), None)
        if v not in (None, ""):
            row[attr] = v
    if getattr(args, "purge", None):
        row["purge"] = "true"
    if args.security_k or args.security_opc:
        row["security"] = {"k": args.security_k or "",
                           "opc": args.security_opc or "",
                           "amf": args.security_amf or ""}
        row["security"] = {k: v for k, v in row["security"].items()
                           if v}
    return row


def add_common(p):
    p.add_argument("--msisdn", help="MSISDN digits (stored as E.212 BCD)")
    p.add_argument("--imeisv", help="IMEISV (hex string)")
    p.add_argument("--mme-host", help="MME host (S6a restriction)")
    p.add_argument("--mme-realm", help="MME realm")
    p.add_argument("--apn", help="APN name (replaces the slice)")
    p.add_argument("--apn-type", help="internet/default/ims/... or 1-6")
    p.add_argument("--qos", help="5G QoS id: 8 or 8,2,2 (pri,cap,vuln)")
    p.add_argument("--arp", help="arp name (best-effort/voice/...) "
                                 "or pri,cap,vuln")
    p.add_argument("--ambr-d", help="session AMBR downlink, e.g. 1G/500M")
    p.add_argument("--ambr-u", help="session AMBR uplink")
    p.add_argument("--sst", help="SST (default 1)")
    p.add_argument("--sd", help="SD hex (default ffffff)")
    p.add_argument("--ue-ambr-d", help="UE-AMBR downlink")
    p.add_argument("--ue-ambr-u", help="UE-AMBR uplink")
    p.add_argument("--ue-ambr", help="UE-AMBR both directions")
    p.add_argument("--access-restriction",
                   help="bitmask or flag names (comma-separated)")
    p.add_argument("--nam", help="packet/reserved/only-packet or 0-2")
    p.add_argument("--status", help="granted/barring or 0/1")
    p.add_argument("--barring",
                   help="operator-determined barring bitmask / names")
    p.add_argument("--tau", help="RAU/TAU timer (as dbctl writes it: "
                                 "minutes, default 12)")
    p.add_argument("--security-k", help="Ki, 32 hex (LOUD WARNING; "
                                        "prefer import-profiles.sh)")
    p.add_argument("--security-opc", help="OPc, 32 hex "
                                          "(with --security-k)")
    p.add_argument("--security-amf", help="AMF, 4 hex")
    p.add_argument("--purge", action="store_true",
                   help="set purge_flag (update only)")
    p.add_argument("--dry-run", action="store_true")



def main():
    ap = argparse.ArgumentParser(
        description="open5gs subscriber profile manager (AuC)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="CSV bulk header: " + ",".join(CSV_HEADER) +
               "\nFull reference: .deploy/profiles/README.md")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("show", help="show one profile (keys masked)")
    p.add_argument("imsi")
    sub.add_parser("list", help="list subscribers")
    p = sub.add_parser("add", help="create a subscriber (dbctl base "
                                   "+ extras)")
    p.add_argument("imsi")
    add_common(p)
    p = sub.add_parser("update", help="update fields of an existing "
                                      "subscriber (never creates)")
    p.add_argument("imsi")
    add_common(p)
    p = sub.add_parser("edit", help="bulk apply a profile file "
                                    "(CSV or JSON)")
    p.add_argument("file")
    p.add_argument("--dry-run", action="store_true")
    p = sub.add_parser("del", help="delete a subscriber")
    p.add_argument("imsi")
    p.add_argument("--dry-run", action="store_true")
    p = sub.add_parser("revoke",
                       help="revoke: subscriber_status=barring")
    p.add_argument("imsi")
    p.add_argument("--barring", help="barring flags (optional)")
    p.add_argument("--dry-run", action="store_true")
    p = sub.add_parser("purge", help="set purge_flag=true")
    p.add_argument("imsi")
    p.add_argument("--dry-run", action="store_true")
    p = sub.add_parser("restore",
                       help="restore from a profile-mgmt backup")
    p.add_argument("backup")
    p.add_argument("imsi", nargs="?")
    p.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    stack = Stack().detect()
    dry = getattr(args, "dry_run", False)
    backup = None if (dry or args.cmd in ("show", "list")) else backup_file()
    if args.cmd == "show":
        cmd_show(stack, args.imsi)
    elif args.cmd == "list":
        cmd_list(stack)
    elif args.cmd == "add":
        row = row_from_cli(args)
        row["create"] = True
        res = apply_row(stack, row, dry=dry, backup=backup)
        if backup and not dry and res == "added":
            print("backup: %s" % backup)
    elif args.cmd == "update":
        row = row_from_cli(args)
        res = apply_row(stack, row, dry=dry, backup=backup)
        if backup and not dry and res == "updated":
            print("backup: %s" % backup)
    elif args.cmd == "edit":
        cmd_edit(stack, args.file, dry=dry, backup=backup)
        if backup and not dry:
            print("backup: %s (contains previous documents with "
                  "keys - keep it secret)" % backup)
    elif args.cmd == "del":
        cmd_del(stack, args.imsi, dry, backup)
    elif args.cmd == "revoke":
        cmd_revoke(stack, args.imsi, args.barring, dry, backup)
    elif args.cmd == "purge":
        cmd_purge(stack, args.imsi, dry, backup)
    elif args.cmd == "restore":
        restore(stack, args.backup, args.imsi, dry)
    if backup and not dry:
        print("NOTE: backup file %s contains plaintext keys; store it "
              "like a secret (chmod 600 applied)" % backup)


if __name__ == "__main__":
    main()
