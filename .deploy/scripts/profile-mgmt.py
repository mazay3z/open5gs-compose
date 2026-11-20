#!/usr/bin/env python3
"""
profile-mgmt.py - open5gs subscriber profile manager (AuC: 4G HSS + 5G UDM/UDR)

v2 (2026-11-19, PLTEBOX-137):
  - several APN (sessions) per IMSI + static IP per APN (session.ue.ipv4/ipv6)
  - KV bulk format: only the fields that must be changed
  - CSV (positional) and JSON (explicit slice replace) formats kept
  - two-phase 'edit': the whole file is validated before the first write
  - backups only with --backup (a backup contains plaintext keys)

Based on open5gs-utils/ctrl-imsi-profile.py. Field reference:
.deploy/profiles/README.md. EKI-TK encrypted key loading: import-profiles.sh.

Usage (works from any cwd; the repo root is resolved from this file):
  python3 .deploy/scripts/profile-mgmt.py show   <imsi>
  python3 .deploy/scripts/profile-mgmt.py list
  python3 .deploy/scripts/profile-mgmt.py add    <imsi> [options]
  python3 .deploy/scripts/profile-mgmt.py update <imsi> [options]
  python3 .deploy/scripts/profile-mgmt.py edit   <file.kv|file.csv|file.json> [--dry-run] [--backup]
  python3 .deploy/scripts/profile-mgmt.py del    <imsi>
  python3 .deploy/scripts/profile-mgmt.py revoke <imsi> [--barring FLAGS]
  python3 .deploy/scripts/profile-mgmt.py purge  <imsi>
  python3 .deploy/scripts/profile-mgmt.py delete-all [--dry-run] [--yes] [--backup]
  python3 .deploy/scripts/profile-mgmt.py restore <backup.json> [imsi]

Bulk formats (auto-detected):

  KV (recommended): one line = one change packet; only the listed fields
  change, the rest of the profile is kept:
      imsi=999990000000101, apn=internet, qos=9, ambr_d=500M, ipv4=10.20.30.40
      imsi=999990000000101, apn=ims, apn_type=4, sst=1, sd=201111
      imsi=999990000000102, msisdn=799900000002
      imsi=999990000000102, ipv4=                # empty value = clear
  Multiple lines with the same IMSI merge additively; later lines win.
  A line with apn= (or qos/arp/ambr_d/ambr_u/ipv4/ipv6) upserts ONE session
  in slice (sst, sd); other sessions/slices are not touched (open5gs limits:
  4 sessions per slice, 8 slices).  Quoted values may contain commas:
  "arp=8,1,2".
  CSV: positional table, header row required (first column 'imsi'),
  empty cell = keep.  Repeated IMSI rows merge the same way as KV.
  (Clearing a field in CSV is not possible - use KV or JSON.)
  JSON: list of objects, same field names as KV; "" clears a field,
  absent/null keeps it.  "sessions" is the explicit form and REPLACES
  whole slices:
      [{"imsi":"...","sessions":[{"sst":1,"sd":"ffffff","default":true,
        "session":[{"name":"internet","type":3,"qos":"8","ipv4":"10.1.2.3"}]}]}]

edit is two-phase: (1) parse + validate every row and simulate the result
(limits, formats) - any error aborts the whole file and NOTHING is written;
(2) apply.  --dry-run stops after phase 1.

security_k/security_opc = plaintext Ki/OPc (32 hex) - a LOUD warning is
printed; for encrypted key loading use import-profiles.sh (EKI-TK).
Backups (--backup) contain plaintext keys: treat them as secrets
(gitignored dir, chmod 600).
"""

import os, re, sys, json, csv, argparse, subprocess, time
from collections import OrderedDict

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BACKUP_DIR = os.path.join(BASE, ".deploy", "backups")

MAX_SESS = 4   # OGS_MAX_NUM_OF_SESS  - open5gs lib/proto/types.h:31
MAX_SLICE = 8  # OGS_MAX_NUM_OF_SLICE - open5gs lib/proto/types.h:137

def warn(msg):
    print("WARN: " + str(msg), file=sys.stderr)


def die(msg):
    print("FAIL: " + str(msg), file=sys.stderr)
    sys.exit(1)


class RowError(Exception):
    """Phase-1 validation error on one bulk row (collected, not fatal)."""


# --- parameter tables (open5gs 2.7.7) ---
APN_TYPES = OrderedDict([
    ("default", 1), ("optimized", 2), ("internet", 3),
    ("ims", 4), ("dedicated", 5), ("emergency", 6)])
QOS_ARPS = OrderedDict([
    ("conversational", [2, 1, 1]), ("video", [4, 1, 1]), ("voice", [5, 1, 1]),
    ("vector-video", [6, 1, 2]), ("non-interactive", [7, 1, 2]),
    ("best-effort", [8, 1, 2]), ("supplementary-services", [9, 1, 2]),
    ("gps", [6, 2, 2]), ("nrtolr", [8, 2, 2])])
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
# --- value parsers (raise RowError on bad input) ---

def ambr_to_mb(m):
    m = (m or "1G").strip().upper()
    if m.endswith("G"):
        try:
            v = int(m[:-1])
        except ValueError:
            raise RowError("ambr: bad value " + m)
        return (v * 1024) << 20
    if m.endswith("M"):
        try:
            v = int(m[:-1])
        except ValueError:
            raise RowError("ambr: bad value " + m)
        return v << 20
    raise RowError("ambr: use like 1G / 500M (got " + m + ")")


def build_ambr(a, b, existing=None):
    """Session/UE AMBR; directions not given keep the existing value or
    default to 1G (same behaviour as open5gs writers)."""
    out = OrderedDict()
    for k, v in (("downlink", a), ("uplink", b)):
        if v:
            out[k] = OrderedDict([("value", ambr_to_mb(v)), ("unit", 0)])
        elif existing and k in existing:
            out[k] = existing[k]
        else:
            out[k] = OrderedDict([("value", ambr_to_mb("1G")), ("unit", 0)])
    return out


def parse_qos(spec):
    parts = (spec or "8").strip().split(",")
    if len(parts) not in (1, 3):
        raise RowError("qos: expect index or index,pri,cap "
                       "(got " + str(spec) + ")")
    for x in parts:
        if not x.strip().isdigit():
            raise RowError("qos: numeric expected (got " + str(spec) + ")")
    idx = int(parts[0])
    if not (1 <= idx <= 255):
        raise RowError("qos: 5QI 1-255 expected (got %d)" % idx)
    if len(parts) == 1:
        pri, cap = 8, 1   # best-effort ARP, as open5gs-dbctl writes
    else:
        pri, cap = int(parts[1]), int(parts[2])
        if not (1 <= pri <= 15):
            raise RowError("qos: arp priority 1-15 expected (got %d)" % pri)
        if cap not in (1, 2):
            raise RowError("qos: arp preemption capability must be 1 or 2 "
                           "(got %d) - the UDR asserts on any other value"
                           % cap)
    return OrderedDict([
        ("index", idx),
        ("arp", OrderedDict([
            ("priority_level", pri),
            ("pre_emption_capability", cap),
            ("pre_emption_vulnerability", 2)])),
    ])


def parse_arp(v):
    s = str(v).strip()
    if "," in s:
        tri = [x.strip() for x in s.split(",")]
        if len(tri) != 3 or not all(x.isdigit() for x in tri):
            raise RowError("arp: name or pri,cap,vuln (got " + s + ")")
        tri = [int(x) for x in tri]
    elif s.isdigit():
        tri = [int(s), 1, 2]
    else:
        tri = QOS_ARPS.get(s.lower().replace(" ", "-"))
        if not tri:
            raise RowError("unknown arp name: " + s)
    return OrderedDict([("priority_level", tri[0]),
                        ("pre_emption_capability", tri[1]),
                        ("pre_emption_vulnerability", tri[2])])


def msisdn_to_bcd(d):
    """E.212 BCD (open5gs lib/core/ogs-conv.c, ogs_bcd_to_buffer): the first
    digit goes to the high nibble, odd length padded with F. The DB stores
    the BCD bytes as a hex ASCII string."""
    s = str(d).strip()
    if not s or not s.isdigit():
        raise RowError("msisdn: digits only, 1-15 (got %r)" % s)
    if len(s) > 15:
        raise RowError("msisdn: 1-15 digits expected (got %d)" % len(s))
    out = []
    for i in range(0, len(s), 2):
        out.append(s[i] + (s[i + 1] if i + 1 < len(s) else "F"))
    return "".join(out)


def bcd_to_msisdn(h):
    return "".join(ch for ch in str(h) if ch != "F")


def parse_mask(v, table):
    """'32' or 'ho to non-3GPP access not allowed,nb-iot not allowed'."""
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
            raise RowError("unknown flag %r (options: %s)" % (
                part, ", ".join(l for _, l in table)))
    return total


def parse_nam(v):
    s = str(v).strip()
    if s.isdigit():
        n = int(s)
        if n not in (0, 1, 2):
            raise RowError("bad nam: 0/1/2 expected (got " + s + ")")
        return n
    r = {"packet": 0, "reserved": 1, "only-packet": 2}.get(
        s.lower().replace(" ", "-"))
    if r is None:
        raise RowError("bad nam: " + s)
    return r


def parse_status(v):
    s = str(v).strip()
    if s.isdigit():
        n = int(s)
        if n not in (0, 1):
            raise RowError("bad status: 0/1 expected (got " + s + ")")
        return n
    r = {"granted": 0, "barring": 1}.get(s.lower())
    if r is None:
        raise RowError("bad status: " + s)
    return r


def parse_bool(v):
    s = str(v).strip().lower()
    if s in ("1", "true", "yes", "on"):
        return True
    if s in ("0", "false", "no", "off"):
        return False
    raise RowError("bool expected (got %r)" % v)
def parse_apn_type(v):
    s = str(v).strip()
    if s.isdigit():
        n = int(s)
        if n not in APN_TYPES.values():
            raise RowError("bad apn type: 1-6 expected (got " + s + ")")
        return n
    for name, val in APN_TYPES.items():
        if s.lower().replace(" ", "-") == name:
            return val
    raise RowError("bad apn type: " + s)


def parse_ipv4(v):
    import ipaddress
    s = str(v).strip()
    if not s:
        return ""
    host = s.split("/")[0]
    if s.count("/") > 1 or (s.count("/") == 1
                            and s.split("/")[1] not in ("32", "")):
        raise RowError("ipv4: use a.b.c.d or a.b.c.d/32 (got " + s + ")")
    try:
        ipaddress.IPv4Address(host)
    except ValueError:
        raise RowError("ipv4: bad address (got " + s + ")")
    return host


def parse_ipv6(v):
    import ipaddress
    s = str(v).strip()
    if not s:
        return ""
    if "/" in s:
        a, p = s.rsplit("/", 1)
        if not p.isdigit() or not (0 <= int(p) <= 128):
            raise RowError("ipv6: bad prefix in " + s)
    else:
        a, p = s, None
    try:
        ipaddress.IPv6Address(a)
    except ValueError:
        raise RowError("ipv6: bad address (got " + s + ")")
    # the open5gs reader (ogs_ipsubnet) applies a full mask when no prefix
    # is given, so a plain address means /128
    return s if p is None else a + "/" + p


def parse_sst(v):
    try:
        n = int(str(v).strip())
    except ValueError:
        raise RowError("sst: integer expected (got %s)" % v)
    if not (0 <= n <= 255):
        raise RowError("sst: 0-255 expected (got %d)" % n)
    return n


def norm_sd(v):
    s = str(v).strip().lower().replace("0x", "")
    if s in ("", "default", "ffffff"):
        return "ffffff"
    if re.fullmatch(r"[0-9a-f]{6}", s):
        return s
    raise RowError("sd: 6 hex digits or 'default' expected (got %s)" % v)


# --- mongo-shell literal rendering ---

def js_literal(v):
    """Render a Python value as a mongo-shell JS literal.
    Ints become NumberInt(...) - REQUIRED: the PSMDB 5.0 shell has no
    EJSON and a plain JSON round-trip stores ints as double, while the
    open5gs readers demand BSON int32 (lib/dbi/subscription.c checks
    BSON_ITER_HOLDS_INT32).  $oid markers (from JSON.stringify of
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
class Stack:
    """Compose context: repo root + active compose files + auto-detect of
    MongoDB TLS mode and DB_URI (same pattern as .deploy/scripts/import-profiles.sh)."""

    DBCTL_IMAGE = "gradiant/open5gs-dbctl:0.10.3"

    def __init__(self):
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
        return subprocess.run(cmd, capture_output=True, text=True,
                               cwd=self.root)

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
        """Run JS in the mongodb container (JS via stdin, not args)."""
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
        """One-shot open5gs-dbctl on the core network (import-profiles.sh
        trick)."""
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


def fetch(stack, imsi):
    out = stack.mongo_eval(
        'JSON.stringify(db.subscribers.findOne({imsi:"' + imsi + '"})||null)')
    return json.loads(out.strip() or "null")


def all_subs(stack):
    out = stack.mongo_eval(
        "JSON.stringify(db.subscribers.find().limit(1000).toArray())")
    return [ejson_unwrap(d) for d in json.loads(out.strip() or "[]")]
# --- change-set model (one IMSI, possibly from several rows) ---

SESSION_FIELDS = ("apn", "apn_type", "qos", "arp", "ambr_d", "ambr_u",
                  "ipv4", "ipv6")
SLICE_FIELDS = ("sst", "sd")
SCALAR_FIELDS = ("msisdn", "imeisv", "mme_host", "mme_realm",
                 "ue_ambr", "ue_ambr_d", "ue_ambr_u",
                 "access_restriction", "nam", "status", "barring",
                 "tau", "purge", "security_k", "security_opc", "create")
CLEARABLE = ("msisdn", "imeisv", "mme_host", "mme_realm", "ipv4", "ipv6")
KNOWN_ROW_KEYS = set(SESSION_FIELDS) | set(SLICE_FIELDS) | set(SCALAR_FIELDS) \
    | {"imsi", "security", "sessions", "ekiprofile"}


class Ops:
    """Accumulated change set for one IMSI."""

    def __init__(self, imsi, src):
        self.imsi = imsi
        self.src = src
        self.fields = OrderedDict()
        self.specs = []         # [{apn..., sst, sd}] session upserts
        self.replace = None     # explicit slice list (JSON 'sessions')
        self.create = False

    def merge(self, other):
        for k, v in other.fields.items():
            self.fields[k] = v
        self.specs.extend(other.specs)
        if other.replace is not None:
            self.replace = other.replace
        self.create = self.create or other.create


def ops_from_row(row, src):
    """Row dict (raw values) -> Ops. Raises RowError on bad input."""
    imsi = str(row.get("imsi") or "").strip()
    if not re.fullmatch(r"[0-9]{14,15}", imsi):
        raise RowError("bad or missing IMSI %r" % imsi)
    if row.get("ekiprofile"):
        raise RowError("ekiprofile is reserved: use import-profiles.sh "
                       "for EKI-TK encrypted files")
    for k in row:
        if k not in KNOWN_ROW_KEYS:
            raise RowError("unknown field %r" % k)
    ops = Ops(imsi, src)
    if str(row.get("create", "") or "").strip().lower() in ("1", "true", "yes"):
        ops.create = True
    for k in SCALAR_FIELDS:
        if k in row and k != "create":
            ops.fields[k] = row[k]
    has_sess = any(str(row.get(k, "") or "").strip() != ""
                   for k in SESSION_FIELDS)
    if has_sess:
        spec = OrderedDict()
        for k in SESSION_FIELDS:
            if k in row:
                spec[k] = row[k]
        spec["sst"] = row.get("sst", 1)
        spec["sd"] = row.get("sd", "ffffff")
        ops.specs.append(spec)
    if row.get("sessions") is not None:
        if has_sess:
            raise RowError("'sessions' (slice replace) cannot be mixed "
                           "with session fields (apn/qos/arp/ambr/ipv4/"
                           "ipv6) in the same row")
        ops.replace = build_slice_list(row["sessions"])
    if isinstance(row.get("security"), dict):
        ops.fields["security"] = row["security"]
    return ops


def session_from_spec(spec, existing=None):
    """Session doc from a spec dict; `existing` session doc (if any)
    supplies the values the spec does not give."""
    name = str(spec.get("apn") or spec.get("name") or "internet").strip()
    if not name:
        raise RowError("session name empty")
    doc = json.loads(json.dumps(existing)) if existing else OrderedDict()
    doc["name"] = name
    t = spec.get("apn_type", spec.get("type"))
    if str(t or "").strip():
        doc["type"] = parse_apn_type(t)
    elif not existing:
        doc["type"] = APN_TYPES["internet"]
    if str(spec.get("qos") or "").strip():
        doc["qos"] = parse_qos(spec["qos"])
    elif not existing:
        doc["qos"] = parse_qos("8")
    if str(spec.get("arp") or "").strip():
        doc["qos"]["arp"] = parse_arp(spec["arp"])
    if spec.get("ambr_d") or spec.get("ambr_u") or not existing:
        doc["ambr"] = build_ambr(spec.get("ambr_d"), spec.get("ambr_u"),
                                 existing=(existing or {}).get("ambr"))
    if "ipv4" in spec or "ipv6" in spec:
        ue = doc.setdefault("ue", OrderedDict())
        for k in ("ipv4", "ipv6"):
            if k in spec:
                v = parse_ipv4(spec[k]) if k == "ipv4" \
                    else parse_ipv6(spec[k])
                if v:
                    ue[k] = v
                elif k in ue:
                    del ue[k]
        if not ue:
            del doc["ue"]
    doc.setdefault("pcc_rule", (existing or {}).get("pcc_rule", []))
    return doc


def build_slice_list(sess):
    """JSON 'sessions' value -> list of slice docs (EXPLICIT replace)."""
    if isinstance(sess, dict):
        sess = [sess]
    if not isinstance(sess, list):
        raise RowError("sessions: list of objects expected")
    out = []
    for ss in sess:
        if not isinstance(ss, dict):
            raise RowError("sessions: list of objects expected")
        for k in ss:
            if k not in ("sst", "sd", "default", "session"):
                raise RowError("sessions: unknown key %r" % k)
        sl = OrderedDict()
        sl["sst"] = parse_sst(ss.get("sst", 1))
        sd = str(ss.get("sd", "ffffff"))
        sl["sd"] = "ffffff" if sd == "default" else norm_sd(sd)
        sl["default_indicator"] = bool(ss.get("default", True))
        sl["session"] = [session_from_spec(x) for x in (ss.get("session") or [{}])]
        out.append(sl)
    return out
def merge_sessions(current_slices, specs, replace=None):
    """Apply session upserts (and/or an explicit slice replace) to the
    current slice list -> new slice list. Raises RowError on limits."""
    if replace is not None and specs:
        raise RowError("mixing 'sessions' replace with session upserts "
                       "is not allowed for the same IMSI")
    slices = json.loads(json.dumps(replace if replace is not None
                                   else (current_slices or [])))
    if not isinstance(slices, list):
        raise RowError("slice: list expected")
    for spec in specs:
        sst = parse_sst(spec.get("sst", 1))
        sd = norm_sd(spec.get("sd", "ffffff"))
        name = str(spec.get("apn") or spec.get("name") or "internet").strip()
        idx = None
        for i, sl in enumerate(slices):
            if isinstance(sl, dict) \
                    and str(sl.get("sst", "1")) == str(sst) \
                    and str(sl.get("sd", "ffffff")) == sd:
                idx = i
                break
        if idx is None:
            if len(slices) >= MAX_SLICE:
                raise RowError("max %d slices per subscriber (open5gs)"
                               % MAX_SLICE)
            first = not slices or (sst == 1 and sd == "ffffff")
            slices.append(OrderedDict([("sst", sst), ("sd", sd),
                                        ("default_indicator", bool(first)),
                                        ("session", [])]))
            idx = len(slices) - 1
        sl = slices[idx]
        if not isinstance(sl.get("session"), list):
            sl["session"] = []
        ses = sl["session"]
        j = None
        for i, x in enumerate(ses):
            if isinstance(x, dict) and x.get("name") == name:
                j = i
                break
        if j is None:
            if len(ses) >= MAX_SESS:
                raise RowError("max %d sessions (APN) per slice (open5gs)"
                               % MAX_SESS)
            ses.append(session_from_spec(spec, existing=None))
        else:
            ses[j] = session_from_spec(spec, existing=ses[j])
    return slices


def validate_plan(ops, current):
    """Phase 1: check every value of the change set (read-only)."""
    f = ops.fields
    for k, v in f.items():
        s = str(v)
        if k == "security":
            sec = v or {}
            kk, opc = str(sec.get("k") or ""), str(sec.get("opc") or "")
            if bool(kk) != bool(opc):
                raise RowError("security: k and opc must be set together")
            if kk and not (re.fullmatch(r"[0-9a-fA-F]{32}", kk)
                           and re.fullmatch(r"[0-9a-fA-F]{32}", opc)):
                raise RowError("security.k/opc: 32 hex expected")
            if sec.get("amf") and not re.fullmatch(r"[0-9a-fA-F]{4}",
                                                   str(sec["amf"])):
                raise RowError("security.amf: 4 hex expected")
            continue
        if s.strip() == "":
            if k not in CLEARABLE:
                raise RowError("field %r: empty value not allowed "
                               "(clearable: %s)"
                               % (k, ", ".join(CLEARABLE)))
            continue
        if k == "msisdn":
            msisdn_to_bcd(s)
        elif k == "tau":
            try:
                if int(s) < 1:
                    raise RowError("tau: positive integer expected")
            except ValueError:
                raise RowError("tau: integer expected (got %s)" % s)
        elif k == "purge":
            parse_bool(s)
        elif k == "nam":
            parse_nam(s)
        elif k == "status":
            parse_status(s)
        elif k == "access_restriction":
            parse_mask(s, ACCESS_RESTRICTIONS)
        elif k == "barring":
            parse_mask(s, BARRING_FLAGS)
        elif k in ("security_k", "security_opc"):
            if not re.fullmatch(r"[0-9a-fA-F]{32}", s.strip()):
                raise RowError("%s: 32 hex expected" % k)
        elif k in ("ue_ambr", "ue_ambr_d", "ue_ambr_u"):
            ambr_to_mb(s)
        elif k == "imeisv":
            if not re.fullmatch(r"[0-9a-fA-F]{8,16}", s.strip()):
                raise RowError("imeisv: 8-16 hex expected (got %s)" % s)
    for spec in ops.specs:
        parse_sst(spec.get("sst", 1))
        norm_sd(spec.get("sd", "ffffff"))
        if str(spec.get("qos") or "").strip():
            parse_qos(spec["qos"])
        if str(spec.get("arp") or "").strip():
            parse_arp(spec["arp"])
        t = spec.get("apn_type", spec.get("type"))
        if str(t or "").strip():
            parse_apn_type(t)
        for k in ("ambr_d", "ambr_u"):
            if spec.get(k):
                ambr_to_mb(spec[k])
        if str(spec.get("ipv4") or "").strip():
            parse_ipv4(spec["ipv4"])
        if str(spec.get("ipv6") or "").strip():
            parse_ipv6(spec["ipv6"])
    if ops.create and current is None:
        sec = f.get("security") or {}
        k = str(sec.get("k") or f.get("security_k") or "").strip()
        opc = str(sec.get("opc") or f.get("security_opc") or "").strip()
        if not (re.fullmatch(r"[0-9a-fA-F]{32}", k)
                and re.fullmatch(r"[0-9a-fA-F]{32}", opc)):
            raise RowError("create requires security k+opc (32 hex each) "
                           "- for EKI-TK loading use import-profiles.sh")
    # simulate the merge (slice/session limits)
    merge_sessions((current or {}).get("slice"), ops.specs,
                   replace=ops.replace)
def compute_set(ops, current):
    """Phase 2: change set + current doc -> ($set document, [notes])."""
    setdoc = OrderedDict()
    notes = []
    f = ops.fields
    if "msisdn" in f:
        v = str(f["msisdn"]).strip()
        setdoc["msisdn"] = [msisdn_to_bcd(v)] if v else []
        notes.append("msisdn" + ("" if v else "-cleared"))
    if "imeisv" in f:
        setdoc["imeisv"] = str(f["imeisv"]).strip()
        notes.append("imeisv")
    if "mme_host" in f:
        setdoc["mme_host"] = str(f["mme_host"]).strip()
        notes.append("mme_host")
    if "mme_realm" in f:
        setdoc["mme_realm"] = str(f["mme_realm"]).strip()
        notes.append("mme_realm")
    if ops.replace is not None or ops.specs:
        setdoc["slice"] = merge_sessions((current or {}).get("slice"),
                                         ops.specs, replace=ops.replace)
        notes.append("slices=%d" % len(setdoc["slice"]))
    if f.get("ue_ambr") or f.get("ue_ambr_d") or f.get("ue_ambr_u"):
        d, u = f.get("ue_ambr_d"), f.get("ue_ambr_u")
        if f.get("ue_ambr"):
            d = u = f["ue_ambr"]
        setdoc["ambr"] = build_ambr(d, u, existing=(current or {}).get("ambr"))
        notes.append("ue_ambr")
    if f.get("access_restriction") is not None:
        m = parse_mask(f["access_restriction"], ACCESS_RESTRICTIONS)
        if m is not None:
            setdoc["access_restriction_data"] = m
            notes.append("access")
    if f.get("nam") is not None:
        setdoc["network_access_mode"] = parse_nam(f["nam"])
        notes.append("nam")
    if f.get("status") is not None:
        setdoc["subscriber_status"] = parse_status(f["status"])
        notes.append("status")
    if f.get("barring") is not None:
        m = parse_mask(f["barring"], BARRING_FLAGS)
        if m is not None:
            setdoc["operator_determined_barring"] = m
            notes.append("barring")
    if f.get("tau") is not None:
        setdoc["subscribed_rau_tau_timer"] = int(str(f["tau"]).strip())
        notes.append("tau")
    if f.get("purge") is not None:
        setdoc["purge_flag"] = parse_bool(f["purge"])
        notes.append("purge_flag")
    sec = {}
    if isinstance(f.get("security"), dict):
        sec.update(f["security"])
    if f.get("security_k") is not None:
        sec["k"] = str(f["security_k"]).strip()
    if f.get("security_opc") is not None:
        sec["opc"] = str(f["security_opc"]).strip()
    if sec:
        if sec.get("k"):
            warn("plaintext Ki/OPc - prefer import-profiles.sh (EKI-TK)")
            setdoc["security.k"] = str(sec["k"]).lower()
            setdoc["security.opc"] = str(sec["opc"]).lower()
            notes.append("security k+opc")
        if sec.get("amf"):
            setdoc["security.amf"] = str(sec["amf"]).lower()
            notes.append("security amf")
    return setdoc, notes
def backup_file():
    os.makedirs(BACKUP_DIR, exist_ok=True)
    return os.path.join(
        BACKUP_DIR, "profile-mgmt-%s.json" % time.strftime("%Y%m%d-%H%M%S"))


def backup_doc(path, imsi, doc, op):
    if doc is None or not path:
        return
    rec = json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                      "imsi": imsi, "op": op, "doc": doc},
                     separators=(",", ":"))
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(rec + "\n")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def read_rows(path):
    """Parse a bulk file -> (rows, errors).
    rows: list of raw dicts; KV preserves empty values ('' = clear);
    CSV: empty cell = field absent; JSON: null/absent = field absent."""
    rows, errors = [], []
    if path.lower().endswith(".json"):
        try:
            data = json.load(open(path, encoding="utf-8"))
        except Exception as e:
            return [], ["JSON: %s" % e]
        if isinstance(data, dict):
            data = [data]
        if not isinstance(data, list):
            return [], ["JSON: list of objects expected"]
        for i, d in enumerate(data, 1):
            if not isinstance(d, dict):
                errors.append("JSON item %d: object expected" % i)
                continue
            rows.append({k: v for k, v in d.items() if v is not None})
        return rows, errors
    lines = open(path, encoding="utf-8").read().splitlines()
    body = [(n, l) for n, l in enumerate(lines, 1)
            if l.strip() and not l.strip().startswith("#")]
    if not body:
        return [], []
    first = body[0][1].strip()
    if re.match(r"^imsi\s*=", first):
        for n, l in body:
            try:
                cells = next(csv.reader([l], skipinitialspace=True))
            except csv.Error as e:
                errors.append("line %d: %s" % (n, e))
                continue
            row, bad = {}, False
            for c in cells:
                c = c.strip()
                if not c:
                    continue
                if "=" not in c:
                    errors.append("line %d: expected key=value (got %r)"
                                  % (n, c))
                    bad = True
                    break
                k, v = c.split("=", 1)
                k = k.strip().lower()
                if k in row:
                    errors.append("line %d: field %r given twice" % (n, k))
                    bad = True
                    break
                row[k] = v.strip()
            if not bad:
                rows.append(row)
        return rows, errors
    # positional CSV: header row required, first column 'imsi'
    hdr = None
    for n, l in body:
        if hdr is None:
            h = [x.strip().lower() for x in l.split(",")]
            if h[0] != "imsi":
                errors.append("line %d: CSV header must start with 'imsi'"
                              % n)
                return rows, errors
            for name in h:
                if name and name != "imsi" and name not in KNOWN_ROW_KEYS:
                    errors.append("line %d: unknown CSV column %r" % (n, name))
            hdr = h
            continue
        cells = [c.strip() for c in l.split(",")]
        if len(cells) > len(hdr):
            errors.append("line %d: more cells (%d) than header (%d)"
                          % (n, len(cells), len(hdr)))
            continue
        row = {}
        for i, name in enumerate(hdr):
            if name in ("", "imsi"):
                continue
            if i < len(cells) and cells[i]:
                row[name] = cells[i]
        if row:
            rows.append(row)
    return rows, errors
def apply_plan(stack, ops, dry=False, backup=None):
    """Phase 2 for one IMSI. Returns a result tag."""
    imsi = ops.imsi
    current = fetch(stack, imsi)
    if ops.create:
        if current is None:
            if dry:
                print("dry-run: add %s (dbctl add_ue_with_slice + fields)"
                      % imsi)
                return "dry"
            sec = ops.fields.get("security") or {}
            k = str(sec.get("k") or ops.fields.get("security_k") or "").strip()
            opc = str(sec.get("opc")
                      or ops.fields.get("security_opc") or "").strip()
            warn("plaintext Ki/OPc - prefer import-profiles.sh (EKI-TK)")
            spec = ops.specs[0] if ops.specs else {}
            name = str(spec.get("apn") or spec.get("name")
                       or "internet").strip()
            sst = parse_sst(spec.get("sst", 1))
            sd = norm_sd(spec.get("sd", "ffffff"))
            r = stack.dbctl("add_ue_with_slice", imsi, k, opc, name,
                            str(sst), sd)
            if r.returncode != 0:
                die("open5gs-dbctl add failed:\n"
                    + (r.stdout or r.stderr).strip())
            current = fetch(stack, imsi)
            if current is None:
                die("subscriber not present after dbctl add")
            print("added %s (dbctl base session %s/%s/%s)"
                  % (imsi, name, sst, sd))
        else:
            warn("create requested but %s already exists - updating" % imsi)
    setdoc, notes = compute_set(ops, current)
    if not setdoc:
        print("%s: nothing to apply" % imsi)
        return "nochange"
    if dry:
        print("dry-run: %s $set %s" % (imsi,
                                       json.dumps(mask_doc(setdoc),
                                                  ensure_ascii=False)))
        return "dry"
    backup_doc(backup, imsi, current, "pre-edit")
    out = stack.mongo_eval(
        'db.subscribers.updateOne({imsi:"' + imsi
        + '"},{$set:' + js_literal(setdoc) + '})')
    j = out.replace(" ", "")
    if '"matchedCount":1' not in j:
        die("updateOne failed for %s: %s" % (imsi, out.strip()))
    if '"modifiedCount":0' in j:
        print("%s: nochange" % imsi)
        return "nochange"
    print("%s: updated (%s)" % (imsi, "; ".join(notes) or ", ".join(setdoc)))
    return "updated"


def cmd_edit(stack, path, dry, backup):
    rows, perrs = read_rows(path)
    if perrs:
        for e in perrs:
            print("parse: " + e, file=sys.stderr)
        die("phase 1 (parse) failed: %d error(s) - nothing written"
            % len(perrs))
    if not rows:
        die("no rows in %s" % path)
    # --- phase 1: validate everything (read-only) ---
    plans, errs = OrderedDict(), []
    for i, row in enumerate(rows, 1):
        try:
            ops = ops_from_row(row, "row %d" % i)
        except RowError as e:
            errs.append("row %d: %s" % (i, e))
            continue
        if ops.imsi in plans:
            plans[ops.imsi].merge(ops)
        else:
            plans[ops.imsi] = ops
    for imsi, ops in plans.items():
        try:
            validate_plan(ops, fetch(stack, imsi))
        except RowError as e:
            errs.append("imsi %s (%s): %s" % (imsi, ops.src, e))
    if errs:
        for e in errs:
            print("validate: " + e, file=sys.stderr)
        die("phase 1 (validate) failed: %d error(s) - nothing written"
            % len(errs))
    if dry:
        print("phase 1 ok: %d row(s), %d imsi(s) - dry-run, nothing written"
              % (len(rows), len(plans)))
        for ops in plans.values():
            print("dry-run: imsi=%s fields=%s sessions=%d%s" % (
                ops.imsi,
                ",".join(ops.fields.keys()) or "-",
                len(ops.specs),
                ", replace slices" if ops.replace is not None else ""))
        return
    print("phase 1 ok: %d row(s), %d imsi(s) - applying"
          % (len(rows), len(plans)))
    # --- phase 2: apply ---
    upd = nochg = 0
    for imsi, ops in plans.items():
        res = apply_plan(stack, ops, dry=False, backup=backup)
        if res == "updated":
            upd += 1
        elif res == "nochange":
            nochg += 1
        print("  [imsi %s] -> %s" % (imsi, res))
    print("edit complete: file=%s rows=%d imsis=%d updated=%d nochange=%d"
          % (path, len(rows), len(plans), upd, nochg))
def cmd_show(stack, imsi):
    d = fetch(stack, imsi)
    if d is None:
        die("subscriber %s not found" % imsi)
    print(json.dumps(mask_doc(d), indent=2, ensure_ascii=False))


def cmd_list(stack):
    subs = all_subs(stack)
    print("%-15s %-15s %-30s %-8s %-8s %-6s %-5s %-5s" % (
        "IMSI", "MSISDN", "APN (static ip)", "STATUS", "BARRING", "ACCESS",
        "NAM", "TAU"))
    for d in subs:
        imsi = d.get("imsi", "?")
        ms = ""
        if d.get("msisdn"):
            ms = bcd_to_msisdn(str(d["msisdn"][0]))
        apn = ""
        for sl in d.get("slice") or []:
            for se in sl.get("session") or []:
                ue = se.get("ue") or {}
                ip = ue.get("ipv4") or ue.get("ipv6") or ""
                apn += se.get("name", "?") + ("/%s" % ip if ip else "") + " "
        print("%-15s %-15s %-30s %-8s %-8s %-6s %-5s %-5s" % (
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
    backup_doc(backup, imsi, d, "pre-delete")
    r = stack.dbctl("remove", imsi)
    if r.returncode != 0:
        die("remove failed:\n" + (r.stdout or r.stderr).strip())
    if fetch(stack, imsi) is not None:
        die("subscriber %s still present after remove" % imsi)
    print("%s: deleted%s" % (imsi, " (backup: %s)" % backup if backup
                             else ""))


def cmd_revoke(stack, imsi, barring, dry, backup):
    row = {"imsi": imsi, "status": "barring"}
    if barring:
        row["barring"] = barring
    _single(stack, row, dry, backup, verb="revoked")


def cmd_purge(stack, imsi, dry, backup):
    _single(stack, {"imsi": imsi, "purge": "true"}, dry, backup)


def _single(stack, row, dry, backup, verb="updated"):
    try:
        ops = ops_from_row(row, "cli")
        current = fetch(stack, imsi := ops.imsi)
        validate_plan(ops, current)
    except RowError as e:
        die(str(e))
    res = apply_plan(stack, ops, dry=dry, backup=backup)
    if verb and res in ("updated", "nochange") and not dry:
        print("%s: %s" % (ops.imsi, verb))
    return res


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
def row_from_cli(args):
    row = {"imsi": args.imsi}
    for attr in ("msisdn", "imeisv", "mme_host", "mme_realm", "apn",
                 "apn_type", "qos", "arp", "ambr_d", "ambr_u", "ipv4",
                 "ipv6", "ue_ambr_d", "ue_ambr_u", "ue_ambr",
                 "access_restriction", "nam", "status", "barring", "tau",
                 "sst", "sd"):
        v = getattr(args, attr.replace("-", "_"), None)
        if v is None:
            continue
        row[attr] = v          # "" allowed -> clears (CLEARABLE fields)
    if getattr(args, "purge", None):
        row["purge"] = "true"
    if args.security_k or args.security_opc:
        row["security"] = {"k": args.security_k or "",
                           "opc": args.security_opc or "",
                           "amf": args.security_amf or ""}
        row["security"] = {k: v for k, v in row["security"].items() if v}
    return row


def add_common(p):
    p.add_argument("--msisdn", help="MSISDN digits (stored as E.212 BCD); "
                                     "'' clears")
    p.add_argument("--imeisv", help="IMEISV (8-16 hex); '' clears")
    p.add_argument("--mme-host", help="MME host (S6a restriction); '' clears")
    p.add_argument("--mme-realm", help="MME realm; '' clears")
    p.add_argument("--apn", help="APN name: upserts this session in slice "
                                 "(sst, sd); other sessions are kept")
    p.add_argument("--apn-type", help="internet/default/ims/... or 1-6")
    p.add_argument("--qos", help="5G QoS id: 8 or 8,1,2 (pri,cap)")
    p.add_argument("--arp", help="arp name (best-effort/voice/...) or "
                                 "pri,cap,vuln")
    p.add_argument("--ambr-d", help="session AMBR downlink, e.g. 1G/500M")
    p.add_argument("--ambr-u", help="session AMBR uplink")
    p.add_argument("--ipv4", help="static IPv4 for the session, e.g. "
                                  "10.20.30.40; '' clears")
    p.add_argument("--ipv6", help="static IPv6 for the session, e.g. "
                                  "2001:db8::1/128; '' clears")
    p.add_argument("--sst", help="SST (default 1)")
    p.add_argument("--sd", help="SD, 6 hex digits (default ffffff)")
    p.add_argument("--ue-ambr-d", help="UE-AMBR downlink")
    p.add_argument("--ue-ambr-u", help="UE-AMBR uplink")
    p.add_argument("--ue-ambr", help="UE-AMBR both directions")
    p.add_argument("--access-restriction",
                   help="bitmask or flag names (comma-separated)")
    p.add_argument("--nam", help="packet/reserved/only-packet or 0-2")
    p.add_argument("--status", help="granted/barring or 0/1")
    p.add_argument("--barring",
                   help="operator-determined barring bitmask / names")
    p.add_argument("--tau", help="RAU/TAU timer (minutes, stack convention)")
    p.add_argument("--security-k", help="Ki, 32 hex (LOUD WARNING; "
                                         "prefer import-profiles.sh)")
    p.add_argument("--security-opc", help="OPc, 32 hex (with --security-k)")
    p.add_argument("--security-amf", help="AMF, 4 hex")
    p.add_argument("--purge", action="store_true",
                   help="set purge_flag (update only)")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--backup", action="store_true",
                   help="write a pre-change backup (contains plaintext "
                        "keys - treat as a secret)")


def cmd_delete_all(stack, dry, backup, yes):
    """Wipe ALL subscribers + sessions (guarded: --dry-run, --yes, --backup)."""
    subs = all_subs(stack)
    sessions = int(stack.mongo_eval(
        "db.sessions.countDocuments({})").strip() or "0")
    print("delete-all: subscribers=%d sessions=%d" % (len(subs), sessions))
    for d in subs[:40]:
        print("  - %s" % d.get("imsi", "?"))
    if len(subs) > 40:
        print("  ... and %d more" % (len(subs) - 40))
    print("collections to wipe: subscribers, sessions "
          "(sas_*/accounts/other collections are NOT touched)")
    if dry:
        print("dry-run: nothing deleted")
        return
    if not yes:
        die("refusing to delete without --yes (re-run with --yes to "
            "confirm the wipe)")
    if not subs and not sessions:
        print("nothing to delete (subscribers=0 sessions=0)")
        return
    if backup:
        for d in subs:
            backup_doc(backup, d.get("imsi"), d, "delete-all")
        print("backup written: %s (contains plaintext keys)" % backup)
    out1 = stack.mongo_eval("db.subscribers.deleteMany({})")
    out2 = stack.mongo_eval("db.sessions.deleteMany({})")
    def _deleted(out):
        m = re.search(r'deletedCount["\s:]+(\d+)', out)
        return m.group(1) if m else "?"
    left_s = stack.mongo_eval("db.subscribers.countDocuments({})").strip()
    left_e = stack.mongo_eval("db.sessions.countDocuments({})").strip()
    print("deleted: subscribers=%s sessions=%s (left: subscribers=%s "
          "sessions=%s)" % (_deleted(out1), _deleted(out2), left_s, left_e))
    print("NOTE: NF RAM contexts (AMF/SMF/UDM/HSS/MME) are NOT reset - to "
          "apply fully, restart the core: docker compose restart amf smf "
          "udm udr ausf hss mme")


def main():
    EPILOG = """
examples:
  show/list:
    profile-mgmt.py show 999990000000101          # профиль (ключи маскируются)
    profile-mgmt.py list                          # таблица: APN + статический IP
  single subscriber:
    profile-mgmt.py add 999990000000101 --security-k <32hex> --security-opc <32hex> \\
        --apn internet --qos 9 --ipv4 10.167.71.200
    profile-mgmt.py update 999990000000101 --msisdn 79990000000101
    profile-mgmt.py update 999990000000101 --apn voip --apn-type dedicated --qos 5
    profile-mgmt.py update 999990000000101 --apn internet --ipv4 ""   # снять стат. IP
    profile-mgmt.py revoke 999990000000101 --barring "all ps barred"  # заблокировать
    profile-mgmt.py purge 999990000000101
    profile-mgmt.py del 999990000000101
  bulk (KV file - only the fields that must change):
    profile-mgmt.py edit profiles.kv --dry-run    # только валидация
    profile-mgmt.py edit profiles.kv             # применение
    profile-mgmt.py edit profiles.kv --backup    # бэкап перед изменением (с ключами!)
  wipe (ALL subscribers + sessions):
    profile-mgmt.py delete-all --dry-run         # что будет удалено
    profile-mgmt.py delete-all --yes             # стереть subscribers+sessions
    profile-mgmt.py delete-all --yes --backup    # сначала бэкап (с ключами!)
  restore from a backup file:
    profile-mgmt.py restore .deploy/backups/profile-mgmt-<ts>.json [imsi]

bulk file formats (auto-detected):
  KV (recommended): one line = one change packet:
        imsi=999990000000101, apn=internet, qos=9, ambr_d=500M, ipv4=10.167.71.200
    several lines with the same IMSI merge additively (later wins);
    empty VALUE clears the field (msisdn, imeisv, mme_host, mme_realm,
    ipv4, ipv6); values with commas in quotes: "arp=8,1,2"
  CSV: header row (first column 'imsi') + rows; empty cell = keep;
    clearing a field is not possible (use KV/JSON)
  JSON: list of objects; "" clears, null/absent keeps;
    "sessions":[...] = explicit FULL slice replace; session objects accept
    "ipv4"/"ipv6"

edit is two-phase: the whole file is validated BEFORE the first write
(any error -> nothing is written); --dry-run stops after validation.

sessions: a line/flag with apn= (or qos/arp/ambr_d/ambr_u/ipv4/ipv6) upserts
ONE session in slice (sst, sd) matched by APN name; other sessions/slices
are not touched. open5gs limits: 4 sessions per slice, 8 slices. The static
IP must be inside the SMF pool 10.167.71.192/24 (.deploy/docker/smf.yaml).

fields (add/update and bulk): msisdn, imeisv, mme_host, mme_realm,
apn, apn_type (internet|default|optimized|ims|dedicated|emergency|1-6),
qos (5QI 1-255 or "5QI,pri,cap"), arp (best-effort|voice|video|... or
"pri,cap,vuln"), ambr_d/ambr_u (1G|500M), ipv4 (a.b.c.d[/32]),
ipv6 (2001:db8::1[/128]), sst, sd (6 hex), ue_ambr[-d/-u],
access_restriction, nam (packet|reserved|only-packet),
status (granted|barring), barring, tau (minutes), purge,
security_k/security_opc (32 hex - LOUD WARNING; for keys prefer
import-profiles.sh EKI-TK), create.
Mask fields accept a bitmask or comma-separated flag names
(see --access-restriction / --barring help). Numbers are written as
BSON int32 (required by open5gs readers); pre_emption_capability is
validated to 1/2 (the UDR asserts on any other value).

safety:
  - show/list mask the security keys;
  - --backup is opt-in: the backup file contains PLAINTEXT keys
    (.deploy/backups/, chmod 600, gitignored) - treat as a secret;
  - unknown fields are rejected (fail-closed);
  - delete-all requires --yes and wipes subscribers+sessions only.

full reference: .deploy/profiles/README.md
"""
    ap = argparse.ArgumentParser(
        description="open5gs subscriber profile manager (AuC): ALL subscriber "
                    "parameters, several APN + static IP per APN, single and "
                    "bulk (KV/CSV/JSON) editing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=EPILOG)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("show", help="show one profile (keys masked)")
    p.add_argument("imsi")
    sub.add_parser("list", help="list subscribers (APN + static ip)")
    p = sub.add_parser("add", help="create a subscriber (dbctl base + "
                                   "fields); needs security k+opc")
    p.add_argument("imsi")
    add_common(p)
    p = sub.add_parser("update", help="update fields of an existing "
                                      "subscriber (never creates)")
    p.add_argument("imsi")
    add_common(p)
    p = sub.add_parser("edit", help="bulk apply a profile file "
                                    "(KV/CSV/JSON); two-phase, fail-closed")
    p.add_argument("file")
    p.add_argument("--dry-run", action="store_true",
                   help="validate only, write nothing")
    p.add_argument("--backup", action="store_true",
                   help="write a pre-change backup (contains plaintext "
                        "keys - treat as a secret)")
    p = sub.add_parser("del", help="delete a subscriber")
    p.add_argument("imsi")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--backup", action="store_true",
                   help="write a pre-change backup (contains plaintext "
                        "keys - treat as a secret)")
    p = sub.add_parser("revoke", help="revoke: subscriber_status=barring")
    p.add_argument("imsi")
    p.add_argument("--barring", help="barring flags (optional)")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--backup", action="store_true",
                   help="write a pre-change backup (contains plaintext "
                        "keys - treat as a secret)")
    p = sub.add_parser("purge", help="set purge_flag=true")
    p.add_argument("imsi")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--backup", action="store_true",
                   help="write a pre-change backup (contains plaintext "
                        "keys - treat as a secret)")
    p = sub.add_parser("delete-all",
                       help="wipe ALL subscribers + sessions (guarded: "
                            "--yes required)")
    p.add_argument("--dry-run", action="store_true",
                   help="list what would be deleted, write nothing")
    p.add_argument("--yes", action="store_true",
                   help="CONFIRM the wipe (required to delete)")
    p.add_argument("--backup", action="store_true",
                   help="write a full pre-delete backup (contains plaintext "
                        "keys - treat as a secret)")
    p = sub.add_parser("restore", help="restore from a profile-mgmt "
                                       "backup file")
    p.add_argument("backup")
    p.add_argument("imsi", nargs="?")
    p.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    stack = Stack().detect()
    dry = getattr(args, "dry_run", False)
    backup = backup_file() if (getattr(args, "backup", False) and not dry
                               and args.cmd not in ("show", "list", "restore")) else None
    if args.cmd == "show":
        cmd_show(stack, args.imsi)
    elif args.cmd == "list":
        cmd_list(stack)
    elif args.cmd in ("add", "update"):
        row = row_from_cli(args)
        if args.cmd == "add":
            row["create"] = "true"
        _single(stack, row, dry, backup, verb="")
    elif args.cmd == "edit":
        cmd_edit(stack, args.file, dry, backup)
    elif args.cmd == "del":
        cmd_del(stack, args.imsi, dry, backup)
    elif args.cmd == "revoke":
        cmd_revoke(stack, args.imsi, args.barring, dry, backup)
    elif args.cmd == "purge":
        cmd_purge(stack, args.imsi, dry, backup)
    elif args.cmd == "delete-all":
        cmd_delete_all(stack, dry, backup, args.yes)
    elif args.cmd == "restore":
        restore(stack, args.backup, args.imsi, dry)
    if backup and not dry:
        print("NOTE: backup file %s contains plaintext keys; treat it as "
              "a secret (chmod 600 applied, dir is gitignored)" % backup)


if __name__ == "__main__":
    main()