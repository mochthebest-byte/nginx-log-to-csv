#!/usr/bin/env python3
import argparse
import csv
import datetime as dt
import re
import sys
from pathlib import Path
from urllib.parse import urlparse, parse_qs

LOG_RE = re.compile(
    r'^'
    r'(?P<remote_addr>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<time_local>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<body_bytes_sent>\S+)\s+'
    r'"(?P<http_referer>[^"]*)"\s+'
    r'"(?P<http_user_agent>[^"]*)"\s+'
    r'(?P<request_length>\S+)\s+'
    r'(?P<request_time>\S+)\s+'
    r'\[(?P<upstream_name>[^\]]*)\]\s+'
    r'\[(?P<upstream_alternative>[^\]]*)\]\s+'
    r'(?P<upstream_addr>\S+)\s+'
    r'(?P<upstream_response_length>\S+)\s+'
    r'(?P<upstream_response_time>\S+)\s+'
    r'(?P<upstream_status>\S+)\s+'
    r'(?P<request_id>\S+)'
    r'$'
)

# Example: 26/Apr/2021:21:20:17 +0000
DT_FORMAT = "%d/%b/%Y:%H:%M:%S %z"

def parse_time(s: str) -> dt.datetime:
    return dt.datetime.strptime(s, DT_FORMAT)

def safe_int(s: str):
    if s == "-" or s == "":
        return None
    try:
        return int(s)
    except ValueError:
        return None

def safe_float(s: str):
    if s == "-" or s == "":
        return None
    try:
        return float(s)
    except ValueError:
        return None

def split_request(req: str):
    # "GET /path?x=1 HTTP/2.0"
    parts = req.split()
    method = parts[0] if len(parts) > 0 else ""
    uri = parts[1] if len(parts) > 1 else ""
    proto = parts[2] if len(parts) > 2 else ""
    path = uri
    query = ""
    if uri and "://" in uri:
        # sometimes absolute URL
        u = urlparse(uri)
        path = u.path
        query = u.query
    elif "?" in uri:
        path, query = uri.split("?", 1)
    return method, uri, path, query, proto

def row_matches_filters(row: dict, args) -> bool:
    if args.status and row["status"] not in args.status:
        return False
    if args.method and row["method"] not in args.method:
        return False
    if args.path_contains and args.path_contains not in (row["path"] or ""):
        return False
    if args.ip and row["remote_addr"] not in args.ip:
        return False
    if args.since:
        if row["time_utc"] and row["time_utc"] < args.since:
            return False
    if args.until:
        if row["time_utc"] and row["time_utc"] > args.until:
            return False
    return True

def parse_args():
    p = argparse.ArgumentParser(
        description="Parse nginx access log (ingress-style) and export to CSV."
    )
    p.add_argument("-i", "--input", required=True, help="Path to nginx log file")
    p.add_argument("-o", "--output", required=True, help="Path to output CSV file")

    # Filters (bonus)
    p.add_argument("--status", nargs="+", type=int, help="Keep only these HTTP statuses, e.g. --status 200 404")
    p.add_argument("--method", nargs="+", help="Keep only these methods, e.g. --method GET POST")
    p.add_argument("--path-contains", help="Keep only rows where path contains substring")
    p.add_argument("--ip", nargs="+", help="Keep only these client IPs")

    p.add_argument("--since", help="Start time (UTC) like 2021-04-26T21:20:00Z")
    p.add_argument("--until", help="End time (UTC) like 2021-04-26T21:30:00Z")

    p.add_argument("--sort-by", default="time_utc",
                   choices=["time_utc", "status", "request_time", "body_bytes_sent", "upstream_response_time"],
                   help="Sort output by column")
    p.add_argument("--desc", action="store_true", help="Sort descending")
    p.add_argument("--limit", type=int, help="Write only first N rows after filtering/sorting")

    p.add_argument("--strict", action="store_true",
                   help="Fail if any line doesn't match expected format")
    return p.parse_args()

def parse_iso_utc(s: str) -> dt.datetime:
    # Accept "Z" suffix
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    t = dt.datetime.fromisoformat(s)
    if t.tzinfo is None:
        t = t.replace(tzinfo=dt.timezone.utc)
    return t.astimezone(dt.timezone.utc)

def main():
    args = parse_args()

    if args.since:
        args.since = parse_iso_utc(args.since)
    if args.until:
        args.until = parse_iso_utc(args.until)

    in_path = Path(args.input)
    out_path = Path(args.output)
    if not in_path.exists():
        print(f"ERROR: input not found: {in_path}", file=sys.stderr)
        sys.exit(2)

    rows = []
    bad_lines = 0

    with in_path.open("r", encoding="utf-8", errors="replace") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.rstrip("\n")
            if not line.strip():
                continue

            m = LOG_RE.match(line)
            if not m:
                bad_lines += 1
                if args.strict:
                    print(f"ERROR: line {line_no} does not match format:\n{line}", file=sys.stderr)
                    sys.exit(3)
                continue

            g = m.groupdict()
            method, uri, path, query, proto = split_request(g["request"])

            # time normalization
            t_local = parse_time(g["time_local"])
            t_utc = t_local.astimezone(dt.timezone.utc)

            # parse query keys count (bonus field)
            query_keys = []
            if query:
                try:
                    query_keys = list(parse_qs(query).keys())
                except Exception:
                    query_keys = []
            row = {
                "remote_addr": g["remote_addr"],
                "time_local": g["time_local"],
                "time_utc": t_utc.isoformat().replace("+00:00", "Z"),
                "method": method,
                "uri": uri,
                "path": path,
                "proto": proto,
                "status": safe_int(g["status"]),
                "body_bytes_sent": safe_int(g["body_bytes_sent"]),
                "http_referer": g["http_referer"],
                "http_user_agent": g["http_user_agent"],
                "request_length": safe_int(g["request_length"]),
                "request_time": safe_float(g["request_time"]),
                "upstream_name": g["upstream_name"],
                "upstream_alternative": g["upstream_alternative"],
                "upstream_addr": g["upstream_addr"],
                "upstream_response_length": safe_int(g["upstream_response_length"]),
                "upstream_response_time": safe_float(g["upstream_response_time"]),
                "upstream_status": safe_int(g["upstream_status"]) if g["upstream_status"].isdigit() else g["upstream_status"],
                "request_id": g["request_id"],
                "query_keys_count": len(query_keys),
            }

            # for filtering comparisons
            row["_time_dt"] = t_utc
            if row_matches_filters(
                {
                    **row,
                    "time_utc": row["_time_dt"],
                },
                args,
            ):
                rows.append(row)

    # sorting
    key_map = {
        "time_utc": lambda r: r["_time_dt"],
        "status": lambda r: (r["status"] if r["status"] is not None else -1),
        "request_time": lambda r: (r["request_time"] if r["request_time"] is not None else -1.0),
        "body_bytes_sent": lambda r: (r["body_bytes_sent"] if r["body_bytes_sent"] is not None else -1),
        "upstream_response_time": lambda r: (r["upstream_response_time"] if r["upstream_response_time"] is not None else -1.0),
    }
    rows.sort(key=key_map[args.sort_by], reverse=args.desc)

    if args.limit is not None:
        rows = rows[: args.limit]

    # write CSV
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "remote_addr",
        "time_local",
        "time_utc",
        "method",
        "uri",
        "path",
        "proto",
        "status",
        "body_bytes_sent",
        "http_referer",
        "http_user_agent",
        "request_length",
        "request_time",
        "upstream_name",
        "upstream_alternative",
        "upstream_addr",
        "upstream_response_length",
        "upstream_response_time",
        "upstream_status",
        "request_id",
        "query_keys_count",
    ]

    with out_path.open("w", newline="", encoding="utf-8") as out:
        w = csv.DictWriter(out, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            r2 = {k: r.get(k) for k in fieldnames}
            w.writerow(r2)

    print(f"OK: parsed={len(rows)} rows, skipped_bad_lines={bad_lines}, output={out_path}")

if __name__ == "__main__":
    main()
