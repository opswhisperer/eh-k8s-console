#!/usr/bin/env python3
"""Generate deploy/components/grafana/eh-k8s-console.json (Grafana dashboard for eh-k8s-console).

    python3 hack/dashboard.py
"""
import json, os

DS = {"type": "prometheus", "uid": "${datasource}"}
NS = 'namespace=~"$namespace"'
panels, pid = [], [0]

def nid():
    pid[0] += 1
    return pid[0]

def row(title, y):
    panels.append({"type": "row", "title": title, "id": nid(), "collapsed": False, "gridPos": {"h": 1, "w": 24, "x": 0, "y": y}, "panels": []})

def target(expr, legend="", instant=False, fmt="time_series"):
    t = {"datasource": DS, "expr": expr, "legendFormat": legend, "refId": chr(64 + len(expr) % 26 + 1)}
    if instant:
        t.update({"instant": True, "range": False, "format": fmt})
    return t

def stat(title, desc, exprs, x, y, unit="none", steps=None, text="value", overrides=None, w=4, decimals=None):
    p = {"type": "stat", "title": title, "description": desc, "id": nid(), "datasource": DS,
         "gridPos": {"h": 4, "w": w, "x": x, "y": y},
         "targets": [dict(target(e, l), refId=chr(65 + i)) for i, (e, l) in enumerate(exprs)],
         "options": {"reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
                     "colorMode": "background", "graphMode": "none", "justifyMode": "center", "textMode": text,
                     "orientation": "auto", "wideLayout": True},
         "fieldConfig": {"defaults": {"unit": unit, "color": {"mode": "thresholds"},
                                      "thresholds": {"mode": "absolute", "steps": steps or [{"color": "green", "value": None}]}},
                         "overrides": overrides or []}}
    if decimals is not None:
        p["fieldConfig"]["defaults"]["decimals"] = decimals
    panels.append(p)

def ts(title, desc, exprs, x, y, w=12, h=8, unit="none", stack=False, step=False, minv=None):
    custom = {"lineWidth": 2, "fillOpacity": 15 if stack else 0, "showPoints": "never",
              "stacking": {"mode": "normal" if stack else "none", "group": "A"},
              "lineInterpolation": "stepAfter" if step else "linear"}
    d = {"unit": unit, "custom": custom, "color": {"mode": "palette-classic"}}
    if minv is not None:
        d["min"] = minv
    panels.append({"type": "timeseries", "title": title, "description": desc, "id": nid(), "datasource": DS,
                   "gridPos": {"h": h, "w": w, "x": x, "y": y},
                   "targets": [dict(target(e, l), refId=chr(65 + i)) for i, (e, l) in enumerate(exprs)],
                   "options": {"legend": {"displayMode": "list", "placement": "bottom", "showLegend": True},
                               "tooltip": {"mode": "multi", "sort": "desc"}},
                   "fieldConfig": {"defaults": d, "overrides": []}})

def table(title, desc, expr, x, y, w=12, h=8, rename=None, hide=None, value_name="Value", unit="none", sort=None, order=None, decimals=None):
    # order: source column names left to right; long text belongs last so it gets the spare width.
    t = dict(target(expr, instant=True, fmt="table"), refId="A")
    org = {"excludeByName": {k: True for k in (hide or [])} | {"Time": True}, "renameByName": dict(rename or {}, Value=value_name),
           "indexByName": {k: i for i, k in enumerate(order or [])}}
    props = [{"id": "unit", "value": unit}] + ([{"id": "decimals", "value": decimals}] if decimals is not None else [])
    p = {"type": "table", "title": title, "description": desc, "id": nid(), "datasource": DS,
         "gridPos": {"h": h, "w": w, "x": x, "y": y}, "targets": [t],
         "transformations": [{"id": "organize", "options": org}],
         "options": {"showHeader": True, "cellHeight": "sm", "sortBy": sort or []},
         "fieldConfig": {"defaults": {"unit": "none", "custom": {"align": "auto", "cellOptions": {"type": "auto"}}},
                         "overrides": [{"matcher": {"id": "byName", "options": value_name}, "properties": props}]}}
    panels.append(p)

RED, ORANGE, GREEN = "red", "orange", "green"
row("Health", 0)
stat("Sensor certificate", "Current certificate state (see docs/certificates.md). OK and ROTATED_TRUSTED are healthy.",
     [(f"max by (state) (ehk_cert_state{{{NS}}} == 1)", "{{state}}")], 0, 1, text="name",
     overrides=[{"matcher": {"id": "byRegexp", "options": "BROKEN|SNI_MISMATCH|INVALID_BUNDLE"}, "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": RED}}]},
                {"matcher": {"id": "byRegexp", "options": "UNREACHABLE"}, "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": ORANGE}}]},
                {"matcher": {"id": "byRegexp", "options": "OK|ROTATED_TRUSTED"}, "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": GREEN}}]}])
stat("Sensor certificate expires in", "Time until the certificate the sensor presents expires.",
     [(f'min(ehk_cert_not_after_seconds{{source="live",role=~"leaf|self-signed",{NS}}}) - time()', "")], 4, 1, unit="dtdurations",
     steps=[{"color": RED, "value": None}, {"color": ORANGE, "value": 7 * 86400}, {"color": GREEN, "value": 21 * 86400}])
stat("Critical problems", "Critical findings in the last scan.", [(f'sum(ehk_findings{{severity="critical",{NS}}}) or vector(0)', "")], 8, 1,
     steps=[{"color": GREEN, "value": None}, {"color": RED, "value": 1}])
stat("Warnings", "Warning findings in the last scan.", [(f'sum(ehk_findings{{severity="warning",{NS}}}) or vector(0)', "")], 12, 1,
     steps=[{"color": GREEN, "value": None}, {"color": ORANGE, "value": 1}])
stat("Integration pods ready", "Ready pods across the integration's workloads, as a share of desired.",
     [(f"sum(ehk_workload_ready{{{NS}}}) / sum(ehk_workload_desired{{{NS}}})", "")], 16, 1, unit="percentunit", decimals=0,
     steps=[{"color": RED, "value": None}, {"color": ORANGE, "value": 0.5}, {"color": GREEN, "value": 1}])
stat("Last scan", "Time since the console's last completed scan.", [(f"time() - max(ehk_last_scan_timestamp_seconds{{{NS}}})", "")], 20, 1, unit="s",
     steps=[{"color": GREEN, "value": None}, {"color": ORANGE, "value": 900}, {"color": RED, "value": 1800}])

row("Workloads", 5)
ts("Ready pods by component", "Ready (solid) against desired pods for each integration workload.",
   [(f"sum by (component) (ehk_workload_ready{{{NS}}})", "{{component}} ready"), (f"sum by (component) (ehk_workload_desired{{{NS}}})", "{{component}} desired")], 0, 6, step=True, minv=0)
ts("Container restarts (per hour)", "Restarts of integration containers, by component.",
   [(f"sum by (component) (increase(ehk_pod_restarts{{{NS}}}[1h]))", "{{component}}")], 12, 6, minv=0)

row("Findings and logs", 14)
ts("Findings by severity", "Problems the console finds on each scan.", [(f"sum by (severity) (ehk_findings{{{NS}}})", "{{severity}}")], 0, 15, stack=True, step=True, minv=0)
table("Recurring errors (last scan window)", "Most frequent error and warning messages, ignore rules excluded.",
      f"topk(10, ehk_log_error_signatures{{{NS}}})", 12, 15, value_name="Count",
      hide=["__name__", "container", "endpoint", "instance", "job", "namespace", "pod", "service", "prometheus", "level"],
      rename={"component": "Component", "signature": "Message"}, sort=[{"displayName": "Count", "desc": True}],
      order=["Value", "component", "signature"])
table("Current findings", "Every finding in the last scan, by severity, source and code.",
      f"ehk_findings{{{NS}}}", 0, 23, w=24, h=7, value_name="Count",
      hide=["__name__", "container", "endpoint", "instance", "job", "namespace", "pod", "service", "prometheus"],
      rename={"severity": "Severity", "source": "Source", "code": "Code"}, sort=[{"displayName": "Severity", "desc": False}])

row("Sensor certificate", 30)
table("Certificate expiry", "Days left on every certificate in sensorCert (bundle) and presented by the sensor (live). The anchor column marks the bundle certificate that anchors trust.",
      f"(ehk_cert_not_after_seconds{{{NS}}} - time()) / 86400", 0, 31, w=14, value_name="Days left",
      hide=["__name__", "container", "endpoint", "instance", "job", "namespace", "pod", "service", "prometheus"],
      rename={"source": "Source", "role": "Role", "subject": "Subject", "fingerprint": "Fingerprint", "anchor": "Anchor"}, sort=[{"displayName": "Days left", "desc": False}],
      order=["Value", "source", "role", "anchor", "subject", "fingerprint"], decimals=1, h=9)
ts("Trust checks", "1 = yes. Trusted: sensorCert verifies the sensor. Public CA: the chain verifies against public roots. Leaf changed: the bundle pins a leaf that's no longer presented. Probe OK: the sensor's certificate could be read.",
   [(f"max(ehk_cert_trusted_by_bundle{{{NS}}})", "trusted by sensorCert"), (f"max(ehk_cert_public_ca{{{NS}}})", "public CA"),
    (f"max(ehk_cert_leaf_changed{{{NS}}})", "leaf changed"), (f"max(ehk_cert_probe_success{{{NS}}})", "probe OK")], 14, 31, w=10, h=9, step=True, minv=0)

dash = {
    "uid": "eh-k8s-console", "title": "ExtraHop Kubernetes integration (eh-k8s-console)",
    "description": "Health of the ExtraHop Kubernetes integration as seen by eh-k8s-console. Community project, not affiliated with ExtraHop Networks.",
    "tags": ["extrahop", "kubernetes", "eh-k8s-console"], "editable": True, "graphTooltip": 1,
    "time": {"from": "now-24h", "to": "now"}, "refresh": "1m", "schemaVersion": 41, "version": 1,
    "links": [{"title": "eh-k8s-console", "type": "link", "url": "https://github.com/opswhisperer/eh-k8s-console", "targetBlank": True, "icon": "doc"}],
    "templating": {"list": [
        {"name": "datasource", "label": "Data source", "type": "datasource", "query": "prometheus", "current": {}, "hide": 0, "refresh": 1},
        {"name": "namespace", "label": "Namespace", "type": "query", "datasource": DS, "query": {"query": "label_values(ehk_scan_success, namespace)", "refId": "ns"},
         "definition": "label_values(ehk_scan_success, namespace)", "refresh": 2, "includeAll": True, "multi": True, "allValue": ".*", "current": {}, "sort": 1, "hide": 0}]},
    "annotations": {"list": []},
    "panels": panels,
}
out = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "deploy", "components", "grafana", "eh-k8s-console.json")
with open(out, "w") as f:
    json.dump(dash, f, indent=2)
    f.write("\n")
print(f"wrote {out}: {len(panels)} panels")
