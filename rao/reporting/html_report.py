"""Generate professional HTML reports from mission results."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path

# N5 fix: import Environment explicitly to enable autoescape
from jinja2 import Environment, select_autoescape

from rao.config import settings
from rao.core.state import MissionState, Severity, SubdomainInfo

logger = logging.getLogger(__name__)

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RAO Report - {{ target }}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: #0a0e17;
            color: #c9d1d9;
            line-height: 1.6;
        }
        .container { max-width: 1100px; margin: 0 auto; padding: 2rem; }

        header {
            background: linear-gradient(135deg, #0d1117, #161b22);
            border-bottom: 2px solid #e74c3c;
            padding: 2rem;
            text-align: center;
        }
        header h1 { color: #e74c3c; font-size: 2rem; margin-bottom: 0.5rem; }
        header .meta { color: #8b949e; font-size: 0.9rem; }
        header .disclaimer {
            margin-top: 1rem; padding: 0.8rem;
            background: rgba(231, 76, 60, 0.1);
            border: 1px solid rgba(231, 76, 60, 0.3);
            border-radius: 6px; font-size: 0.85rem; color: #e74c3c;
        }

        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem; margin: 2rem 0;
        }
        .stat-card {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 1.5rem;
            text-align: center;
        }
        .stat-card .number { font-size: 2.5rem; font-weight: 700; }
        .stat-card .label { color: #8b949e; font-size: 0.85rem; text-transform: uppercase; }

        .severity-bar {
            display: flex; gap: 4px; margin: 2rem 0; height: 24px; border-radius: 4px;
            overflow: hidden;
        }
        .severity-bar .seg { transition: width 0.3s; }
        .seg-critical { background: #e74c3c; }
        .seg-high { background: #e67e22; }
        .seg-medium { background: #f1c40f; }
        .seg-low { background: #3498db; }
        .seg-info { background: #95a5a6; }

        section { margin: 2rem 0; }
        section h2 {
            color: #e74c3c;
            font-size: 1.4rem;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid #30363d;
        }

        .host-card {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            margin-bottom: 1rem;
            overflow: hidden;
        }
        .host-header {
            padding: 1rem 1.5rem;
            background: #1c2128;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .host-header h3 { color: #58a6ff; }
        .host-header .os { color: #8b949e; font-size: 0.85rem; }

        table {
            width: 100%; border-collapse: collapse;
        }
        th, td {
            padding: 0.6rem 1rem;
            text-align: left;
            border-bottom: 1px solid #21262d;
        }
        th { background: #1c2128; color: #8b949e; font-size: 0.8rem; text-transform: uppercase; }

        .finding-card {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            margin-bottom: 1rem;
            border-left: 4px solid;
        }
        .finding-card.critical { border-left-color: #e74c3c; }
        .finding-card.high { border-left-color: #e67e22; }
        .finding-card.medium { border-left-color: #f1c40f; }
        .finding-card.low { border-left-color: #3498db; }
        .finding-card.info { border-left-color: #95a5a6; }

        .finding-header {
            padding: 1rem 1.5rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .finding-header h3 { font-size: 1rem; color: #c9d1d9; }

        .badge {
            padding: 0.2rem 0.7rem;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        .badge-critical { background: rgba(231,76,60,0.2); color: #e74c3c; }
        .badge-high { background: rgba(230,126,34,0.2); color: #e67e22; }
        .badge-medium { background: rgba(241,196,15,0.2); color: #f1c40f; }
        .badge-low { background: rgba(52,152,219,0.2); color: #3498db; }
        .badge-info { background: rgba(149,165,166,0.2); color: #95a5a6; }

        .finding-body { padding: 0 1.5rem 1rem; }
        .finding-body p { margin-bottom: 0.5rem; font-size: 0.9rem; }
        .finding-body .label { color: #8b949e; font-weight: 600; }
        .cve-tag {
            display: inline-block; padding: 0.15rem 0.5rem;
            background: rgba(88,166,255,0.1);
            border: 1px solid rgba(88,166,255,0.3);
            border-radius: 4px;
            font-size: 0.8rem; color: #58a6ff;
            margin-right: 0.3rem;
        }

        .web-results { margin-top: 1rem; }
        .web-results .tag {
            display: inline-block; padding: 0.2rem 0.6rem;
            background: #1c2128; border: 1px solid #30363d;
            border-radius: 4px; font-size: 0.8rem; margin: 0.2rem;
        }

        .attack-plan {
            background: #161b22; border: 1px solid #30363d; border-radius: 8px;
            padding: 1.5rem; font-family: monospace; font-size: 0.85rem;
            white-space: pre-wrap; color: #a5f3a5;
        }

        .errors { background: rgba(231,76,60,0.05); border: 1px solid #30363d; border-radius: 8px; padding: 1rem; }
        .errors li { color: #8b949e; font-size: 0.85rem; margin-left: 1rem; }

        footer {
            text-align: center; padding: 2rem;
            color: #484f58; font-size: 0.8rem;
            border-top: 1px solid #21262d;
        }
    </style>
</head>
<body>
    <header>
        <h1>RAO-Framework</h1>
        <p class="meta">Mission Report | Target: <strong>{{ target }}</strong> | {{ timestamp }}</p>
        <div class="disclaimer">
            This report was generated during an authorized security assessment.
            All findings should be verified before remediation.
        </div>
    </header>

    <div class="container">
        <!-- Summary -->
        <div class="summary-grid">
            <div class="stat-card">
                <div class="number" style="color: #58a6ff;">{{ hosts|length }}</div>
                <div class="label">Hosts Discovered</div>
            </div>
            <div class="stat-card">
                <div class="number" style="color: #f1c40f;">{{ total_findings }}</div>
                <div class="label">Total Findings</div>
            </div>
            <div class="stat-card">
                <div class="number" style="color: #e74c3c;">{{ validated|length }}</div>
                <div class="label">Validated</div>
            </div>
            <div class="stat-card">
                <div class="number" style="color: #2ecc71;">{{ total_ports }}</div>
                <div class="label">Open Ports</div>
            </div>
        </div>

        <!-- Severity Distribution -->
        {% if validated %}
        <div class="severity-bar">
            {% for sev, count in severity_counts.items() %}
            {% if count > 0 %}
            <div class="seg seg-{{ sev }}" style="width: {{ (count / validated|length * 100)|round }}%;"
                 title="{{ sev|upper }}: {{ count }}"></div>
            {% endif %}
            {% endfor %}
        </div>
        {% endif %}

        <!-- Hosts -->
        <section>
            <h2>Discovered Hosts</h2>
            {% for host in hosts %}
            <div class="host-card">
                <div class="host-header">
                    <h3>{{ host.ip }}{% if host.hostname %} ({{ host.hostname }}){% endif %}</h3>
                    <span class="os">{{ host.os_guess or 'OS unknown' }}</span>
                </div>
                {% if host.ports %}
                <table>
                    <thead><tr><th>Port</th><th>Protocol</th><th>Service</th><th>Version</th></tr></thead>
                    <tbody>
                    {% for p in host.ports %}
                    <tr>
                        <td>{{ p.port }}</td>
                        <td>{{ p.protocol }}</td>
                        <td>{{ p.service }}</td>
                        <td>{{ p.version or '-' }}</td>
                    </tr>
                    {% endfor %}
                    </tbody>
                </table>
                {% endif %}
            </div>
            {% endfor %}
        </section>

        <!-- Web Scan Results -->
        {% if web_results %}
        <section>
            <h2>Web Scan Results</h2>
            {% for wr in web_results %}
            <div class="host-card">
                <div class="host-header">
                    <h3>{{ wr.url }}</h3>
                    <span class="os">HTTP {{ wr.status_code }}</span>
                </div>
                <div class="web-results" style="padding: 1rem 1.5rem;">
                    {% if wr.technologies %}
                    <p><span class="label">Technologies: </span>
                        {% for t in wr.technologies %}<span class="tag">{{ t }}</span>{% endfor %}
                    </p>
                    {% endif %}
                    {% if wr.missing_headers %}
                    <p style="margin-top: 0.8rem;"><span class="label">Missing Security Headers:</span></p>
                    <ul style="margin-left: 1rem;">
                    {% for mh in wr.missing_headers %}
                        <li style="font-size: 0.85rem;">{{ mh.header }} - {{ mh.description }}</li>
                    {% endfor %}
                    </ul>
                    {% endif %}
                    {% if wr.exposed_paths %}
                    <p style="margin-top: 0.8rem;"><span class="label">Exposed Paths:</span></p>
                    <ul style="margin-left: 1rem;">
                    {% for ep in wr.exposed_paths %}
                        <li style="font-size: 0.85rem;">{{ ep.path }} [{{ ep.status }}] ({{ ep.size }} bytes)</li>
                    {% endfor %}
                    </ul>
                    {% endif %}
                    {% if wr.cors_issues %}
                    <p style="margin-top: 0.8rem;"><span class="label">CORS Issues:</span></p>
                    <ul style="margin-left: 1rem;">
                    {% for ci in wr.cors_issues %}
                        <li style="font-size: 0.85rem; color: #e67e22;">{{ ci }}</li>
                    {% endfor %}
                    </ul>
                    {% endif %}
                    {% if wr.info_leaks %}
                    <p style="margin-top: 0.8rem;"><span class="label">Information Leakage:</span></p>
                    <ul style="margin-left: 1rem;">
                    {% for il in wr.info_leaks %}
                        <li style="font-size: 0.85rem; color: #f1c40f;">{{ il }}</li>
                    {% endfor %}
                    </ul>
                    {% endif %}
                </div>
            </div>
            {% endfor %}
        </section>
        {% endif %}

        <!-- Subdomains -->
        {% if subdomains %}
        <section>
            <h2>Discovered Subdomains ({{ subdomains|length }})</h2>
            <div class="host-card">
                <table>
                    <thead><tr><th>Subdomain</th><th>IP</th><th>Source</th></tr></thead>
                    <tbody>
                    {% for s in subdomains %}
                    <tr>
                        <td>{{ s.subdomain }}</td>
                        <td>{{ s.ip }}</td>
                        <td><span class="tag">{{ s.source }}</span></td>
                    </tr>
                    {% endfor %}
                    </tbody>
                </table>
            </div>
        </section>
        {% endif %}

        <!-- Findings -->
        {% if validated %}
        <section>
            <h2>Validated Findings</h2>
            {% for f in validated %}
            <div class="finding-card {{ f.severity.value }}">
                <div class="finding-header">
                    <h3>{{ f.title }}</h3>
                    <span class="badge badge-{{ f.severity.value }}">{{ f.severity.value|upper }}</span>
                </div>
                <div class="finding-body">
                    <p><span class="label">Host: </span>{{ f.host }}:{{ f.port if f.port is not none else 'N/A' }}</p>
                    <p><span class="label">Description: </span>{{ f.description }}</p>
                    <p><span class="label">Evidence: </span>{{ f.evidence }}</p>
                    {% if f.cve_ids %}
                    <p><span class="label">CVEs: </span>
                        {% for cve in f.cve_ids %}<span class="cve-tag">{{ cve }}</span>{% endfor %}
                    </p>
                    {% endif %}
                </div>
            </div>
            {% endfor %}
        </section>
        {% endif %}

        <!-- Attack Plan -->
        {% if attack_plan %}
        <section>
            <h2>Attack Plan</h2>
            <div class="attack-plan">{{ attack_plan }}</div>
        </section>
        {% endif %}

        <!-- Errors -->
        {% if errors %}
        <section>
            <h2>Errors</h2>
            <div class="errors">
                <ul>{% for e in errors %}<li>{{ e }}</li>{% endfor %}</ul>
            </div>
        </section>
        {% endif %}
    </div>

    <footer>
        Generated by RAO-Framework v{{ version }} | {{ timestamp }} | Authorized assessment only
    </footer>
</body>
</html>"""


def generate_html_report(
    mission: MissionState,
    web_results: list | None = None,
    subdomains: list | None = None,
) -> Path:
    """Render and save an HTML report.

    N5 fix: Jinja2 Environment with autoescape=True prevents XSS from
    mission data (target names, finding titles, CVE descriptions) being
    rendered as raw HTML in the browser.

    N6 fix: subdomains are converted to SubdomainInfo objects so the
    template accesses .subdomain / .ip / .source consistently regardless
    of whether raw dicts or SubdomainInfo objects are passed.

    N7 fix: version sourced from importlib.metadata.
    """
    output_dir = Path(settings.report_output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    file_ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe_target = mission.target.replace(".", "_").replace("/", "_")
    filepath = output_dir / f"rao_report_{safe_target}_{file_ts}.html"

    # N7 fix: version from importlib.metadata
    try:
        from importlib.metadata import version as _pkg_version
        _version = _pkg_version("rao-framework")
    except Exception:
        _version = "0.0.0-dev"

    severity_counts = {s.value: 0 for s in Severity}
    for f in mission.validated_findings:
        severity_counts[f.severity.value] += 1

    total_ports = sum(len(h.ports) for h in mission.hosts)

    # N6 fix: normalize subdomains to SubdomainInfo objects so template
    # accesses .subdomain / .ip / .source uniformly (dicts don't support
    # attribute access reliably across all Jinja2 versions).
    _subdomains: list[SubdomainInfo] = []
    for s in (subdomains or []):
        if isinstance(s, SubdomainInfo):
            _subdomains.append(s)
        elif isinstance(s, dict):
            _subdomains.append(SubdomainInfo(
                subdomain=s.get("subdomain", ""),
                ip=s.get("ip", ""),
                source=s.get("source", ""),
            ))

    # Prefer mission.subdomains if template list is empty
    if not _subdomains and mission.subdomains:
        _subdomains = mission.subdomains

    # N5 fix: autoescape=True — all {{ vars }} are HTML-escaped automatically.
    # This prevents XSS from target names, finding titles, CVE descriptions, etc.
    env = Environment(autoescape=select_autoescape(["html"]))
    template = env.from_string(HTML_TEMPLATE)

    html = template.render(
        target=mission.target,
        timestamp=timestamp,
        hosts=mission.hosts,
        total_findings=len(mission.findings),
        validated=mission.validated_findings,
        severity_counts=severity_counts,
        total_ports=total_ports,
        web_results=web_results or [],
        subdomains=_subdomains,
        attack_plan=mission.attack_plan or "",
        errors=mission.errors,
        version=_version,         # N7 fix
    )

    filepath.write_text(html, encoding="utf-8")
    logger.info("HTML report saved: %s", filepath)
    return filepath
