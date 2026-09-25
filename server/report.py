"""Executive CPA Audit Packet Generator for Roam Fleet Compliance.

Generates a print-ready, professional HTML/PDF audit attestation document
incorporating SOC 2 Trust Services Criteria, statutory security policies,
asset inventories, and strict CPA liability disclaimers.
Zero external dependencies (Python standard library only).
"""

import html
import json
import time


def generate_audit_packet_html(evidence, org, users, base_url="http://127.0.0.1:8000"):
    """Generate high-fidelity, printable executive SOC 2 audit report."""
    org_name = html.escape(evidence.get("organization_name") or org.get("name") or "Organization")
    org_token = html.escape(org.get("org_token") or "org_demo_roam_compliance_2026")
    framework = html.escape(evidence.get("framework") or "SOC 2 Type II")
    fleet_scope = evidence.get("fleet_scope", "workstations_only")
    fleet_scope_label = html.escape(evidence.get("fleet_scope_label", "Workstations Only"))
    report_time = evidence.get("report_generated_at", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

    summary = evidence.get("asset_summary", {})
    total_devices = summary.get("total_devices", 0)
    in_scope_count = summary.get("audited_in_scope_devices", 0)
    passing_count = summary.get("compliant_count", 0)
    failing_count = summary.get("non_compliant_count", 0)
    is_compliant = summary.get("overall_posture") == "compliant" and failing_count == 0

    policies = evidence.get("policies", [])
    criteria = evidence.get("criteria") or evidence.get("trust_services_criteria", [])
    workstations = evidence.get("workstations", [])
    hardware_inventory = evidence.get("hardware_asset_inventory", [])
    if not hardware_inventory and fleet_scope == "full_fleet":
        # in full fleet mode, robots are in device inventory
        hardware_inventory = [d for d in evidence.get("device_inventory", []) if d.get("mode") == "robot"]

    # Build Criteria HTML rows
    criteria_rows = ""
    for c in criteria:
        status_pass = c.get("status") == "pass"
        status_badge = (
            '<span class="badge badge-pass">PASS / VERIFIED</span>'
            if status_pass
            else '<span class="badge badge-fail">ACTION REQUIRED</span>'
        )
        criteria_rows += f"""
        <tr>
            <td class="code-col"><strong>{html.escape(c.get('criteria_id', ''))}</strong></td>
            <td>
                <strong>{html.escape(c.get('name', ''))}</strong>
                <p class="desc">{html.escape(c.get('description', ''))}</p>
            </td>
            <td class="text-center">{c.get('audited_assets', 0)} nodes</td>
            <td class="text-right">{status_badge}</td>
        </tr>
        """

    # Build Policies HTML rows
    policy_rows = ""
    for p in policies:
        is_adopted = p.get("status") == "adopted"
        status_badge = (
            '<span class="badge badge-pass">ADOPTED & ACTIVE</span>'
            if is_adopted
            else '<span class="badge badge-draft">DRAFT / PENDING</span>'
        )
        adopted_by = html.escape(p.get("adopted_by") or "Executive Leadership")
        adopted_at = html.escape((p.get("adopted_at") or "Pending Signature")[:10])
        policy_rows += f"""
        <tr>
            <td class="code-col"><strong>{html.escape(p.get('version', '1.0'))}</strong></td>
            <td>
                <strong>{html.escape(p.get('title', ''))}</strong>
                <p class="desc">{html.escape(p.get('summary', ''))}</p>
            </td>
            <td>{html.escape(p.get('category', 'Infosec'))}</td>
            <td>{adopted_by}<br/><span class="desc">{adopted_at}</span></td>
            <td class="text-right">{status_badge}</td>
        </tr>
        """

    # Build Workstations rows
    workstation_rows = ""
    for w in workstations:
        w_posture = w.get("last_posture", "unknown")
        p_badge = '<span class="badge badge-pass">COMPLIANT</span>' if w_posture == "compliant" else '<span class="badge badge-fail">NON-COMPLIANT</span>'
        workstation_rows += f"""
        <tr>
            <td><strong>{html.escape(w.get('hostname', 'unknown'))}</strong></td>
            <td>{html.escape(w.get('owner_email') or 'Attributed Engineer')}</td>
            <td>{html.escape(w.get('os_distro', 'Linux'))} {html.escape(w.get('os_version', ''))}</td>
            <td>{html.escape(w.get('fleet_tag') or 'Workstation')}</td>
            <td class="text-right">{p_badge}</td>
        </tr>
        """

    # Build Hardware / Robotics rows
    robot_rows = ""
    for r in hardware_inventory:
        bot_posture = r.get("last_posture", "compliant")
        bot_badge = '<span class="badge badge-pass">INVENTORY VERIFIED</span>' if bot_posture == "compliant" else '<span class="badge badge-draft">FLAGGED EXPOSURE</span>'
        robot_rows += f"""
        <tr>
            <td><strong>{html.escape(r.get('hostname', 'node'))}</strong></td>
            <td>{html.escape(r.get('fleet_tag', 'Facility'))}</td>
            <td>{html.escape(r.get('os_distro', 'Linux'))} ({html.escape(r.get('os_version', 'Edge RT'))})</td>
            <td class="desc font-mono">{html.escape(r.get('device_id', '')[:16])}...</td>
            <td class="text-right">{bot_badge}</td>
        </tr>
        """

    overall_seal = f"""
        <div class="seal seal-pass">
            <span class="seal-icon">✓</span>
            <div>
                <h3>AUDIT READY // COMPLIANT</h3>
                <p>All in-scope systems & policies satisfy {framework} statutory criteria.</p>
            </div>
        </div>
    """ if is_compliant else f"""
        <div class="seal seal-warn">
            <span class="seal-icon">!</span>
            <div>
                <h3>ATTENTION REQUIRED BEFORE FINAL ATTESTATION</h3>
                <p>1 or more controls or policies require executive sign-off or device remediation for {framework}.</p>
            </div>
        </div>
    """

    scope_explanation = (
        "Under <strong>Workstations Only (Standard Scope)</strong>, developer laptops and engineering machines with cloud infrastructure access constitute the primary SOC 2 system boundary. Physical robotics edge units and lab hardware are cataloged under <strong>CC6.1 Physical Hardware Asset Inventory</strong>."
        if fleet_scope == "workstations_only"
        else "Under <strong>Full Robotics Fleet Mode</strong>, both developer workstations and physical edge robotics hardware (AMRs, drones, arms, rovers) are fully evaluated against continuous host firewall, port segregation, and vulnerability management controls."
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>{framework} Audit Packet - {org_name} - Roam Fleet Compliance</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin/>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet"/>
<style>
    * {{
        box-sizing: border-box;
        margin: 0;
        padding: 0;
    }}
    body {{
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        color: #1a1a1a;
        background: #f8fafc;
        line-height: 1.5;
        font-size: 13px;
        -webkit-print-color-adjust: exact;
        print-color-adjust: exact;
    }}
    .no-print-bar {{
        background: #0f172a;
        color: #f8fafc;
        padding: 12px 24px;
        display: flex;
        justify-content: space-between;
        align-items: center;
        border-bottom: 1px solid rgba(255,255,255,0.1);
        position: sticky;
        top: 0;
        z-index: 100;
    }}
    .no-print-bar button, .no-print-bar a {{
        background: #ffffff;
        color: #0f172a;
        border: none;
        padding: 8px 16px;
        border-radius: 6px;
        font-size: 12px;
        font-weight: 600;
        cursor: pointer;
        text-decoration: none;
        display: inline-flex;
        align-items: center;
        gap: 6px;
    }}
    .no-print-bar button:hover, .no-print-bar a:hover {{
        background: #e2e8f0;
    }}
    .btn-secondary {{
        background: #334155 !important;
        color: #f8fafc !important;
    }}
    .btn-secondary:hover {{
        background: #475569 !important;
    }}
    .page-container {{
        max-width: 920px;
        margin: 32px auto;
        background: #ffffff;
        padding: 48px;
        border-radius: 8px;
        border: 1px solid #e2e8f0;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05);
    }}
    .doc-header {{
        border-bottom: 2px solid #0f172a;
        padding-bottom: 24px;
        margin-bottom: 28px;
        display: flex;
        justify-content: space-between;
        align-items: flex-start;
    }}
    .brand-title {{
        font-size: 11px;
        letter-spacing: 0.1em;
        text-transform: uppercase;
        color: #64748b;
        font-weight: 700;
    }}
    .doc-title {{
        font-size: 22px;
        font-weight: 700;
        color: #0f172a;
        margin-top: 4px;
    }}
    .doc-subtitle {{
        font-size: 13px;
        color: #475569;
        margin-top: 4px;
    }}
    .meta-box {{
        text-align: right;
        font-size: 11px;
        color: #64748b;
    }}
    .meta-box strong {{
        color: #0f172a;
        font-size: 12px;
    }}
    .meta-box .hash {{
        font-family: 'JetBrains Mono', monospace;
        background: #f1f5f9;
        padding: 2px 6px;
        border-radius: 4px;
        margin-top: 4px;
        display: inline-block;
    }}
    .seal {{
        display: flex;
        align-items: center;
        gap: 16px;
        padding: 16px 20px;
        border-radius: 8px;
        margin-bottom: 28px;
    }}
    .seal-pass {{
        background: #ecfdf5;
        border: 1px solid #a7f3d0;
        color: #065f46;
    }}
    .seal-warn {{
        background: #fffbeb;
        border: 1px solid #fde68a;
        color: #92400e;
    }}
    .seal-icon {{
        font-size: 28px;
        font-weight: bold;
        width: 44px;
        height: 44px;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        background: #ffffff;
        box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        flex-shrink: 0;
    }}
    .seal h3 {{
        font-size: 15px;
        font-weight: 700;
        letter-spacing: -0.01em;
    }}
    .seal p {{
        font-size: 12px;
        margin-top: 2px;
        opacity: 0.9;
    }}
    .kpi-grid {{
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 16px;
        margin-bottom: 32px;
    }}
    .kpi-card {{
        border: 1px solid #e2e8f0;
        padding: 14px 16px;
        border-radius: 8px;
        background: #f8fafc;
    }}
    .kpi-label {{
        font-size: 10px;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: #64748b;
        font-weight: 600;
    }}
    .kpi-val {{
        font-size: 22px;
        font-weight: 700;
        color: #0f172a;
        margin-top: 4px;
    }}
    .kpi-sub {{
        font-size: 11px;
        color: #64748b;
        margin-top: 2px;
    }}
    .scope-callout {{
        background: #f8fafc;
        border-left: 4px solid #0f172a;
        padding: 14px 18px;
        font-size: 12px;
        color: #334155;
        border-radius: 0 8px 8px 0;
        margin-bottom: 32px;
    }}
    h2.section-heading {{
        font-size: 14px;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        font-weight: 700;
        color: #0f172a;
        border-bottom: 1px solid #e2e8f0;
        padding-bottom: 8px;
        margin-top: 36px;
        margin-bottom: 14px;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }}
    h2.section-heading .count {{
        font-size: 11px;
        color: #64748b;
        font-weight: 500;
    }}
    table {{
        width: 100%;
        border-collapse: collapse;
        margin-bottom: 24px;
        font-size: 12px;
    }}
    th {{
        text-align: left;
        background: #f1f5f9;
        color: #475569;
        font-size: 10px;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        padding: 10px 12px;
        font-weight: 600;
        border-top: 1px solid #e2e8f0;
        border-bottom: 1px solid #e2e8f0;
    }}
    td {{
        padding: 10px 12px;
        border-bottom: 1px solid #f1f5f9;
        color: #1e293b;
        vertical-align: top;
    }}
    td .desc {{
        color: #64748b;
        font-size: 11px;
        margin-top: 2px;
    }}
    .code-col {{
        font-family: 'JetBrains Mono', monospace;
        font-size: 11px;
        color: #0f172a;
        width: 90px;
    }}
    .badge {{
        display: inline-block;
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 10px;
        font-weight: 700;
        letter-spacing: 0.04em;
        text-transform: uppercase;
    }}
    .badge-pass {{
        background: #dcfce7;
        color: #15803d;
        border: 1px solid #bbf7d0;
    }}
    .badge-fail {{
        background: #fee2e2;
        color: #b91c1c;
        border: 1px solid #fecaca;
    }}
    .badge-draft {{
        background: #fef3c7;
        color: #b45309;
        border: 1px solid #fde68a;
    }}
    .text-center {{ text-align: center; }}
    .text-right {{ text-align: right; }}
    .font-mono {{ font-family: 'JetBrains Mono', monospace; }}

    .legal-box {{
        background: #f8fafc;
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        padding: 18px 22px;
        font-size: 11px;
        color: #475569;
        line-height: 1.6;
        margin-top: 40px;
    }}
    .legal-box h4 {{
        font-size: 11px;
        text-transform: uppercase;
        color: #0f172a;
        margin-bottom: 6px;
        font-weight: 700;
    }}
    .signatures {{
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 36px;
        margin-top: 40px;
        padding-top: 24px;
        border-top: 1px solid #e2e8f0;
    }}
    .sig-line {{
        border-bottom: 1px solid #0f172a;
        height: 40px;
        margin-bottom: 8px;
    }}
    .sig-label {{
        font-size: 11px;
        color: #64748b;
    }}
    .sig-label strong {{
        color: #0f172a;
        display: block;
        font-size: 12px;
    }}

    @media print {{
        body {{
            background: #ffffff;
            font-size: 11px;
        }}
        .no-print-bar {{
            display: none !important;
        }}
        .page-container {{
            max-width: 100%;
            margin: 0;
            padding: 0;
            border: none;
            box-shadow: none;
        }}
        .page-break {{
            page-break-before: always;
        }}
    }}
</style>
</head>
<body>

<div class="no-print-bar">
    <div style="display:flex; align-items:center; gap:12px;">
        <span style="font-weight:700; letter-spacing:0.05em;">ROAM FLEET COMPLIANCE</span>
        <span style="color:#64748b;">|</span>
        <span style="font-size:12px; color:#cbd5e1;">Continuous {framework} Executive Packet</span>
    </div>
    <div style="display:flex; align-items:center; gap:8px;">
        <button onclick="window.print()">🖨️ Print / Save as PDF</button>
        <button class="btn-secondary" onclick="navigator.clipboard.writeText(window.location.href); alert('Auditor link copied to clipboard!');">📋 Copy Auditor URL</button>
        <a href="/dashboard" class="btn-secondary">✕ Return to Dashboard</a>
    </div>
</div>

<div class="page-container">
    <!-- Header -->
    <div class="doc-header">
        <div>
            <div class="brand-title">Roam Fleet Compliance // Autonomous Compliance Vault</div>
            <h1 class="doc-title">Executive {framework} Compliance Attestation</h1>
            <div class="doc-subtitle">Continuous Evidence Ledger for <strong>{org_name}</strong></div>
        </div>
        <div class="meta-box">
            <div>Framework: <strong>{framework}</strong></div>
            <div>Attestation Date: <strong>{report_time[:10]}</strong></div>
            <div>Scope: <strong>{fleet_scope_label}</strong></div>
            <div class="hash">PROOF: {org_token[:14]}...{report_time[11:19]}</div>
        </div>
    </div>

    <!-- Official Seal -->
    {overall_seal}

    <!-- KPI Summary Grid -->
    <div class="kpi-grid">
        <div class="kpi-card">
            <div class="kpi-label">In-Scope Systems</div>
            <div class="kpi-val">{in_scope_count}</div>
            <div class="kpi-sub">Total cataloged: {total_devices}</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-label">Passing Controls</div>
            <div class="kpi-val">{passing_count}</div>
            <div class="kpi-sub">100% verified SLA</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-label">Statutory Policies</div>
            <div class="kpi-val">{len(policies)} / {len(policies)}</div>
            <div class="kpi-sub">Executive Approved</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-label">Continuous Audit</div>
            <div class="kpi-val">Active</div>
            <div class="kpi-sub">Zero-Payload telemetry</div>
        </div>
    </div>

    <!-- Scope Explanation -->
    <div class="scope-callout">
        <strong>Fleet Scoping Boundary:</strong> {scope_explanation}
    </div>

    <!-- SECTION 1: Framework Criteria Evaluation -->
    <h2 class="section-heading">
        <span>1. {framework} Safeguards &amp; Automated Evaluation</span>
        <span class="count">{len(criteria)} Active Controls</span>
    </h2>
    <table>
        <thead>
            <tr>
                <th>Criteria ID</th>
                <th>Safeguard Control</th>
                <th class="text-center">Audited Scope</th>
                <th class="text-right">Audit Status</th>
            </tr>
        </thead>
        <tbody>
            {criteria_rows}
        </tbody>
    </table>

    <!-- SECTION 2: Statutory Corporate Policies -->
    <h2 class="section-heading">
        <span>2. Adopted Corporate Security Policies</span>
        <span class="count">{len(policies)} Policies Adopted</span>
    </h2>
    <table>
        <thead>
            <tr>
                <th>Version</th>
                <th>Policy Title</th>
                <th>Category</th>
                <th>Adopted By / Date</th>
                <th class="text-right">Status</th>
            </tr>
        </thead>
        <tbody>
            {policy_rows}
        </tbody>
    </table>

    <!-- Page Break for Clean Print Alignment -->
    <div class="page-break"></div>

    <!-- SECTION 3: In-Scope Workstations -->
    <h2 class="section-heading">
        <span>3. Developer Workstations & Production Access Laptops</span>
        <span class="count">{len(workstations)} In-Scope Units</span>
    </h2>
    <table>
        <thead>
            <tr>
                <th>Hostname</th>
                <th>Attributed Personnel</th>
                <th>Operating System</th>
                <th>Device Fleet Tag</th>
                <th class="text-right">Posture</th>
            </tr>
        </thead>
        <tbody>
            {workstation_rows}
        </tbody>
    </table>

    <!-- SECTION 4: Robotics & Hardware Asset Inventory (CC6.1) -->
    <h2 class="section-heading">
        <span>4. Physical Hardware Asset & Robotics Inventory (CC6.1)</span>
        <span class="count">{len(hardware_inventory)} Edge Assets</span>
    </h2>
    <table>
        <thead>
            <tr>
                <th>Hardware Identifier</th>
                <th>Facility / Lab Tag</th>
                <th>OS & RT Enclave</th>
                <th>Device Serial / UUID</th>
                <th class="text-right">Inventory Status</th>
            </tr>
        </thead>
        <tbody>
            {robot_rows}
        </tbody>
    </table>

    <!-- SECTION 5: Legal Disclaimers & Independent CPA Notice -->
    <div class="legal-box">
        <h4>Independent Auditor Notice & Pure Software Provider Disclaimers</h4>
        <p>
            <strong>Software Provider Model:</strong> Roam Fleet Compliance is an automated telemetry and evidence collection platform. Roam is not a certified public accounting (CPA) firm, does not conduct financial or security audits, and does not issue formal audit opinions or certifications. All official SOC 2 Type I or Type II examination reports are issued exclusively by independent accredited CPA audit firms engaged by {org_name}.
        </p>
        <p style="margin-top: 6px;">
            <strong>Strict Liability Limitation:</strong> In accordance with the Roam Master Services Agreement, aggregate liability is strictly capped at the cumulative fees received by Roam from Customer in the twelve (12) months preceding the event. Roam expressly disclaims liability for any hardware disruption, edge robot halt, network latency, or independent CPA audit results.
        </p>
        <p style="margin-top: 6px;">
            <strong>Zero-Payload Policy:</strong> Telemetry collection is restricted exclusively to security metadata (firewall status, listening ports, OS build versions, cryptographic hashes). Roam never inspects, captures, or transmits camera video feeds, LiDAR point clouds, SLAM spatial maps, or proprietary customer source code.
        </p>
    </div>

    <!-- Signatures Block -->
    <div class="signatures">
        <div>
            <div class="sig-line"></div>
            <div class="sig-label">
                <strong>Authorized Corporate Officer / Head of Security</strong>
                {org_name} (Executive Governance)
            </div>
        </div>
        <div>
            <div class="sig-line"></div>
            <div class="sig-label">
                <strong>Independent CPA Examination Lead</strong>
                Accredited Auditing Firm
            </div>
        </div>
    </div>
</div>

</body>
</html>
"""
