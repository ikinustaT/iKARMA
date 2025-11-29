"""
iKARMA HTML Report Generator

Generates comprehensive, searchable HTML reports for forensic analysis.
"""

from typing import List, Dict, Any
from datetime import datetime
from pathlib import Path
import json


class HTMLReportGenerator:
    """Generate comprehensive HTML forensic reports."""

    def __init__(self, result):
        """Initialize with analysis result."""
        self.result = result

    def generate(self, output_path: str):
        """Generate complete HTML report."""
        html = self._build_html()

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)

    def _build_html(self) -> str:
        """Build complete HTML document."""
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>iKARMA Forensic Analysis Report</title>
    <style>
        {self._get_css()}
    </style>
</head>
<body>
    <div class="container">
        {self._build_header()}
        {self._build_summary()}
        {self._build_statistics()}
        {self._build_critical_findings()}
        {self._build_byovd_findings()}
        {self._build_search_filter()}
        {self._build_drivers_table()}
        {self._build_footer()}
    </div>
    <script>
        {self._get_javascript()}
    </script>
</body>
</html>"""

    def _get_css(self) -> str:
        """Get CSS styles."""
        return """
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: #333;
            padding: 20px;
            line-height: 1.6;
        }

        .container {
            max-width: 1600px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
            overflow: hidden;
        }

        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }

        .header h1 {
            font-size: 3em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }

        .header .subtitle {
            font-size: 1.2em;
            opacity: 0.9;
        }

        .section {
            padding: 30px 40px;
            border-bottom: 2px solid #f0f0f0;
        }

        .section h2 {
            color: #667eea;
            margin-bottom: 20px;
            font-size: 2em;
            border-left: 5px solid #667eea;
            padding-left: 15px;
        }

        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }

        .summary-card {
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }

        .summary-card h3 {
            color: #667eea;
            margin-bottom: 10px;
            font-size: 1.1em;
        }

        .summary-card .value {
            font-size: 2em;
            font-weight: bold;
            color: #333;
        }

        .stat-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }

        .stat-box {
            background: white;
            padding: 20px;
            border-radius: 8px;
            border-left: 5px solid #667eea;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            text-align: center;
        }

        .stat-box.critical {
            border-left-color: #e74c3c;
            background: #ffebee;
        }

        .stat-box.high {
            border-left-color: #ff9800;
            background: #fff3e0;
        }

        .stat-box.warning {
            border-left-color: #ffc107;
            background: #fffde7;
        }

        .stat-box.info {
            border-left-color: #2196f3;
            background: #e3f2fd;
        }

        .stat-box .label {
            font-size: 0.9em;
            color: #666;
            margin-bottom: 10px;
        }

        .stat-box .value {
            font-size: 2.5em;
            font-weight: bold;
        }

        .alert {
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
            border-left: 5px solid;
        }

        .alert.critical {
            background: #ffebee;
            border-color: #c62828;
            color: #c62828;
        }

        .alert.warning {
            background: #fff3e0;
            border-color: #f57c00;
            color: #e65100;
        }

        .alert h3 {
            margin-bottom: 15px;
            font-size: 1.5em;
        }

        .alert ul {
            list-style: none;
            padding-left: 0;
        }

        .alert li {
            padding: 8px 0;
            border-bottom: 1px solid rgba(0,0,0,0.1);
        }

        .search-filter {
            background: #f5f7fa;
            padding: 25px;
            border-radius: 8px;
            margin: 20px 0;
        }

        .filter-row {
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            align-items: center;
        }

        .search-box {
            flex: 1;
            min-width: 300px;
        }

        .search-box input {
            width: 100%;
            padding: 12px 20px;
            border: 2px solid #ddd;
            border-radius: 25px;
            font-size: 1em;
            transition: all 0.3s;
        }

        .search-box input:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 10px rgba(102, 126, 234, 0.3);
        }

        .filter-buttons {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }

        .filter-btn {
            padding: 10px 20px;
            border: 2px solid #ddd;
            background: white;
            border-radius: 20px;
            cursor: pointer;
            transition: all 0.3s;
            font-size: 0.9em;
        }

        .filter-btn:hover {
            background: #f0f0f0;
        }

        .filter-btn.active {
            background: #667eea;
            color: white;
            border-color: #667eea;
        }

        .drivers-table-container {
            overflow-x: auto;
            margin: 20px 0;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }

        table {
            width: 100%;
            border-collapse: collapse;
            background: white;
        }

        thead {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }

        th {
            padding: 15px 12px;
            text-align: left;
            font-weight: 600;
            cursor: pointer;
            user-select: none;
            position: sticky;
            top: 0;
            z-index: 10;
        }

        th:hover {
            background: rgba(255,255,255,0.1);
        }

        th .sort-icon {
            margin-left: 5px;
            font-size: 0.8em;
        }

        tbody tr {
            border-bottom: 1px solid #f0f0f0;
            transition: all 0.2s;
        }

        tbody tr:hover {
            background: #f8f9fa;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }

        tbody tr.hidden {
            display: none;
        }

        td {
            padding: 15px 12px;
            vertical-align: top;
        }

        .driver-name {
            font-weight: 600;
            color: #333;
        }

        .risk-badge {
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: 600;
            font-size: 0.9em;
            text-transform: uppercase;
        }

        .risk-critical {
            background: #e74c3c;
            color: white;
        }

        .risk-high {
            background: #ff9800;
            color: white;
        }

        .risk-medium {
            background: #ffc107;
            color: #333;
        }

        .risk-low {
            background: #4caf50;
            color: white;
        }

        .capability-tag,
        .indicator-tag {
            display: inline-block;
            padding: 4px 10px;
            margin: 2px;
            border-radius: 12px;
            font-size: 0.85em;
            background: #e3f2fd;
            color: #1976d2;
        }

        .indicator-tag {
            background: #ffebee;
            color: #c62828;
        }

        .address {
            font-family: 'Courier New', monospace;
            color: #666;
            font-size: 0.9em;
        }

        .expandable {
            cursor: pointer;
            color: #667eea;
            text-decoration: underline;
        }

        .expandable:hover {
            color: #764ba2;
        }

        .details {
            display: none;
            margin-top: 10px;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 5px;
            border-left: 3px solid #667eea;
        }

        .details.visible {
            display: block;
        }

        .footer {
            background: #2c3e50;
            color: white;
            padding: 30px 40px;
            text-align: center;
        }

        .footer p {
            margin: 5px 0;
        }

        .pagination {
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 10px;
            margin: 20px 0;
            flex-wrap: wrap;
        }

        .pagination button {
            padding: 10px 16px;
            border: 2px solid #667eea;
            background: white;
            color: #667eea;
            border-radius: 5px;
            cursor: pointer;
            transition: all 0.3s;
            font-weight: 600;
            min-width: 45px;
        }

        .pagination button:hover:not(:disabled) {
            background: #667eea;
            color: white;
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(102, 126, 234, 0.3);
        }

        .pagination button.active {
            background: #667eea;
            color: white;
        }

        .pagination button:disabled {
            opacity: 0.5;
            cursor: not-allowed;
            background: #f0f0f0;
            border-color: #ddd;
            color: #999;
        }

        .pagination .page-info {
            padding: 10px 20px;
            background: #f5f7fa;
            border-radius: 5px;
            font-weight: 600;
            color: #667eea;
        }

        tbody tr.page-hidden {
            display: none !important;
        }

        @media print {
            body {
                background: white;
                padding: 0;
            }

            .search-filter,
            .pagination,
            .filter-buttons {
                display: none;
            }

            .container {
                box-shadow: none;
            }
        }
        """

    def _build_header(self) -> str:
        """Build report header."""
        return f"""
        <div class="header">
            <h1>iKARMA</h1>
            <div class="subtitle">Kernel Driver Analysis - Forensic Report</div>
            <div class="subtitle" style="margin-top: 10px; font-size: 1em;">
                Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            </div>
        </div>
        """

    def _build_summary(self) -> str:
        """Build summary section."""
        return f"""
        <div class="section">
            <h2>Analysis Summary</h2>
            <div class="summary-grid">
                <div class="summary-card">
                    <h3>Memory Image</h3>
                    <p><strong>Path:</strong> {self.result.memory_image_path}</p>
                    <p><strong>Size:</strong> {self.result.memory_image_size / (1024*1024):.1f} MB</p>
                    <p><strong>Hash:</strong> <span class="address">{self.result.memory_image_hash[:32]}...</span></p>
                </div>
                <div class="summary-card">
                    <h3>Analysis Details</h3>
                    <p><strong>Duration:</strong> {self.result.analysis_duration_seconds:.1f} seconds</p>
                    <p><strong>Volatility3:</strong> {'Available' if self.result.volatility_available else 'Not Available'}</p>
                    <p><strong>Started:</strong> {self.result.analysis_start_time.strftime('%Y-%m-%d %H:%M:%S')}</p>
                </div>
            </div>
        </div>
        """

    def _build_statistics(self) -> str:
        """Build statistics section."""
        return f"""
        <div class="section">
            <h2>Driver Statistics</h2>
            <div class="stat-grid">
                <div class="stat-box info">
                    <div class="label">Total Drivers</div>
                    <div class="value">{self.result.total_drivers_analyzed}</div>
                </div>
                <div class="stat-box critical">
                    <div class="label">High Risk Drivers</div>
                    <div class="value">{self.result.high_risk_drivers}</div>
                </div>
                <div class="stat-box warning">
                    <div class="label">Anti-Forensic Indicators</div>
                    <div class="value">{self.result.drivers_with_antiforensic}</div>
                </div>
                <div class="stat-box critical">
                    <div class="label">Hooked Drivers</div>
                    <div class="value">{self.result.drivers_with_hooks}</div>
                </div>
                <div class="stat-box critical">
                    <div class="label">Hidden Drivers (DKOM)</div>
                    <div class="value">{self.result.hidden_drivers_detected}</div>
                </div>
                <div class="stat-box warning">
                    <div class="label">Remnant Drivers</div>
                    <div class="value">{self.result.remnant_drivers_detected}</div>
                </div>
            </div>
        </div>
        """

    def _build_critical_findings(self) -> str:
        """Build critical findings section."""
        findings_html = """
        <div class="section">
            <h2>Critical Findings</h2>
        """

        # Hidden drivers
        if self.result.hidden_drivers_detected > 0:
            findings_html += """
            <div class="alert critical">
                <h3>⚠ DKOM Attack Detected - Hidden Drivers Found</h3>
                <p><strong>Description:</strong> These drivers were found via pool scanning but are NOT in the PsLoadedModuleList. This indicates Direct Kernel Object Manipulation (DKOM), a rootkit technique.</p>
                <ul>
            """
            for driver in self.result.cross_view_result.hidden_drivers:
                findings_html += f"""
                <li>
                    <strong>{driver.name}</strong> @ <span class="address">{hex(driver.base_address)}</span>
                    - Risk Score: <strong>{driver.risk_score:.1f}</strong>
                </li>
                """
            findings_html += "</ul></div>"

        # Hooked drivers
        hooked_drivers = [d for d in self.result.drivers if any(mf.is_hooked for mf in d.major_function_info)]
        if hooked_drivers:
            findings_html += """
            <div class="alert critical">
                <h3>⚠ Hooked MajorFunctions Detected</h3>
                <p><strong>Description:</strong> These drivers have MajorFunction handlers pointing outside their code sections, indicating hooks or inline patching.</p>
                <ul>
            """
            for driver in hooked_drivers:
                hooked_funcs = [mf for mf in driver.major_function_info if mf.is_hooked]
                func_names = ', '.join([mf._get_name() for mf in hooked_funcs[:5]])
                findings_html += f"""
                <li>
                    <strong>{driver.name}</strong> - Hooked: {func_names}
                    {f'(+{len(hooked_funcs)-5} more)' if len(hooked_funcs) > 5 else ''}
                </li>
                """
            findings_html += "</ul></div>"

        # Known vulnerable drivers
        known_vulns = [d for d in self.result.drivers if d.is_known_vulnerable]
        if known_vulns:
            findings_html += """
            <div class="alert warning">
                <h3>⚠ Known Vulnerable Drivers (LOLDrivers)</h3>
                <p><strong>Description:</strong> These drivers are listed in the LOLDrivers database as having known vulnerabilities or being abused by attackers.</p>
                <ul>
            """
            for driver in known_vulns:
                cves = ', '.join(driver.known_cves[:3]) if driver.known_cves else 'No CVEs listed'
                findings_html += f"""
                <li>
                    <strong>{driver.name}</strong> - CVEs: {cves}
                    - Risk Score: <strong>{driver.risk_score:.1f}</strong>
                </li>
                """
            findings_html += "</ul></div>"

        if self.result.hidden_drivers_detected == 0 and not hooked_drivers and not known_vulns:
            findings_html += """
            <div class="alert" style="background: #e8f5e9; border-color: #4caf50; color: #2e7d32;">
                <h3>✓ No Critical Findings</h3>
                <p>No DKOM attacks, hooks, or known vulnerable drivers detected.</p>
            </div>
            """

        findings_html += "</div>"
        return findings_html

    def _build_byovd_findings(self) -> str:
        """Build BYOVD/Dangerous API findings section."""
        byovd_entries = []
        for driver in self.result.drivers:
            api_caps = [c.description for c in driver.capabilities if "Dangerous API" in c.description]
            if api_caps:
                byovd_entries.append((driver, api_caps))

        if not byovd_entries:
            return """
            <div class="section">
                <h2>BYOVD / Dangerous API Findings</h2>
                <div class="alert" style="background:#f5f5f5;border-color:#9e9e9e;color:#424242;">
                    <p>No BYOVD / Dangerous API findings detected.</p>
                </div>
            </div>
            """

        items_html = ""
        for driver, api_caps in byovd_entries:
            api_list = ', '.join(api_caps[:5])
            more = ""
            if len(api_caps) > 5:
                more = f" (+{len(api_caps)-5} more)"
            items_html += f"""
            <li>
                <strong>{driver.name}</strong> — {api_list}{more}
            </li>
            """

        return f"""
        <div class="section">
            <h2>BYOVD / Dangerous API Findings</h2>
            <div class="alert" style="background:#e3f2fd;border-color:#2196f3;color:#0d47a1;">
                <p><strong>{len(byovd_entries)} driver(s)</strong> contained Dangerous API indicators (BYOVD IOCTL analysis).</p>
                <ul>
                    {items_html}
                </ul>
            </div>
        </div>
        """

    def _build_search_filter(self) -> str:
        """Build search and filter controls."""
        return """
        <div class="section">
            <h2>Driver Analysis</h2>
            <div class="search-filter">
                <div class="filter-row">
                    <div class="search-box">
                        <input type="text" id="searchInput" placeholder="🔍 Search drivers by name, address, capability, or indicator (searches all pages)...">
                    </div>
                </div>
                <div class="filter-row" style="margin-top: 15px;">
                    <strong>Filter by Risk:</strong>
                    <div class="filter-buttons">
                        <button class="filter-btn active" data-filter="all">All Drivers</button>
                        <button class="filter-btn" data-filter="critical">Critical</button>
                        <button class="filter-btn" data-filter="high">High</button>
                        <button class="filter-btn" data-filter="medium">Medium</button>
                        <button class="filter-btn" data-filter="low">Low</button>
                    </div>
                </div>
                <div class="filter-row" style="margin-top: 10px;">
                    <strong>Special:</strong>
                    <div class="filter-buttons">
                        <button class="filter-btn" data-filter="hidden">Hidden (DKOM)</button>
                        <button class="filter-btn" data-filter="hooked">Hooked</button>
                        <button class="filter-btn" data-filter="vulnerable">Known Vulnerable</button>
                        <button class="filter-btn" data-filter="antiforensic">Anti-Forensic</button>
                    </div>
                </div>
                <div style="margin-top: 15px; color: #666;">
                    <span id="resultCount"></span>
                </div>
            </div>

            <!-- Pagination Controls -->
            <div class="pagination" id="paginationTop">
                <button id="firstPage" onclick="goToPage(1)">&laquo; First</button>
                <button id="prevPage" onclick="previousPage()">&lsaquo; Previous</button>
                <span class="page-info" id="pageInfo">Page 1 of 1</span>
                <button id="nextPage" onclick="nextPage()">Next &rsaquo;</button>
                <button id="lastPage" onclick="goToLastPage()">Last &raquo;</button>
            </div>
        """

    def _build_drivers_table(self) -> str:
        """Build drivers table."""
        table_html = """
        <div class="drivers-table-container">
            <table id="driversTable">
                <thead>
                    <tr>
                        <th onclick="sortTable(0)">#<span class="sort-icon">⇅</span></th>
                        <th onclick="sortTable(1)">Driver Name<span class="sort-icon">⇅</span></th>
                        <th onclick="sortTable(2)">Risk Score<span class="sort-icon">⇅</span></th>
                        <th onclick="sortTable(3)">Category<span class="sort-icon">⇅</span></th>
                        <th onclick="sortTable(4)">Base Address<span class="sort-icon">⇅</span></th>
                        <th>Size</th>
                        <th>Capabilities</th>
                        <th>Anti-Forensic Indicators</th>
                        <th>Source</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
        """

        # Sort drivers by risk score
        sorted_drivers = sorted(self.result.drivers, key=lambda x: x.risk_score, reverse=True)

        for idx, driver in enumerate(sorted_drivers, 1):
            # Get unique capabilities
            unique_caps = list(set([c.capability_type.name for c in driver.capabilities]))
            caps_html = ''.join([f'<span class="capability-tag">{cap.replace("_", " ").title()}</span>'
                                for cap in unique_caps[:10]])
            if len(unique_caps) > 10:
                caps_html += f'<span class="capability-tag">+{len(unique_caps)-10} more</span>'

            # Get unique indicators
            unique_inds = list(set([i.indicator_type.name for i in driver.anti_forensic_indicators]))
            inds_html = ''.join([f'<span class="indicator-tag">{ind.replace("_", " ").title()}</span>'
                                for ind in unique_inds[:5]])
            if len(unique_inds) > 5:
                inds_html += f'<span class="indicator-tag">+{len(unique_inds)-5} more</span>'

            # Determine risk class
            if driver.risk_score >= 8.5:
                risk_class = "critical"
            elif driver.risk_score >= 7.0:
                risk_class = "high"
            elif driver.risk_score >= 5.0:
                risk_class = "medium"
            else:
                risk_class = "low"

            # Special flags
            is_hidden = driver in (self.result.cross_view_result.hidden_drivers if self.result.cross_view_result else [])
            is_hooked = any(mf.is_hooked for mf in driver.major_function_info)
            is_vulnerable = driver.is_known_vulnerable
            has_antiforensic = len(driver.anti_forensic_indicators) > 0

            special_classes = []
            if is_hidden:
                special_classes.append('dkom-hidden')
            if is_hooked:
                special_classes.append('hooked')
            if is_vulnerable:
                special_classes.append('vulnerable')
            if has_antiforensic:
                special_classes.append('has-antiforensic')

            # Build details section
            details_html = f"""
            <div class="details" id="details-{idx}">
                <p><strong>Full Path:</strong> {driver.driver_path or 'N/A'}</p>
                <p><strong>Entry Point:</strong> <span class="address">{hex(driver.entry_point) if driver.entry_point else 'N/A'}</span></p>
                <p><strong>PE Timestamp:</strong> {driver.pe_timestamp_datetime.strftime('%Y-%m-%d %H:%M:%S') if driver.pe_timestamp_datetime else 'N/A'}</p>
                <p><strong>MD5:</strong> <span class="address">{driver.md5_hash or 'N/A'}</span></p>
                <p><strong>SHA256:</strong> <span class="address">{driver.sha256_hash or 'N/A'}</span></p>
                <p><strong>Imphash:</strong> <span class="address">{driver.imphash or 'N/A'}</span></p>
            """

            # Add signature info
            if driver.signature_info:
                details_html += f"""
                <p><strong>Signed:</strong> {driver.signature_info.is_signed}</p>
                <p><strong>Signer:</strong> {driver.signature_info.signer_name or 'N/A'}</p>
                """

            # Add hook details
            if is_hooked:
                hooked_funcs = [mf for mf in driver.major_function_info if mf.is_hooked]
                details_html += f"<p><strong>Hooked Functions:</strong></p><ul>"
                for mf in hooked_funcs:
                    details_html += f"<li>{mf._get_name()} → <span class='address'>{hex(mf.hook_target)}</span></li>"
                details_html += "</ul>"

            # Add vulnerability details
            if is_vulnerable and driver.loldrivers_match:
                details_html += f"""
                <p><strong>LOLDrivers Info:</strong></p>
                <p>{driver.loldrivers_match.get('description', 'N/A')}</p>
                <p><strong>CVEs:</strong> {', '.join(driver.known_cves) if driver.known_cves else 'None'}</p>
                """

            details_html += "</div>"

            table_html += f"""
            <tr class="driver-row {risk_class} {' '.join(special_classes)}"
                data-risk="{risk_class}"
                data-name="{driver.name.lower()}"
                data-caps="{' '.join(unique_caps).lower()}"
                data-inds="{' '.join(unique_inds).lower()}">
                <td>{idx}</td>
                <td><span class="driver-name">{driver.name}</span></td>
                <td><span class="risk-badge risk-{risk_class}">{driver.risk_score:.1f}</span></td>
                <td>{driver.risk_category}</td>
                <td><span class="address">{hex(driver.base_address)}</span></td>
                <td>{driver.size or 0:,} bytes</td>
                <td>{caps_html if caps_html else 'None'}</td>
                <td>{inds_html if inds_html else 'None'}</td>
                <td>{driver.enumeration_source}</td>
                <td><span class="expandable" onclick="toggleDetails({idx})">View Details</span>
                    {details_html}
                </td>
            </tr>
            """

        table_html += """
                </tbody>
            </table>
        </div>

        <!-- Pagination Controls Bottom -->
        <div class="pagination" id="paginationBottom">
            <button onclick="goToPage(1)">&laquo; First</button>
            <button onclick="previousPage()">&lsaquo; Previous</button>
            <span class="page-info" id="pageInfoBottom">Page 1 of 1</span>
            <button onclick="nextPage()">Next &rsaquo;</button>
            <button onclick="goToLastPage()">Last &raquo;</button>
        </div>
        </div>
        """

        return table_html

    def _build_footer(self) -> str:
        """Build footer."""
        return f"""
        <div class="footer">
            <p><strong>iKARMA v2.0.1</strong> - Kernel Driver Analysis for Memory Forensics</p>
            <p>Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>© 2025 - For Digital Forensics and Incident Response</p>
        </div>
        """

    def _get_javascript(self) -> str:
        """Get JavaScript for interactivity."""
        return """
        // Toggle details
        function toggleDetails(id) {
            const details = document.getElementById('details-' + id);
            details.classList.toggle('visible');
        }

        // Pagination & Filtering System
        const searchInput = document.getElementById('searchInput');
        const table = document.getElementById('driversTable');
        const rows = table.getElementsByClassName('driver-row');
        const resultCount = document.getElementById('resultCount');
        const pageInfo = document.getElementById('pageInfo');
        const pageInfoBottom = document.getElementById('pageInfoBottom');

        const DRIVERS_PER_PAGE = 50;
        let currentPage = 1;
        let currentFilter = 'all';
        let filteredRows = [];

        searchInput.addEventListener('input', function() {
            currentPage = 1; // Reset to page 1 on search
            filterAndPaginate();
        });

        // Filter buttons
        const filterBtns = document.querySelectorAll('.filter-btn');
        filterBtns.forEach(btn => {
            btn.addEventListener('click', function() {
                filterBtns.forEach(b => b.classList.remove('active'));
                this.classList.add('active');
                currentFilter = this.getAttribute('data-filter');
                currentPage = 1; // Reset to page 1 on filter change
                filterAndPaginate();
            });
        });

        function filterAndPaginate() {
            const searchTerm = searchInput.value.toLowerCase();
            filteredRows = [];

            // First, apply filters to ALL rows (across all pages)
            for (let row of rows) {
                const name = row.getAttribute('data-name');
                const risk = row.getAttribute('data-risk');
                const caps = row.getAttribute('data-caps');
                const inds = row.getAttribute('data-inds');
                const text = row.textContent.toLowerCase();

                let matchesSearch = !searchTerm ||
                    name.includes(searchTerm) ||
                    text.includes(searchTerm) ||
                    caps.includes(searchTerm) ||
                    inds.includes(searchTerm);

                let matchesFilter = true;
                if (currentFilter === 'all') {
                    matchesFilter = true;
                } else if (currentFilter === 'critical' || currentFilter === 'high' ||
                           currentFilter === 'medium' || currentFilter === 'low') {
                    matchesFilter = risk === currentFilter;
                } else if (currentFilter === 'hidden') {
                    matchesFilter = row.classList.contains('dkom-hidden');
                } else if (currentFilter === 'hooked') {
                    matchesFilter = row.classList.contains('hooked');
                } else if (currentFilter === 'vulnerable') {
                    matchesFilter = row.classList.contains('vulnerable');
                } else if (currentFilter === 'antiforensic') {
                    matchesFilter = row.classList.contains('has-antiforensic');
                }

                if (matchesSearch && matchesFilter) {
                    row.classList.remove('hidden');
                    filteredRows.push(row);
                } else {
                    row.classList.add('hidden');
                }
            }

            // Now apply pagination to filtered rows
            applyPagination();
        }

        function applyPagination() {
            const totalPages = Math.ceil(filteredRows.length / DRIVERS_PER_PAGE);
            const startIndex = (currentPage - 1) * DRIVERS_PER_PAGE;
            const endIndex = startIndex + DRIVERS_PER_PAGE;

            // Hide all filtered rows first
            filteredRows.forEach(row => row.classList.add('page-hidden'));

            // Show only rows for current page
            for (let i = startIndex; i < endIndex && i < filteredRows.length; i++) {
                filteredRows[i].classList.remove('page-hidden');
            }

            // Update result count
            const showing = Math.min(filteredRows.length, endIndex) - startIndex;
            resultCount.textContent = `Showing ${startIndex + 1}-${startIndex + showing} of ${filteredRows.length} drivers`;

            // Update page info
            const pageText = `Page ${currentPage} of ${totalPages || 1}`;
            pageInfo.textContent = pageText;
            pageInfoBottom.textContent = pageText;

            // Update pagination buttons
            updatePaginationButtons(totalPages);
        }

        function updatePaginationButtons(totalPages) {
            const firstPageBtns = document.querySelectorAll('#firstPage, #paginationBottom button:nth-child(1)');
            const prevPageBtns = document.querySelectorAll('#prevPage, #paginationBottom button:nth-child(2)');
            const nextPageBtns = document.querySelectorAll('#nextPage, #paginationBottom button:nth-child(4)');
            const lastPageBtns = document.querySelectorAll('#lastPage, #paginationBottom button:nth-child(5)');

            // Disable/enable first and previous buttons
            firstPageBtns.forEach(btn => btn.disabled = currentPage === 1);
            prevPageBtns.forEach(btn => btn.disabled = currentPage === 1);

            // Disable/enable next and last buttons
            nextPageBtns.forEach(btn => btn.disabled = currentPage >= totalPages);
            lastPageBtns.forEach(btn => btn.disabled = currentPage >= totalPages);
        }

        function goToPage(page) {
            const totalPages = Math.ceil(filteredRows.length / DRIVERS_PER_PAGE);
            if (page >= 1 && page <= totalPages) {
                currentPage = page;
                applyPagination();
                scrollToTop();
            }
        }

        function previousPage() {
            if (currentPage > 1) {
                currentPage--;
                applyPagination();
                scrollToTop();
            }
        }

        function nextPage() {
            const totalPages = Math.ceil(filteredRows.length / DRIVERS_PER_PAGE);
            if (currentPage < totalPages) {
                currentPage++;
                applyPagination();
                scrollToTop();
            }
        }

        function goToLastPage() {
            const totalPages = Math.ceil(filteredRows.length / DRIVERS_PER_PAGE);
            if (totalPages > 0) {
                currentPage = totalPages;
                applyPagination();
                scrollToTop();
            }
        }

        function scrollToTop() {
            document.getElementById('paginationTop').scrollIntoView({ behavior: 'smooth', block: 'start' });
        }

        // Sort table
        let sortDirection = {};

        function sortTable(columnIndex) {
            const tbody = table.querySelector('tbody');
            const rowsArray = Array.from(rows);

            if (!sortDirection[columnIndex]) {
                sortDirection[columnIndex] = 'asc';
            } else {
                sortDirection[columnIndex] = sortDirection[columnIndex] === 'asc' ? 'desc' : 'asc';
            }

            rowsArray.sort((a, b) => {
                let aValue = a.children[columnIndex].textContent.trim();
                let bValue = b.children[columnIndex].textContent.trim();

                // Handle numeric sorting for risk score
                if (columnIndex === 2) {
                    aValue = parseFloat(aValue);
                    bValue = parseFloat(bValue);
                }

                if (sortDirection[columnIndex] === 'asc') {
                    return aValue > bValue ? 1 : -1;
                } else {
                    return aValue < bValue ? 1 : -1;
                }
            });

            rowsArray.forEach(row => tbody.appendChild(row));

            // Reapply filter and pagination after sorting
            filterAndPaginate();
        }

        // Initialize
        filterAndPaginate();
        """
