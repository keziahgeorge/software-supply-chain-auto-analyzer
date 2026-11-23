import json
import os
import html
from collections import defaultdict, Counter

# ============================================================
# SOFTWARE SUPPLY CHAIN GUARDIAN
# Interactive Dependency and Vulnerability Dashboard
#
# Required files inside output/:
#   dependencies.json
#   dependency_edges.json
#   remediation_priorities.json
#
# Run:
#   python graph_generator.py
#
# Generated:
#   output/security_dashboard.html
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "output")

DEPENDENCIES_FILE = os.path.join(OUTPUT_DIR, "dependencies.json")
EDGES_FILE = os.path.join(OUTPUT_DIR, "dependency_edges.json")
FINDINGS_FILE = os.path.join(OUTPUT_DIR, "remediation_priorities.json")
DASHBOARD_FILE = os.path.join(OUTPUT_DIR, "security_dashboard.html")

SEVERITY_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "UNKNOWN": 0
}

SEVERITY_COLORS = {
    "CRITICAL": "#e74c3c",
    "HIGH": "#e67e22",
    "MEDIUM": "#f1c40f",
    "LOW": "#2ecc71",
    "UNKNOWN": "#95a5a6"
}


# ============================================================
# 1. LOAD INPUT DATA
# ============================================================

def load_json(path):

    if not os.path.isfile(path):
        raise FileNotFoundError(
            f"Required file not found: {path}\n"
            "Make sure all JSON files are inside the output folder."
        )

    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def load_data():

    dependencies = load_json(DEPENDENCIES_FILE)
    edges = load_json(EDGES_FILE)
    findings_data = load_json(FINDINGS_FILE)

    if not isinstance(dependencies, list):
        raise ValueError("dependencies.json must contain a JSON array.")

    if not isinstance(edges, list):
        raise ValueError("dependency_edges.json must contain a JSON array.")

    if isinstance(findings_data, list):
        findings = findings_data

    elif isinstance(findings_data, dict):
        findings = findings_data.get("priorities", [])

    else:
        findings = []

    if not isinstance(findings, list):
        raise ValueError("The priorities field must contain a JSON array.")

    return dependencies, edges, findings


# ============================================================
# 2. VULNERABILITY LOOKUP
# ============================================================

def build_risk_lookup(findings):

    lookup = defaultdict(list)

    for finding in findings:

        package_id = finding.get("package_instance_id")

        if package_id is not None:
            lookup[str(package_id)].append(finding)

    return lookup


def get_package_severity(package_id, risk_lookup):

    package_findings = risk_lookup.get(str(package_id), [])

    if not package_findings:
        return "NONE"

    return max(
        (
            str(item.get("severity", "UNKNOWN")).upper()
            for item in package_findings
        ),
        key=lambda value: SEVERITY_ORDER.get(value, 0)
    )


# ============================================================
# 3. CREATE GRAPH NODES AND EDGES
# ============================================================

def make_package_node(package, risk_lookup):

    package_id = str(package.get("id", ""))
    name = str(package.get("name") or package_id or "Unknown package")

    severity = get_package_severity(package_id, risk_lookup)

    findings = risk_lookup.get(package_id, [])

    if severity == "NONE":
        background = "#2ecc71"
    else:
        background = SEVERITY_COLORS.get(severity, "#95a5a6")

    details = [
        f"Package: {name}",
        f"Version: {package.get('version', 'Unknown')}",
        f"Dependency type: {package.get('dependency_type', 'Unknown')}",
        f"Direct dependency: {'Yes' if package.get('is_direct') else 'No'}",
        f"Highest severity: {severity}",
        f"Vulnerability findings: {len(findings)}"
    ]

    if package.get("resolved"):
        details.append(f"Resolved: {package.get('resolved')}")

    return {
        "id": package_id,
        "label": name,
        "title": "<br>".join(
            html.escape(str(value)) for value in details
        ),
        "color": {
            "background": background,
            "border": background,
            "highlight": {
                "background": background,
                "border": "#172b4d"
            }
        },
        "size": 19 if package.get("is_direct") else 13,
        "font": {
            "size": 11,
            "face": "Arial",
            "color": "#263238"
        },
        "shape": "dot"
    }


def prepare_graph_data(dependencies, edges, risk_lookup):

    nodes = [{
        "id": "APPLICATION",
        "label": "APPLICATION",
        "title": "Root application",
        "color": {
            "background": "#3498db",
            "border": "#1f618d",
            "highlight": {
                "background": "#3498db",
                "border": "#172b4d"
            }
        },
        "size": 34,
        "font": {
            "size": 17,
            "face": "Arial",
            "color": "#ffffff",
            "bold": True
        },
        "shape": "dot"
    }]

    known_ids = {"APPLICATION"}

    for package in dependencies:

        package_id = package.get("id")

        if not package_id:
            continue

        package_id = str(package_id)

        if package_id not in known_ids:

            nodes.append(
                make_package_node(package, risk_lookup)
            )

            known_ids.add(package_id)

    graph_edges = []

    for index, edge in enumerate(edges):

        source = str(edge.get("source", ""))
        target = str(edge.get("target", ""))

        if not source or not target:
            continue

        if source not in known_ids or target not in known_ids:
            continue

        graph_edges.append({
            "id": f"edge_{index}",
            "from": source,
            "to": target,
            "arrows": "to",
            "color": {
                "color": "#9aa0a6",
                "opacity": 0.65,
                "highlight": "#1769aa"
            },
            "width": 1,
            "title": html.escape(
                str(edge.get("dependency_name", "dependency"))
            )
        })

    # Fallback: create APPLICATION edges for direct dependencies
    # if the input edge file does not contain them.

    has_application_edges = any(
        edge["from"] == "APPLICATION"
        for edge in graph_edges
    )

    if not has_application_edges:

        direct_ids = sorted({
            str(package.get("id"))
            for package in dependencies
            if package.get("id") and package.get("is_direct")
        })

        for index, package_id in enumerate(direct_ids):

            if package_id in known_ids:

                graph_edges.append({
                    "id": f"fallback_direct_{index}",
                    "from": "APPLICATION",
                    "to": package_id,
                    "arrows": "to",
                    "color": {
                        "color": "#9aa0a6",
                        "opacity": 0.65
                    },
                    "width": 1,
                    "title": "direct dependency"
                })

    return nodes, graph_edges


# ============================================================
# 4. VULNERABILITY TABLE DATA
# ============================================================

def build_vulnerability_rows(findings):

    rows = []

    for finding in findings:

        cve_ids = finding.get("cve_ids", [])

        if isinstance(cve_ids, list):
            cve_text = ", ".join(map(str, cve_ids))
        else:
            cve_text = str(cve_ids or "")

        rows.append({
            "package": finding.get("package_name", "Unknown"),
            "version": finding.get("installed_version", "Unknown"),
            "severity": str(
                finding.get("severity", "UNKNOWN")
            ).upper(),
            "cvss": finding.get("cvss_score", "N/A"),
            "cve": cve_text,
            "vulnerability": finding.get(
                "vulnerability_id", "N/A"
            ),
            "summary": finding.get(
                "summary", "No description available"
            ),
            "type": finding.get("dependency_type", "Unknown")
        })

    rows.sort(
        key=lambda row: SEVERITY_ORDER.get(row["severity"], 0),
        reverse=True
    )

    return rows


# ============================================================
# 5. GENERATE HTML DASHBOARD
# ============================================================

def build_dashboard(dependencies, edges, findings):

    risk_lookup = build_risk_lookup(findings)

    nodes, graph_edges = prepare_graph_data(
        dependencies,
        edges,
        risk_lookup
    )

    direct_count = sum(
        1 for package in dependencies
        if package.get("is_direct")
    )

    stats = {
        "packages": len(dependencies),
        "direct": direct_count,
        "transitive": max(0, len(dependencies) - direct_count),
        "edges": len(edges),
        "findings": len(findings),
        "vulnerable": len({
            str(item.get("package_instance_id"))
            for item in findings
            if item.get("package_instance_id") is not None
        })
    }

    severity_counts = Counter(
        str(item.get("severity", "UNKNOWN")).upper()
        for item in findings
    )

    vulnerability_rows = build_vulnerability_rows(findings)

    page = r'''<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">

<title>Software Supply Chain Guardian</title>

<script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

<style>

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    font-family: Arial, sans-serif;
    background: #f4f6f9;
    color: #263238;
}

header {
    background: #172b4d;
    color: white;
    padding: 22px 30px;
}

header h1 {
    margin: 0;
    font-size: 25px;
}

header p {
    margin: 7px 0 0;
    color: #cbd5e1;
}

nav {
    display: flex;
    gap: 8px;
    padding: 12px 25px;
    background: white;
    border-bottom: 1px solid #ddd;
    flex-wrap: wrap;
}

nav button {
    border: 0;
    background: #e9eef5;
    color: #263238;
    padding: 11px 18px;
    border-radius: 6px;
    cursor: pointer;
    font-size: 14px;
}

nav button.active {
    background: #1769aa;
    color: white;
}

section {
    display: none;
    padding: 24px;
}

section.active {
    display: block;
}

.section-title {
    margin: 0 0 20px;
}

.stats {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 15px;
    margin-bottom: 22px;
}

.stat-card {
    background: white;
    padding: 20px;
    border-radius: 9px;
    box-shadow: 0 2px 7px rgba(0,0,0,.06);
}

.stat-card h3 {
    margin: 0;
    color: #687787;
    font-size: 13px;
    font-weight: normal;
}

.stat-card p {
    margin: 10px 0 0;
    font-size: 27px;
    font-weight: bold;
}

.panel {
    background: white;
    padding: 20px;
    border-radius: 9px;
    box-shadow: 0 2px 7px rgba(0,0,0,.06);
    margin-bottom: 22px;
}

.panel h3 {
    margin-top: 0;
}

.graph {
    height: 680px;
    width: 100%;
    border: 1px solid #e5e7eb;
    border-radius: 7px;
    background: white;
}

.graph-large {
    height: 780px;
}

.graph-toolbar {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
    margin-bottom: 13px;
    align-items: center;
}

input, select {
    padding: 10px;
    border: 1px solid #cbd5e1;
    border-radius: 5px;
    font-size: 14px;
}

.graph-toolbar button {
    padding: 10px 14px;
    border: 0;
    background: #1769aa;
    color: white;
    border-radius: 5px;
    cursor: pointer;
}

.graph-toolbar button:hover {
    background: #12558c;
}

.legend {
    display: flex;
    gap: 18px;
    flex-wrap: wrap;
    margin: 12px 0;
    font-size: 13px;
}

.legend-item {
    display: flex;
    align-items: center;
    gap: 6px;
}

.dot {
    width: 11px;
    height: 11px;
    border-radius: 50%;
    display: inline-block;
}

.table-container {
    overflow: auto;
    max-height: 650px;
    border: 1px solid #e5e7eb;
    border-radius: 7px;
}

table {
    width: 100%;
    border-collapse: collapse;
    background: white;
    font-size: 13px;
}

th, td {
    padding: 12px;
    text-align: left;
    border-bottom: 1px solid #e5e7eb;
}

th {
    background: #eef2f7;
    position: sticky;
    top: 0;
}

.severity {
    display: inline-block;
    padding: 5px 9px;
    border-radius: 5px;
    font-weight: bold;
    font-size: 11px;
    color: white;
}

.CRITICAL {
    background: #e74c3c;
}

.HIGH {
    background: #e67e22;
}

.MEDIUM {
    background: #d4ac0d;
}

.LOW {
    background: #27ae60;
}

.UNKNOWN {
    background: #7f8c8d;
}

.small-note {
    color: #687787;
    font-size: 13px;
    line-height: 1.5;
}

.details {
    margin-top: 15px;
    padding: 14px;
    background: #f4f6f9;
    border-radius: 6px;
    overflow-wrap: anywhere;
    line-height: 1.5;
}

.details h3 {
    margin-top: 0;
}

.graph-help {
    display: flex;
    flex-wrap: wrap;
    gap: 10px 20px;
    margin: 15px 0;
    font-size: 13px;
}

.graph-help span {
    display: inline-flex;
    align-items: center;
    gap: 6px;
}

.indicator {
    display: inline-block;
    padding: 3px 7px;
    border-radius: 4px;
    font-weight: bold;
    color: white;
    background: #1769aa;
}

.leaf-indicator {
    background: #7f8c8d;
}

@media(max-width:700px) {

    section {
        padding: 14px;
    }

    .graph {
        height: 550px;
    }

}

</style>

</head>

<body>

<header>

    <h1>Software Supply Chain Guardian</h1>

    <p>
        Dependency Analysis and Vulnerability Monitoring Dashboard
    </p>

</header>


<nav>

    <button class="active"
        onclick="showSection('overview', this)">
        Overview
    </button>

    <button
        onclick="showSection('dependencies', this)">
        Application Dependency Graph
    </button>

    <button
        onclick="showSection('vulnerabilities', this)">
        Vulnerability Explorer
    </button>

</nav>


<!-- ======================================================
     OVERVIEW
====================================================== -->

<section id="overview" class="active">

    <h2 class="section-title">Security Overview</h2>

    <div class="stats" id="stats"></div>

    <div class="panel">

        <h3>Vulnerability Severity Distribution</h3>

        <div style="max-width:550px;height:300px">
            <canvas id="severityChart"></canvas>
        </div>

    </div>

</section>


<!-- ======================================================
     APPLICATION DEPENDENCY GRAPH
====================================================== -->

<section id="dependencies">

    <h2 class="section-title">Application Dependency Graph</h2>

    <div class="panel">

        <p class="small-note">
            The graph initially displays the application and its
            direct dependencies. Click a package to reveal its
            immediate dependencies. Use Show Full Graph to display
            the complete dependency structure.
        </p>

        <div class="graph-toolbar">

            <button onclick="showFullGraph()">
                Show Full Graph
            </button>

            <button onclick="resetFullGraph()">
                Reset View
            </button>

            <input
                type="text"
                id="nodeSearch"
                placeholder="Search package name..."
            >

            <button onclick="searchNode()">
                Find Package
            </button>

        </div>

        <div class="graph-help">

            <span>
                <span class="indicator">+ N</span>
                Click to expand
            </span>

            <span>
                <span class="indicator">- N</span>
                Click to collapse
            </span>

            <span>
                <span class="indicator leaf-indicator">LEAF</span>
                No further dependencies
            </span>

        </div>

        <div class="legend">

            <span class="legend-item">
                <span class="dot" style="background:#3498db"></span>
                Application
            </span>

            <span class="legend-item">
                <span class="dot" style="background:#2ecc71"></span>
                No matching finding
            </span>

            <span class="legend-item">
                <span class="dot" style="background:#e74c3c"></span>
                Critical
            </span>

            <span class="legend-item">
                <span class="dot" style="background:#e67e22"></span>
                High
            </span>

            <span class="legend-item">
                <span class="dot" style="background:#f1c40f"></span>
                Medium
            </span>

        </div>

        <div id="fullGraph" class="graph graph-large"></div>

        <div id="fullDetails"></div>

    </div>

</section>


<!-- ======================================================
     VULNERABILITY EXPLORER
====================================================== -->

<section id="vulnerabilities">

    <h2 class="section-title">Vulnerability Explorer</h2>

    <div class="panel">

        <div class="graph-toolbar">

            <input
                type="text"
                id="vulnerabilitySearch"
                placeholder="Search package, CVE, or vulnerability..."
                oninput="filterVulnerabilities()"
            >

            <select
                id="severityFilter"
                onchange="filterVulnerabilities()"
            >

                <option value="ALL">All severities</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
                <option value="UNKNOWN">Unknown</option>

            </select>

        </div>

        <p id="vulnerabilityCount" class="small-note"></p>

        <div class="table-container">

            <table>

                <thead>

                    <tr>
                        <th>Package</th>
                        <th>Version</th>
                        <th>Severity</th>
                        <th>CVSS</th>
                        <th>Vulnerability ID</th>
                        <th>CVE</th>
                        <th>Dependency Type</th>
                    </tr>

                </thead>

                <tbody id="vulnerabilityTable"></tbody>

            </table>

        </div>

    </div>

</section>


<script>

// ============================================================
// 6. DATA FROM PYTHON
// ============================================================

const ALL_NODES = __NODES__;
const ALL_EDGES = __EDGES__;
const VULNERABILITIES = __VULNERABILITIES__;
const STATS = __STATS__;
const SEVERITY_COUNTS = __SEVERITY_COUNTS__;


// Lookup package data by ID.
const nodeLookup = new Map(
    ALL_NODES.map(node => [String(node.id), node])
);


// ============================================================
// 7. COUNT IMMEDIATE DEPENDENCIES
// ============================================================

const childCount = new Map();

ALL_NODES.forEach(node => {
    childCount.set(String(node.id), 0);
});

ALL_EDGES.forEach(edge => {

    const parent = String(edge.from);

    childCount.set(
        parent,
        (childCount.get(parent) || 0) + 1
    );

});


// ============================================================
// 8. EXPANSION INDICATORS
// ============================================================

function getDisplayNode(node, expandedNodes) {

    const id = String(node.id);

    const count = childCount.get(id) || 0;

    let indicator = "";

    if (count === 0) {

        indicator = " [LEAF]";

    } else if (expandedNodes.has(id)) {

        indicator = ` [- ${count}]`;

    } else {

        indicator = ` [+ ${count}]`;

    }

    // The physics engine controls node positions.
    const displayNode = {
        ...node,
        label: node.label + indicator
    };

    delete displayNode.x;
    delete displayNode.y;
    delete displayNode.physics;

    return displayNode;

}


// ============================================================
// 9. NETWORK STATE
// ============================================================

let fullExpanded = new Set(["APPLICATION"]);

let fullNetwork = null;


// ============================================================
// 10. HELPER FUNCTIONS
// ============================================================

function escapeHtml(value) {

    return String(value ?? "").replace(/[&<>"']/g, char => ({

        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#039;"

    })[char]);

}


function showSection(sectionId, button) {

    document.querySelectorAll("section").forEach(section => {

        section.classList.remove("active");

    });

    document.getElementById(sectionId).classList.add("active");

    document.querySelectorAll("nav button").forEach(btn => {

        btn.classList.remove("active");

    });

    button.classList.add("active");


    // The graph lives in a hidden tab at load time, so resize and
    // refit it once the tab becomes visible.
    setTimeout(() => {

        if (sectionId === "dependencies" && fullNetwork) {

            fullNetwork.network.setSize("100%", "100%");

            fullNetwork.network.redraw();

            fullNetwork.network.fit();

        }

    }, 100);

}


// Every edge means:
// source package depends on target package.

function getChildEdges(parentId) {

    return ALL_EDGES.filter(

        edge => String(edge.from) === String(parentId)

    );

}


// ============================================================
// 11. CALCULATE VISIBLE GRAPH
// ============================================================

function calculateVisibleGraph(expandedNodes) {

    const visibleIds = new Set(["APPLICATION"]);

    const visibleEdges = [];

    const queue = ["APPLICATION"];

    const processed = new Set();


    while (queue.length) {

        const current = queue.shift();

        if (processed.has(current)) {
            continue;
        }

        processed.add(current);

        if (!expandedNodes.has(current)) {
            continue;
        }

        for (const edge of getChildEdges(current)) {

            const childId = String(edge.to);

            if (!nodeLookup.has(childId)) {
                continue;
            }

            visibleIds.add(childId);

            visibleEdges.push(edge);

            if (
                expandedNodes.has(childId) &&
                !processed.has(childId)
            ) {

                queue.push(childId);

            }

        }

    }


    return {

        nodes: ALL_NODES.filter(

            node => visibleIds.has(String(node.id))

        ),

        edges: visibleEdges

    };

}


// ============================================================
// 12. CREATE NETWORK
// ============================================================

function createNetwork(containerId, initialGraph) {

    const nodeData = new vis.DataSet(initialGraph.nodes);

    const edgeData = new vis.DataSet(initialGraph.edges);

    const container = document.getElementById(containerId);


    const options = {

        autoResize: true,

        nodes: {

            shape: "dot",

            borderWidth: 1,

            borderWidthSelected: 3,

            scaling: {
                min: 8,
                max: 35
            },

            font: {
                size: 11,
                face: "Arial",
                color: "#263238",
                strokeWidth: 2,
                strokeColor: "#ffffff"
            }

        },


        edges: {

            arrows: {

                to: {
                    enabled: true,
                    scaleFactor: 0.45
                }

            },

            smooth: {

                enabled: true,

                type: "continuous",

                roundness: 0.25

            },

            color: {

                color: "#9aa0a6",

                opacity: 0.65,

                highlight: "#1769aa"

            }

        },


        // Moving force-directed graph.
        physics: {

            enabled: true,

            solver: "barnesHut",

            barnesHut: {

                gravitationalConstant: -18000,

                centralGravity: 0.35,

                springLength: 110,

                springConstant: 0.025,

                damping: 0.12,

                avoidOverlap: 0.3

            },

            stabilization: {

                enabled: true,

                iterations: 300,

                updateInterval: 50,

                fit: true

            }

        },


        interaction: {

            hover: true,

            tooltipDelay: 150,

            navigationButtons: true,

            keyboard: true,

            multiselect: false,

            zoomView: true,

            dragView: true

        }

    };


    const network = new vis.Network(

        container,

        {
            nodes: nodeData,
            edges: edgeData
        },

        options

    );


    return {

        network,
        nodeData,
        edgeData

    };

}


// ============================================================
// 13. COLLAPSE BRANCH
// ============================================================

function collapseBranch(nodeId, expandedNodes) {

    const queue = [String(nodeId)];

    const visited = new Set(queue);


    while (queue.length) {

        const current = queue.shift();

        expandedNodes.delete(current);

        for (const edge of getChildEdges(current)) {

            const child = String(edge.to);

            if (!visited.has(child)) {

                visited.add(child);

                queue.push(child);

            }

        }

    }

}


// ============================================================
// 14. REDRAW GRAPH INCREMENTALLY
// ============================================================

function redrawExpandableGraph(graph, expandedNodes) {

    const visible = calculateVisibleGraph(expandedNodes);


    const currentNodeIds = new Set(

        graph.nodeData.getIds().map(String)

    );

    const visibleNodeIds = new Set(

        visible.nodes.map(node => String(node.id))

    );


    const currentEdgeIds = new Set(

        graph.edgeData.getIds().map(String)

    );

    const visibleEdgeIds = new Set(

        visible.edges.map(edge => String(edge.id))

    );


    // Remove nodes that are no longer visible.
    const nodesToRemove = [...currentNodeIds].filter(

        id => !visibleNodeIds.has(id)

    );

    if (nodesToRemove.length) {

        graph.nodeData.remove(nodesToRemove);

    }


    // Remove edges that are no longer visible.
    const edgesToRemove = [...currentEdgeIds].filter(

        id => !visibleEdgeIds.has(id)

    );

    if (edgesToRemove.length) {

        graph.edgeData.remove(edgesToRemove);

    }


    // Add newly revealed nodes.
    const nodesToAdd = visible.nodes

        .filter(node => !currentNodeIds.has(String(node.id)))

        .map(node => getDisplayNode(node, expandedNodes));


    if (nodesToAdd.length) {

        graph.nodeData.add(nodesToAdd);

    }


    // Update indicators on existing nodes.
    const nodesToUpdate = visible.nodes

        .filter(node => currentNodeIds.has(String(node.id)))

        .map(node => getDisplayNode(node, expandedNodes));


    if (nodesToUpdate.length) {

        graph.nodeData.update(nodesToUpdate);

    }


    // Add newly revealed edges.
    const edgesToAdd = visible.edges.filter(

        edge => !currentEdgeIds.has(String(edge.id))

    );

    if (edgesToAdd.length) {

        graph.edgeData.add(edgesToAdd);

    }


    // Keep force-directed physics enabled.
    graph.network.setOptions({

        physics: {
            enabled: true
        }

    });

    graph.network.startSimulation();

    graph.network.redraw();

}


// ============================================================
// 15. PACKAGE DETAILS
// ============================================================

function showPackageDetails(nodeId, targetId) {

    const container = document.getElementById(targetId);

    const node = nodeLookup.get(String(nodeId));

    if (!node) {

        container.innerHTML = "";

        return;

    }


    const outgoing = getChildEdges(nodeId).length;

    const incoming = ALL_EDGES.filter(

        edge => String(edge.to) === String(nodeId)

    ).length;


    let expansionMessage = "";

    if (outgoing === 0) {

        expansionMessage = "This package has no further dependencies.";

    } else {

        expansionMessage =
            `This package has ${outgoing} immediate dependencies.`;

    }


    container.innerHTML = `

        <div class="details">

            <h3>Package Details</h3>

            <p>
                <b>Package:</b>
                ${escapeHtml(node.label)}
            </p>

            <p>
                <b>Package ID:</b>
                ${escapeHtml(node.id)}
            </p>

            <p>
                <b>Immediate dependencies:</b>
                ${outgoing}
            </p>

            <p>
                <b>Dependents:</b>
                ${incoming}
            </p>

            <p>
                <b>Expansion:</b>
                ${escapeHtml(expansionMessage)}
            </p>

        </div>

    `;

}


// ============================================================
// 16. HANDLE NODE CLICKS
// ============================================================

function handleNodeClick(

    params,

    graph,

    expandedNodes,

    detailsId

) {

    if (!params.nodes || !params.nodes.length) {
        return;
    }


    const nodeId = String(params.nodes[0]);

    const numberOfChildren = childCount.get(nodeId) || 0;


    if (numberOfChildren > 0) {

        if (expandedNodes.has(nodeId)) {

            // Collapse this package and its expanded descendants.
            collapseBranch(nodeId, expandedNodes);

        } else {

            // Reveal its immediate dependencies.
            expandedNodes.add(nodeId);

        }

        redrawExpandableGraph(graph, expandedNodes);

    }


    showPackageDetails(nodeId, detailsId);

}


// ============================================================
// 17. OVERVIEW STATISTICS
// ============================================================

function renderStats() {

    const cards = [

        ["Total Packages", STATS.packages],

        ["Direct Dependencies", STATS.direct],

        ["Transitive Dependencies", STATS.transitive],

        ["Dependency Relationships", STATS.edges],

        ["Vulnerability Findings", STATS.findings],

        ["Affected Packages", STATS.vulnerable]

    ];


    document.getElementById("stats").innerHTML =

        cards.map(([label, value]) => `

            <div class="stat-card">

                <h3>${escapeHtml(label)}</h3>

                <p>${escapeHtml(value)}</p>

            </div>

        `).join("");

}


// ============================================================
// 18. SEVERITY CHART
// ============================================================

function renderSeverityChart() {

    const labels = [

        "CRITICAL",

        "HIGH",

        "MEDIUM",

        "LOW",

        "UNKNOWN"

    ];


    const values = labels.map(

        label => SEVERITY_COUNTS[label] || 0

    );


    new Chart(

        document.getElementById("severityChart"),

        {

            type: "doughnut",

            data: {

                labels,

                datasets: [{

                    data: values,

                    backgroundColor: [

                        "#e74c3c",

                        "#e67e22",

                        "#f1c40f",

                        "#2ecc71",

                        "#95a5a6"

                    ],

                    borderWidth: 1

                }]

            },


            options: {

                responsive: true,

                maintainAspectRatio: false,

                plugins: {

                    legend: {

                        position: "bottom"

                    }

                }

            }

        }

    );

}


// ============================================================
// 19. VULNERABILITY TABLE
// ============================================================

function renderVulnerabilities(rows) {

    const tbody = document.getElementById(

        "vulnerabilityTable"

    );


    tbody.innerHTML = rows.map(item => `

        <tr>

            <td>${escapeHtml(item.package)}</td>

            <td>${escapeHtml(item.version)}</td>

            <td>

                <span class="severity ${escapeHtml(item.severity)}">

                    ${escapeHtml(item.severity)}

                </span>

            </td>

            <td>${escapeHtml(item.cvss)}</td>

            <td>${escapeHtml(item.vulnerability)}</td>

            <td>${escapeHtml(item.cve || "N/A")}</td>

            <td>${escapeHtml(item.type)}</td>

        </tr>

    `).join("");


    document.getElementById("vulnerabilityCount").textContent =

        `Showing ${rows.length} vulnerability findings`;

}


// ============================================================
// 20. FILTER VULNERABILITIES
// ============================================================

function filterVulnerabilities() {

    const query = document.getElementById(

        "vulnerabilitySearch"

    ).value.toLowerCase();


    const severity = document.getElementById(

        "severityFilter"

    ).value;


    const filtered = VULNERABILITIES.filter(item => {

        const searchable = [

            item.package,

            item.version,

            item.cve,

            item.vulnerability,

            item.summary,

            item.type

        ].join(" ").toLowerCase();


        return (

            searchable.includes(query) &&

            (severity === "ALL" || item.severity === severity)

        );

    });


    renderVulnerabilities(filtered);

}


// ============================================================
// 21. FIND PATH FROM APPLICATION
// ============================================================

function findPathFromApplication(targetId) {

    const target = String(targetId);


    if (target === "APPLICATION") {

        return ["APPLICATION"];

    }


    const queue = [target];

    const visited = new Set([target]);

    const nextTowardTarget = new Map();

    let found = false;


    while (queue.length && !found) {

        const current = queue.shift();

        const incoming = ALL_EDGES.filter(

            edge => String(edge.to) === current

        );


        for (const edge of incoming) {

            const parent = String(edge.from);

            if (visited.has(parent)) {
                continue;
            }

            visited.add(parent);

            nextTowardTarget.set(parent, current);


            if (parent === "APPLICATION") {

                found = true;

                break;

            }

            queue.push(parent);

        }

    }


    if (!found) {

        return null;

    }


    const path = ["APPLICATION"];

    let current = "APPLICATION";


    while (current !== target) {

        current = nextTowardTarget.get(current);

        if (!current) {
            return null;
        }

        path.push(current);

    }


    return path;

}


// ============================================================
// 22. SEARCH PACKAGE
// ============================================================

function searchNode() {

    const query = document.getElementById(

        "nodeSearch"

    ).value.trim().toLowerCase();


    if (!query || !fullNetwork) {
        return;
    }


    const match = ALL_NODES.find(node =>

        String(node.label).toLowerCase().includes(query) ||

        String(node.id).toLowerCase().includes(query)

    );


    if (!match) {

        alert("Package not found.");

        return;

    }


    const path = findPathFromApplication(match.id);


    if (!path) {

        alert(
            "No dependency path from APPLICATION was found for this package."
        );

        return;

    }


    // Expand the parent packages along the path.
    fullExpanded = new Set(path.slice(0, -1));


    redrawExpandableGraph(fullNetwork, fullExpanded);


    fullNetwork.network.selectNodes([match.id]);


    fullNetwork.network.focus(match.id, {

        scale: 1.3,

        animation: {

            duration: 700,

            easingFunction: "easeInOutQuad"

        }

    });


    showPackageDetails(match.id, "fullDetails");

}


// ============================================================
// 23. SHOW FULL GRAPH
// ============================================================

function showFullGraph() {

    if (!fullNetwork) {
        return;
    }

    // Mark every package as expanded.
    fullExpanded = new Set(
        ALL_NODES.map(node => String(node.id))
    );

    // Display every reachable package and dependency edge.
    redrawExpandableGraph(fullNetwork, fullExpanded);

    fullNetwork.network.unselectAll();

    document.getElementById("fullDetails").innerHTML = "";

    // Allow the new nodes to enter the physics simulation,
    // then fit the complete graph into the available area.
    setTimeout(() => {

        fullNetwork.network.fit({

            animation: {

                duration: 800,

                easingFunction: "easeInOutQuad"

            }

        });

    }, 500);

}


// ============================================================
// 24. RESET GRAPH
// ============================================================

function resetFullGraph() {

    if (!fullNetwork) {
        return;
    }

    // Return to APPLICATION and direct dependencies.
    fullExpanded = new Set(["APPLICATION"]);

    redrawExpandableGraph(fullNetwork, fullExpanded);

    fullNetwork.network.unselectAll();

    fullNetwork.network.fit({

        animation: {

            duration: 700,

            easingFunction: "easeInOutQuad"

        }

    });

    document.getElementById("fullDetails").innerHTML = "";

}


// ============================================================
// 25. INITIALIZE DASHBOARD
// ============================================================

renderStats();

renderSeverityChart();

renderVulnerabilities(VULNERABILITIES);


// Initial graph contains APPLICATION and direct dependencies only.

function prepareInitialGraph(expandedNodes) {

    const visible = calculateVisibleGraph(expandedNodes);

    return {

        nodes: visible.nodes.map(node =>

            getDisplayNode(node, expandedNodes)

        ),

        edges: visible.edges

    };

}


fullNetwork = createNetwork(

    "fullGraph",

    prepareInitialGraph(fullExpanded)

);


// ============================================================
// 26. REGISTER CLICK EVENTS
// ============================================================

fullNetwork.network.on("click", params => {

    handleNodeClick(

        params,

        fullNetwork,

        fullExpanded,

        "fullDetails"

    );

});

</script>

</body>
</html>
'''

    # Insert Python data into the HTML template.
    values = {

        "__NODES__": json.dumps(
            nodes,
            ensure_ascii=True
        ).replace("</", "<\\/"),

        "__EDGES__": json.dumps(
            graph_edges,
            ensure_ascii=True
        ).replace("</", "<\\/"),

        "__VULNERABILITIES__": json.dumps(
            vulnerability_rows,
            ensure_ascii=True
        ).replace("</", "<\\/"),

        "__STATS__": json.dumps(stats),

        "__SEVERITY_COUNTS__": json.dumps(
            dict(severity_counts)
        )

    }


    for placeholder, value in values.items():

        page = page.replace(placeholder, value)


    os.makedirs(OUTPUT_DIR, exist_ok=True)


    with open(
        DASHBOARD_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(page)


    print("\nDashboard generated successfully!")

    print(f"\nDashboard: {DASHBOARD_FILE}")

    print("\nDashboard statistics")
    print("--------------------")

    print(f"Total packages: {stats['packages']}")

    print(f"Direct dependencies: {stats['direct']}")

    print(f"Transitive dependencies: {stats['transitive']}")

    print(f"Dependency relationships: {stats['edges']}")

    print(f"Vulnerability findings: {stats['findings']}")

    print(f"Affected packages: {stats['vulnerable']}")


# ============================================================
# 27. MAIN
# ============================================================

def main():

    print("Loading dependency and vulnerability data...")

    dependencies, edges, findings = load_data()

    print("Generating interactive dependency dashboard...")

    build_dashboard(
        dependencies,
        edges,
        findings
    )


if __name__ == "__main__":

    main()