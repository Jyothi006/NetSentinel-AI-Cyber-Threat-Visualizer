/* ==========================================================================
   NETSENTINEL CORE CLIENT CONTROLLER (D3.JS & API CONNECTIONS)
   ========================================================================== */

// --- Global State Variables ---
let networkNodes = [];
let networkLinks = [];
let recentAlerts = [];
let processedPacketKeys = new Set();
let simulationActive = true;
let chartInitialized = false;
const API_URL = window.location.origin.startsWith("http") ? window.location.origin : "http://127.0.0.1:5000";


// D3 SVG Selection references
let svg, simulation, linkGroup, nodeGroup, particleGroup;
let width = 700;
let height = 440;

// Map internal system IP addresses to Topology Node IDs
const ipToNodeIdMap = {
    "10.0.0.1": "Gateway",
    "10.0.0.2": "Firewall",
    "10.0.0.10": "Web-01",
    "10.0.0.11": "Web-02",
    "10.0.0.20": "DB-Server",
    "10.0.0.30": "DC-01",
    "10.0.1.50": "Workstation-A",
    "10.0.1.51": "Workstation-B"
};

// Node specifications (Colors)
const nodeThemes = {
    gateway: { color: "#ffffff" },
    firewall: { color: "#3b82f6" },
    server: { color: "#3b82f6" },
    database: { color: "#3b82f6" },
    endpoint: { color: "#3b82f6" },
    threat: { color: "#ffffff" }
};

// --- Initialization ---
document.addEventListener("DOMContentLoaded", () => {
    initTopologyChart();
    
    // Bind DOM events
    document.getElementById("toggle-sim-btn").addEventListener("click", toggleSimulation);
    document.getElementById("clear-db-btn").addEventListener("click", resetDatabase);
    
    const severityFilter = document.getElementById("severity-filter");
    if (severityFilter) {
        severityFilter.addEventListener("change", renderThreatLogs);
    }
    
    document.getElementById("trigger-ddos").addEventListener("click", () => injectAttack("ddos"));
    document.getElementById("trigger-scan").addEventListener("click", () => injectAttack("scan"));
    document.getElementById("trigger-exfil").addEventListener("click", () => injectAttack("exfil"));
    
    // Trigger initial polls
    pollStatus();
    pollNetwork();
    pollTraffic();
    pollThreats();
    
    // Set auto refresh intervals to 2 seconds (2000ms) as requested
    setInterval(pollTraffic, 2000);    
    setInterval(pollStatus, 2000);    
    setInterval(pollNetwork, 2000);   
    setInterval(pollThreats, 2000);   
});

// --- D3.js Network Topology Setup ---
function initTopologyChart() {
    const container = document.getElementById("topology-graph");
    width = container.clientWidth || 700;
    height = container.clientHeight || 440;
    
    // Create base SVG canvas
    svg = d3.select("#topology-graph")
        .append("svg")
        .attr("width", "100%")
        .attr("height", "100%")
        .attr("viewBox", `0 0 ${width} ${height}`)
        .attr("preserveAspectRatio", "xMidYMid meet");
        
    // Define Glow Filters in SVG
    const defs = svg.append("defs");
    
    // Cyan glow
    const glowFilter = defs.append("filter")
        .attr("id", "cyan-glow")
        .attr("x", "-20%")
        .attr("y", "-20%")
        .attr("width", "140%")
        .attr("height", "140%");
    glowFilter.append("feGaussianBlur")
        .attr("stdDeviation", "6")
        .attr("result", "blur");

    const mergeGroup = glowFilter.append("feMerge");
    mergeGroup.append("feMergeNode").attr("in", "blur");
    mergeGroup.append("feMergeNode").attr("in", "SourceGraphic");

    // SVG Groups representing layers (Links -> Particles -> Nodes)
    linkGroup = svg.append("g").attr("class", "links-layer");
    particleGroup = svg.append("g").attr("class", "particles-layer");
    nodeGroup = svg.append("g").attr("class", "nodes-layer");

    // Initialize D3 Force Simulation
    simulation = d3.forceSimulation()
        .force("charge", d3.forceManyBody().strength(-450))
        .force("center", d3.forceCenter(width / 2, height / 2))
        .force("collision", d3.forceCollide().radius(50))
        .force("link", d3.forceLink().id(d => d.id).distance(120));

    // Handle Window Resize
    window.addEventListener("resize", () => {
        width = container.clientWidth;
        height = container.clientHeight;
        svg.attr("viewBox", `0 0 ${width} ${height}`);
        simulation.force("center", d3.forceCenter(width / 2, height / 2));
        simulation.alpha(0.3).restart();
    });
}

// --- Fetch & Update Network Topology Data ---
async function pollNetwork() {
    try {
        const response = await fetch(`${API_URL}/api/network`);
        if (!response.ok) {
            const errorText = await response.text();
            console.error("API error /api/network:", response.status, errorText);
            return;
        }

        const data = await response.json();
        
        // Adapt schema mapping: support both "edges" and "links" keys
        const edges = data.edges || data.links || [];
        updateTopology(data.nodes || [], edges);
    } catch (error) {
        console.error("Error fetching network topology:", error);
    }
}

function updateTopology(nodes, links) {
    networkNodes = nodes;
    networkLinks = links;

    // 1. Bind Links
    const link = linkGroup.selectAll(".link-line")
        .data(networkLinks, d => `${d.source.id || d.source}-${d.target.id || d.target}`);
        
    // Exit
    link.exit().remove();
    
    // Enter + Update
    const linkEnter = link.enter()
        .append("line")
        .attr("class", "link-line")
        .merge(link);

    // 2. Bind Nodes
    const node = nodeGroup.selectAll(".node-group")
        .data(networkNodes, d => d.id);
        
    // Exit
    node.exit().remove();
    
    // Enter
    const nodeEnter = node.enter()
        .append("g")
        .attr("class", "node-group")
        .attr("transform", d => {
            // Set initial position to center if undefined to prevent NaN issues
            d.x = d.x || (width / 2);
            d.y = d.y || (height / 2);
            return `translate(${d.x}, ${d.y})`;
        })
        .call(d3.drag()
            .on("start", dragstarted)
            .on("drag", dragged)
            .on("end", dragended));
            
    // Node Outer Glow Ring (Blinks red on active alert status)
    nodeEnter.append("circle")
        .attr("class", "node-glow-ring")
        .attr("r", 28)
        .attr("fill", "none")
        .attr("stroke", "transparent")
        .attr("stroke-width", 2);
        
    // Node Center Circle
    nodeEnter.append("circle")
        .attr("class", "node-circle")
        .attr("r", 20)
        .attr("fill", "#040811")
        .attr("stroke-width", 2);

    // Node Friendly Title
    nodeEnter.append("text")
        .attr("class", "node-label")
        .attr("dy", "38px")
        .text(d => d.label);

    // Node IP Address
    nodeEnter.append("text")
        .attr("class", "node-ip")
        .attr("dy", "49px")
        .text(d => d.ip || "");

    // Merge Enter + Update sets
    const nodeMerge = nodeEnter.merge(node);
    
    // Update Node visual state depending on status ('alert', 'danger', or 'normal')
    nodeMerge.select(".node-circle")
        .attr("stroke", d => (d.status === "alert" || d.status === "danger") ? "#ffffff" : (nodeThemes[d.type]?.color || "#3b82f6"))
        .style("filter", "none")
        .classed("alert-state", d => (d.status === "alert" || d.status === "danger"));
        
    nodeMerge.select(".node-glow-ring")
        .attr("stroke", d => (d.status === "alert" || d.status === "danger") ? "#ffffff" : "transparent")
        .classed("alert-state", d => (d.status === "alert" || d.status === "danger"));

    // Update simulation nodes and forces
    simulation.nodes(networkNodes);
    simulation.force("link").links(networkLinks);
    
    if (!chartInitialized) {
        chartInitialized = true;
        simulation.alpha(1).restart();
    } else {
        simulation.alpha(0.15).restart();
    }

    simulation.on("tick", () => {
        linkEnter
            .attr("x1", d => d.source.x)
            .attr("y1", d => d.source.y)
            .attr("x2", d => d.target.x)
            .attr("y2", d => d.target.y);

        nodeMerge
            .attr("transform", d => `translate(${d.x}, ${d.y})`);
    });
}

// --- D3 Drag Handlers ---
function dragstarted(event, d) {
    if (!event.active) simulation.alphaTarget(0.3).restart();
    d.fx = d.x;
    d.fy = d.y;
}

function dragged(event, d) {
    d.fx = event.x;
    d.fy = event.y;
}

function dragended(event, d) {
    if (!event.active) simulation.alphaTarget(0);
    d.fx = null;
    d.fy = null;
}

// --- Live Traffic Feed & Packet Particle Animation ---
async function pollTraffic() {
    try {
        const response = await fetch(`${API_URL}/api/traffic`);
        if (!response.ok) {
            const errorText = await response.text();
            console.error("API error /api/traffic:", response.status, errorText);
            return;
        }

        const traffic = await response.json();
        
        if (!traffic || traffic.length === 0) return;
        
        const feedElement = document.getElementById("ticker-feed");
        
        traffic.forEach(pkt => {
            const freq = pkt.connection_count !== undefined ? pkt.connection_count : pkt.conn_freq;
            // Generate a signature to avoid duplicates in streaming ticker log
            const signature = `${pkt.src_ip}-${pkt.dest_ip}-${pkt.packet_size}-${pkt.duration}-${pkt.threat_score}`;
            
            if (!processedPacketKeys.has(signature)) {
                processedPacketKeys.add(signature);
                
                // 1. Insert Ticker Log entry
                const entry = document.createElement("div");
                const isThreat = pkt.threat_level !== "Normal";
                const lvlClass = pkt.threat_level.toLowerCase();
                
                entry.className = `ticker-entry ${lvlClass}`;
                entry.innerHTML = `
                    [${pkt.src_ip} &rarr; ${pkt.dest_ip}] [${pkt.protocol}]
                    Size: ${formatBytes(pkt.packet_size)} | Conn Count: ${freq} | 
                    Score: <strong>${pkt.threat_score}%</strong> (${pkt.threat_level})
                `;
                
                feedElement.appendChild(entry);
                
                // Auto scroll
                feedElement.scrollTop = feedElement.scrollHeight;
                
                // Limit domestic logs length
                if (feedElement.childNodes.length > 50) {
                    feedElement.removeChild(feedElement.firstChild);
                }
                
                // 2. Trigger particle animation along D3 nodes
                triggerPacketParticleAnimation(pkt.src_ip, pkt.dest_ip, isThreat);
            }
        });
        
        // Cap key cache
        if (processedPacketKeys.size > 200) {
            const arr = Array.from(processedPacketKeys);
            processedPacketKeys = new Set(arr.slice(arr.length - 100));
        }
        
    } catch (error) {
        console.error("Error polling live traffic:", error);
    }
}

// Map IP address to topological node structure
function resolveNodeId(ip) {
    if (ipToNodeIdMap[ip]) return ipToNodeIdMap[ip];
    
    // Check if there is an active threat node with matching IP
    const threatNode = networkNodes.find(n => n.ip === ip);
    if (threatNode) return threatNode.id;
    
    // If not matching internal mapping, assume Gateway node
    return "Gateway";
}

function triggerPacketParticleAnimation(srcIp, destIp, isThreat) {
    if (!chartInitialized || networkNodes.length === 0) return;
    
    const srcId = resolveNodeId(srcIp);
    const destId = resolveNodeId(destIp);
    
    const srcNode = networkNodes.find(n => n.id === srcId);
    const destNode = networkNodes.find(n => n.id === destId);
    
    // If they represent the same resolved node, or nodes don't have layout coordinates yet, skip
    if (!srcNode || !destNode || srcNode === destNode) return;
    if (srcNode.x === undefined || destNode.x === undefined) return;
    
    // Draw SVG animated circle particle
    const particle = particleGroup.append("circle")
        .attr("class", isThreat ? "packet-particle threat" : "packet-particle")
        .attr("cx", srcNode.x)
        .attr("cy", srcNode.y)
        .attr("r", isThreat ? 6 : 3.5);
        
    // Standard transition over 1100ms
    particle.transition()
        .duration(1100)
        .ease(d3.easeQuadInOut)
        .attr("cx", destNode.x)
        .attr("cy", destNode.y)
        .on("end", () => {
            particle.remove();
            
            // Flash node red momentarily on collision if it's a threat
            if (isThreat) {
                const targetEl = d3.selectAll(".node-group").filter(d => d.id === destId);
                targetEl.select(".node-circle")
                    .transition().duration(150)
                    .attr("r", 25)
                    .transition().duration(250)
                    .attr("r", 20);
            }
        });
}

// --- Poll Status Core Telemetry Metrics ---
async function pollStatus() {
    try {
        const response = await fetch(`${API_URL}/api/status`);
        if (!response.ok) {
            const errorText = await response.text();
            console.error("API error /api/status:", response.status, errorText);
            return;
        }

        const status = await response.json();
        
        // Update stats widgets (Read both threats_detected and threat_packets for backward compatibility)
        const threatsCount = status.threats_detected !== undefined ? status.threats_detected : status.threat_packets;
        
        animateNumberValue("val-total", status.total_packets);
        animateNumberValue("val-normal", status.normal_packets);
        animateNumberValue("val-threats", threatsCount);
        
        // Risk percentage updates
        const riskVal = document.getElementById("val-risk");
        riskVal.innerText = `${status.risk_percentage.toFixed(1)}%`;
        
        const riskBar = document.getElementById("val-risk-bar");
        riskBar.style.width = `${Math.min(100, status.risk_percentage * 1.5)}%`; // Scaled for alert colors visibility
        
        // Update Risk Theme card border colors based on percentage
        const riskCard = document.getElementById("card-risk");
        if (riskCard) {
            riskCard.style.boxShadow = "none";
            if (status.risk_percentage > 50) {
                riskCard.style.borderColor = "#ffffff";
            } else if (status.risk_percentage > 15) {
                riskCard.style.borderColor = "var(--accent)";
            } else {
                riskCard.style.borderColor = "var(--border-color)";
            }
        }

        // Toggle badge classes depending on state
        const statusBadge = document.getElementById("status-badge");
        const statusText = document.getElementById("status-text");
        simulationActive = status.simulation_active;
        
        if (status.simulation_active) {
            statusBadge.className = "status-badge online";
            statusText.innerText = "ACTIVE MONITORING";
            document.getElementById("toggle-sim-btn").innerHTML = 'PAUSE SIMULATION';
            document.getElementById("toggle-sim-btn").classList.remove("danger-btn");
        } else {
            statusBadge.className = "status-badge paused";
            statusText.innerText = "SYSTEM PAUSED";
            document.getElementById("toggle-sim-btn").innerHTML = 'RESUME SIMULATION';
            document.getElementById("toggle-sim-btn").classList.add("danger-btn");
        }
        
    } catch (error) {
        console.error("Error fetching system status:", error);
    }
}

// --- Poll & Render Threat Logs ---
async function pollThreats() {
    try {
        const response = await fetch(`${API_URL}/api/threats?limit=50`);
        if (!response.ok) {
            const errorText = await response.text();
            console.error("API error /api/threats:", response.status, errorText);
            return;
        }

        recentAlerts = await response.json();
        
        renderThreatLogs();
    } catch (error) {
        console.error("Error fetching threat logs:", error);
    }
}

function renderThreatLogs() {
    const tableBody = document.getElementById("logs-body");
    const severityFilter = document.getElementById("severity-filter");
    const filterValue = severityFilter ? severityFilter.value : "ALL";
    
    // Filter alerts
    const filteredAlerts = recentAlerts.filter(alert => {
        if (filterValue === "ALL") return true;
        return alert.threat_level === filterValue;
    });
    
    if (filteredAlerts.length === 0) {
        tableBody.innerHTML = `
            <tr>
                <td colspan="10" class="empty-table-msg">No threat records match selection. Security systems stable.</td>
            </tr>
        `;
        return;
    }
    
    tableBody.innerHTML = "";
    
    filteredAlerts.forEach(alert => {
        const row = document.createElement("tr");
        
        // Color threat values
        const scoreClass = alert.threat_score >= 75 ? "high" : "med";
        const badgeClass = alert.threat_level === "High-Risk" ? "high-risk" : "suspicious";
        const freq = alert.connection_count !== undefined ? alert.connection_count : alert.conn_freq;
        
        row.innerHTML = `
            <td>${alert.timestamp}</td>
            <td style="color: var(--accent)">${alert.src_ip}</td>
            <td style="color: #ffffff">${alert.dest_ip}</td>
            <td>${alert.protocol}</td>
            <td>${formatBytes(alert.packet_size)}</td>
            <td>${freq} c/m</td>
            <td><span class="badge ${badgeClass}">${alert.threat_level.toUpperCase()}</span></td>
            <td class="threat-score-col ${scoreClass}">${alert.threat_score.toFixed(1)}%</td>
            <td style="color: var(--accent); font-weight: bold">${alert.category}</td>
            <td style="color: var(--text-main); font-size: 0.8rem">${alert.reason}</td>
        `;
        
        tableBody.appendChild(row);
    });
}

// --- Simulator Control Actions ---
async function toggleSimulation() {
    const btn = document.getElementById("toggle-sim-btn");
    btn.disabled = true;
    try {
        const response = await fetch(`${API_URL}/api/simulator/toggle`, { method: "POST" });
        if (!response.ok) {
            const errorText = await response.text();
            console.error("API error /api/simulator/toggle:", response.status, errorText);
            return;
        }

        const data = await response.json();
        simulationActive = data.simulation_active;
        await pollStatus();
    } catch (error) {
        console.error("Error toggling simulation:", error);
    } finally {
        btn.disabled = false;
    }
}

async function resetDatabase() {
    const btn = document.getElementById("clear-db-btn");
    if (btn) btn.disabled = true;

    try {
        const response = await fetch(`${API_URL}/api/clear`, { method: "POST" });
        if (!response.ok) {
            const errorText = await response.text();
            console.error("API error /api/clear:", response.status, errorText);
            return;
        }

        await pollStatus();
        await pollThreats();
        await pollNetwork();
    } catch (error) {
        console.error("Error clearing database:", error);
    } finally {
        if (btn) btn.disabled = false;
    }
}

async function injectAttack(type) {
    const btnMap = {
        ddos: document.getElementById("trigger-ddos"),
        scan: document.getElementById("trigger-scan"),
        exfil: document.getElementById("trigger-exfil")
    };

    Object.values(btnMap).forEach(btn => btn && (btn.disabled = true));

    try {
        const response = await fetch(`${API_URL}/api/simulate_attack`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ type })
        });

        if (!response.ok) {
            const errorText = await response.text();
            console.error("API error /api/simulate_attack:", response.status, errorText);
            return;
        }

        const feedElement = document.getElementById("ticker-feed");
        const entry = document.createElement("div");
        entry.className = "ticker-entry system-msg";
        entry.style.color = "#ffffff";
        entry.innerHTML = `CRITICAL: Injecting ${type.toUpperCase()} threat vector...`;
        feedElement.appendChild(entry);
        feedElement.scrollTop = feedElement.scrollHeight;

        setTimeout(() => pollThreats(), 1000);
        setTimeout(() => pollStatus(), 1000);
        setTimeout(() => pollNetwork(), 1000);
    } catch (error) {
        console.error(`Error injecting ${type} attack:`, error);
    } finally {
        setTimeout(() => {
            Object.values(btnMap).forEach(btn => btn && (btn.disabled = false));
        }, 1000);
    }
}

// --- Helper Functions ---
function formatBytes(bytes) {
    if (bytes === 0) return "0 Bytes";
    if (bytes < 1024) return bytes + " Bytes";
    
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

function animateNumberValue(id, targetVal) {
    const el = document.getElementById(id);
    if (!el) return;
    
    const currentVal = parseInt(el.innerText.replace(/,/g, "")) || 0;
    if (currentVal === targetVal) return;
    
    const diff = targetVal - currentVal;
    // Animate difference over 10 ticks
    const step = Math.ceil(diff / 8);
    
    if (Math.abs(diff) < 2) {
        el.innerText = targetVal.toLocaleString();
        return;
    }
    
    let current = currentVal;
    const timer = setInterval(() => {
        current += step;
        if ((step > 0 && current >= targetVal) || (step < 0 && current <= targetVal)) {
            current = targetVal;
            clearInterval(timer);
        }
        el.innerText = current.toLocaleString();
    }, 40);
}
