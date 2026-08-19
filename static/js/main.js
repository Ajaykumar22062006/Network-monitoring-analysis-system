/**
 * Network Monitoring Dashboard JS Helpers
 * Handles client-side dynamics, such as asynchronous device scanning.
 */

document.addEventListener("DOMContentLoaded", () => {
    // If we are on the dashboard, automatically run a network status scan
    const deviceRows = document.querySelectorAll("tr[data-device-id]");
    if (deviceRows.length > 0) {
        runSequentialDeviceScan(deviceRows);
    }

    // Set up click listener for global scan button if it exists
    const scanBtn = document.getElementById("scan-network-btn");
    if (scanBtn) {
        scanBtn.addEventListener("click", () => {
            const rows = document.querySelectorAll("tr[data-device-id]");
            if (rows.length > 0) {
                runSequentialDeviceScan(rows);
            }
        });
    }

    // Simple close alert button handler
    const alertCloseBtns = document.querySelectorAll(".alert .close-btn");
    alertCloseBtns.forEach(btn => {
        btn.addEventListener("click", (e) => {
            e.target.closest(".alert").remove();
        });
    });
});

/**
 * Sequentially triggers a ping check on each device row.
 * Sequential run prevents running too many background ping subprocesses at once,
 * which can cause false timeouts or performance stutters.
 */
async function runSequentialDeviceScan(rows) {
    const scanBtn = document.getElementById("scan-network-btn");
    if (scanBtn) {
        scanBtn.disabled = true;
        scanBtn.innerHTML = `
            <svg class="animate-spin" style="width:16px; height:16px; margin-right:8px; display:inline-block; vertical-align:middle;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="12" cy="12" r="10" stroke-opacity="0.25"></circle>
                <path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"></path>
            </svg>Scanning...
        `;
    }

    // Reset status badges to "Checking..."
    rows.forEach(row => {
        const statusCell = row.querySelector(".device-status-badge");
        if (statusCell) {
            statusCell.className = "badge badge-unknown device-status-badge";
            statusCell.innerHTML = `<span class="badge-dot ping-pulse-checking"></span> Checking...`;
        }
    });

    // Execute sequential status checks
    for (let row of rows) {
        const id = row.getAttribute("data-device-id");
        try {
            await scanDevice(id, row);
        } catch (err) {
            console.error(`Failed to scan device ${id}:`, err);
        }
    }

    // Re-enable scan button
    if (scanBtn) {
        scanBtn.disabled = false;
        scanBtn.innerHTML = `
            <svg style="width:16px; height:16px; margin-right:8px; display:inline-block; vertical-align:middle;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"></path>
            </svg>Scan Network
        `;
    }
}

/**
 * Pings a single device via Flask API and updates its dashboard row details in the DOM.
 */
async function scanDevice(deviceId, row) {
    const statusCell = row.querySelector(".device-status-badge");
    const latencyCell = row.querySelector(".device-latency");
    const lossCell = row.querySelector(".device-loss");
    const timestampCell = row.querySelector(".device-timestamp");

    const response = await fetch(`/api/ping_device/${deviceId}`);
    const data = await response.json();

    if (data.success) {
        // Update Table row parameters
        if (data.status === "Online") {
            statusCell.className = "badge badge-online device-status-badge";
            statusCell.innerHTML = `<span class="badge-dot ping-pulse"></span> Online`;
            latencyCell.textContent = data.response_time;
            lossCell.textContent = data.packet_loss;
        } else {
            statusCell.className = "badge badge-offline device-status-badge";
            statusCell.innerHTML = `<span class="badge-dot ping-pulse-offline"></span> Offline`;
            latencyCell.textContent = "N/A";
            lossCell.textContent = data.packet_loss || "100%";
        }

        // Format and update Timestamp
        const now = new Date();
        const timeStr = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        timestampCell.textContent = timeStr;

        // Recompute Dashboard counters
        recalculateStats();
    } else {
        statusCell.className = "badge badge-offline device-status-badge";
        statusCell.innerHTML = `<span class="badge-dot ping-pulse-offline"></span> Error`;
        latencyCell.textContent = "N/A";
        lossCell.textContent = "100%";
    }
}

/**
 * Iterates through all device rows in the table to recompute 
 * online vs offline tallies and update the dashboard layout cards.
 */
function recalculateStats() {
    const badges = document.querySelectorAll(".device-status-badge");
    let onlineCount = 0;
    let offlineCount = 0;
    let totalCount = badges.length;

    badges.forEach(badge => {
        if (badge.classList.contains("badge-online")) {
            onlineCount++;
        } else if (badge.classList.contains("badge-offline")) {
            offlineCount++;
        }
    });

    const onlineCard = document.getElementById("stat-online-val");
    const offlineCard = document.getElementById("stat-offline-val");
    const totalCard = document.getElementById("stat-total-val");

    if (onlineCard) onlineCard.textContent = onlineCount;
    if (offlineCard) offlineCard.textContent = offlineCount;
    if (totalCard) totalCard.textContent = totalCount;
}
