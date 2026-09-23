// ---------- Live clock ----------
function updateClock() {
    const el = document.getElementById("clock");
    if (!el) return;
    const now = new Date();
    const time = now.toLocaleTimeString("en-GB");
    const date = now.toLocaleDateString("en-US", { weekday: "short", month: "short", day: "numeric", year: "numeric" });
    el.innerHTML = `${time}<br>${date}`;
}
setInterval(updateClock, 1000);
updateClock();

// ---------- Dashboard streaming logic ----------
const chainEl = document.getElementById("chain");
const checklistEl = document.getElementById("checklist");
const restartBtn = document.getElementById("restartBtn");
const alertBanner = document.getElementById("alertBanner");
const scenarioSelect = document.getElementById("scenarioSelect");

const scenarioMetrics = {
    data_exfiltration: {
        records: ["Patient records accessed", "baseline for this role: ~40/day"],
        exported: ["Data exported", "single EHR export job"],
    },
    ransomware: {
        records: ["Systems affected", "workstations and shared clinical systems"],
        exported: ["Data encrypted", "estimated affected file volume"],
    },
    insider_misuse: {
        records: ["Patient records accessed", "outside the account's treatment relationship"],
        exported: ["Data exported", "unauthorized report export"],
    },
    phishing_compromise: {
        records: ["Privileged access attempts", "activity after reported phishing"],
        exported: ["Data exposure", "no confirmed export in this scenario"],
    },
};

function updateScenarioMetrics() {
    const metrics = scenarioMetrics[scenarioSelect ? scenarioSelect.value : "data_exfiltration"];
    if (!metrics) return;
    document.getElementById("statRecordsLabel").textContent = metrics.records[0];
    document.getElementById("statRecordsSub").textContent = metrics.records[1];
    document.getElementById("statExportedLabel").textContent = metrics.exported[0];
    document.getElementById("statExportedSub").textContent = metrics.exported[1];
}

if (scenarioSelect) scenarioSelect.addEventListener("change", updateScenarioMetrics);
updateScenarioMetrics();

if (restartBtn) {
    let eventSource = null;

    function resetUI() {
        chainEl.innerHTML = "";
        checklistEl.innerHTML = '<li class="checklist-empty">No recommendations yet — run the simulation.</li>';
        alertBanner.style.display = "none";
        document.getElementById("statRecords").textContent = "0";
        document.getElementById("statExported").textContent = "0 GB";
        document.getElementById("statOutbound").textContent = "—";
        document.getElementById("statDetection").textContent = "—";
    }

    function addChainStep(data) {
        const step = document.createElement("div");
        step.className = `chain-step level-${data.level}`;
        step.innerHTML = `
            <div class="chain-num">${data.num}</div>
            <div class="chain-content">
                <div class="chain-title">
                    ${data.title}
                    ${data.badge ? `<span class="chain-badge">${data.badge}</span>` : ""}
                </div>
                <div class="chain-time">${data.elapsed} — ${data.timestamp}</div>
                <p>${data.detail}</p>
            </div>
        `;
        chainEl.appendChild(step);

        // Update stat cards as new info becomes available
        if (data.stats) {
            if (data.stats.records_accessed !== undefined) {
                document.getElementById("statRecords").textContent =
                    data.stats.records_accessed.toLocaleString();
            }
            if (data.stats.systems_affected !== undefined) {
                document.getElementById("statRecords").textContent =
                    data.stats.systems_affected.toLocaleString();
            }
            if (data.stats.data_exported_gb !== undefined) {
                document.getElementById("statExported").textContent =
                    data.stats.data_exported_gb + " GB";
            }
            if (data.stats.encrypted_files_gb !== undefined) {
                document.getElementById("statExported").textContent =
                    data.stats.encrypted_files_gb + " GB";
            }
            if (data.stats.outbound_ip !== undefined) {
                document.getElementById("statOutbound").textContent = data.stats.outbound_ip;
            }
        }
    }

    function showAlert(data) {
        alertBanner.style.display = "flex";
        document.getElementById("alertTitle").textContent = data.title;
        document.getElementById("alertDesc").textContent = data.description;
        document.getElementById("alertMeta").textContent =
            `Account: ${data.account} · Source: ${data.source_ip} · Chain length: ${data.chain_length} stages`;
        document.getElementById("statDetection").textContent = data.time_to_detection_min + " min";
    }

    function showRecommendations(data) {
        checklistEl.innerHTML = "";
        data.recommendations.forEach((text, i) => {
            const li = document.createElement("li");
            li.innerHTML = `<input type="checkbox" id="rec${i}"><label for="rec${i}">${text}</label>`;
            checklistEl.appendChild(li);
        });
    }

    function startSimulation() {
        resetUI();
        restartBtn.disabled = true;
        restartBtn.textContent = "Running...";
        if (scenarioSelect) scenarioSelect.disabled = true;

        if (eventSource) eventSource.close();
        const scenario = scenarioSelect ? scenarioSelect.value : "data_exfiltration";
        eventSource = new EventSource(`/api/stream?scenario=${encodeURIComponent(scenario)}`);

        eventSource.onmessage = (e) => {
            const data = JSON.parse(e.data);

            if (data.type === "stage") addChainStep(data);
            if (data.type === "alert") showAlert(data);
            if (data.type === "recommendations") showRecommendations(data);

            if (data.type === "done") {
                eventSource.close();
                restartBtn.disabled = false;
                restartBtn.textContent = "▶ Run Simulation Again";
                if (scenarioSelect) scenarioSelect.disabled = false;
            }
        };

        eventSource.onerror = () => {
            eventSource.close();
            restartBtn.disabled = false;
            restartBtn.textContent = "▶ Run Simulation";
            if (scenarioSelect) scenarioSelect.disabled = false;
        };
    }

    restartBtn.addEventListener("click", startSimulation);
}