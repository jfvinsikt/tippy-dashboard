const DEFAULT_DATA = [
    {
        recordId: "1",
        recordName: "Record 1",
        signatureId: "SIG001",
        ioc: "example.com",
        type: "Domain",
        country: "US",
        timestamp: "2023-10-01 12:00:00",
        riskScore: "High",
        threatActor: "Actor A",
        malware: "Malware X",
        analystNotes: "",
        tippyTag: "Tag1",
        status: "pending",
        selected: false
    },
    {
        recordId: "2",
        recordName: "Record 2",
        signatureId: "SIG002",
        ioc: "192.168.1.1",
        type: "IP",
        country: "CN",
        timestamp: "2023-10-02 13:00:00",
        riskScore: "Medium",
        threatActor: "Actor B",
        malware: "Malware Y",
        analystNotes: "",
        tippyTag: "Tag2",
        status: "pending",
        selected: false
    },
    {
        recordId: "3",
        recordName: "Record 3",
        signatureId: "SIG003",
        ioc: "bad.domain.net",
        type: "Domain",
        country: "RU",
        timestamp: "2023-10-03 14:00:00",
        riskScore: "Low",
        threatActor: "Actor C",
        malware: "Malware Z",
        analystNotes: "",
        tippyTag: "Tag3",
        status: "pending",
        selected: false
    },
    {
        recordId: "4",
        recordName: "Record 4",
        signatureId: "SIG004",
        ioc: "10.0.0.1",
        type: "IP",
        country: "IN",
        timestamp: "2023-10-04 15:00:00",
        riskScore: "High",
        threatActor: "Actor D",
        malware: "Malware W",
        analystNotes: "",
        tippyTag: "Tag4",
        status: "pending",
        selected: false
    },
    {
        recordId: "5",
        recordName: "Record 5",
        signatureId: "SIG005",
        ioc: "evil.com",
        type: "Domain",
        country: "BR",
        timestamp: "2023-10-05 16:00:00",
        riskScore: "Medium",
        threatActor: "Actor E",
        malware: "Malware V",
        analystNotes: "",
        tippyTag: "Tag5",
        status: "pending",
        selected: false
    },
    {
        recordId: "6",
        recordName: "Record 6",
        signatureId: "SIG006",
        ioc: "https://malicious.example.com/payload",
        type: "URL",
        country: "DE",
        timestamp: "2023-10-06 17:00:00",
        riskScore: "High",
        threatActor: "Actor F",
        malware: "Malware U",
        analystNotes: "",
        tippyTag: "Tag6",
        status: "pending",
        selected: false
    },
    {
        recordId: "7",
        recordName: "Record 7",
        signatureId: "SIG007",
        ioc: "http://suspicious.site/download.exe",
        type: "URL",
        country: "FR",
        timestamp: "2023-10-07 18:00:00",
        riskScore: "Medium",
        threatActor: "Actor G",
        malware: "Malware T",
        analystNotes: "",
        tippyTag: "Tag7",
        status: "pending",
        selected: false
    },
    {
        recordId: "8",
        recordName: "Record 8",
        signatureId: "SIG008",
        ioc: "https://cdn.bad-example.net/dropper.zip",
        type: "URL",
        country: "GB",
        timestamp: "2023-10-08 09:30:00",
        riskScore: "High",
        threatActor: "Actor H",
        malware: "Malware S",
        analystNotes: "",
        tippyTag: "Tag8",
        status: "pending",
        selected: false
    },
    {
        recordId: "9",
        recordName: "Record 9",
        signatureId: "SIG009",
        ioc: "http://login-alert.example.org/verify/session",
        type: "URL",
        country: "NL",
        timestamp: "2023-10-09 11:45:00",
        riskScore: "Medium",
        threatActor: "Actor I",
        malware: "Malware R",
        analystNotes: "",
        tippyTag: "Tag9",
        status: "pending",
        selected: false
    },
    {
        recordId: "10",
        recordName: "Record 10",
        signatureId: "SIG010",
        ioc: "https://update-portal.fakecdn.io/install/client.msi",
        type: "URL",
        country: "SE",
        timestamp: "2023-10-10 14:20:00",
        riskScore: "High",
        threatActor: "Actor J",
        malware: "Malware Q",
        analystNotes: "",
        tippyTag: "Tag10",
        status: "pending",
        selected: false
    }
];

const STORAGE_KEY = "tippyData";
const DEFAULT_SORT = { column: "recordId", order: "asc" };
const TEXT_FIELDS = [
    "recordId",
    "recordName",
    "signatureId",
    "ioc",
    "type",
    "country",
    "timestamp",
    "riskScore",
    "threatActor",
    "malware",
    "analystNotes",
    "tippyTag",
    "status"
];

const state = {
    activeTab: "pending",
    filters: {
        pending: { search: "", ...DEFAULT_SORT },
        completed: { search: "", ...DEFAULT_SORT }
    }
};

let data = loadData();

function loadData() {
    try {
        const raw = localStorage.getItem(STORAGE_KEY);
        const parsed = raw ? JSON.parse(raw) : DEFAULT_DATA;

        if (!Array.isArray(parsed)) {
            throw new Error("Stored data is not an array.");
        }

        return mergeDefaultData(parsed.map(normalizeItem));
    } catch (error) {
        console.warn("Falling back to default dashboard data.", error);
        return DEFAULT_DATA.map(normalizeItem);
    }
}

function mergeDefaultData(savedItems) {
    const savedRecordIds = new Set(savedItems.map((item) => item.recordId));
    const missingDefaultItems = DEFAULT_DATA
        .map(normalizeItem)
        .filter((item) => !savedRecordIds.has(item.recordId));

    return [...savedItems, ...missingDefaultItems];
}

function normalizeItem(item, index = 0) {
    const safeItem = item && typeof item === "object" ? item : {};

    return {
        recordId: sanitizeString(safeItem.recordId, String(index + 1)),
        recordName: sanitizeString(safeItem.recordName, `Record ${index + 1}`),
        signatureId: sanitizeString(safeItem.signatureId, ""),
        ioc: sanitizeString(safeItem.ioc, ""),
        type: normalizeType(safeItem.type),
        country: sanitizeString(safeItem.country, ""),
        timestamp: sanitizeString(safeItem.timestamp, ""),
        riskScore: sanitizeString(safeItem.riskScore, ""),
        threatActor: sanitizeString(safeItem.threatActor, ""),
        malware: sanitizeString(safeItem.malware, ""),
        analystNotes: sanitizeString(safeItem.analystNotes, ""),
        tippyTag: sanitizeString(safeItem.tippyTag, ""),
        status: safeItem.status === "completed" ? "completed" : "pending",
        selected: Boolean(safeItem.selected)
    };
}

function sanitizeString(value, fallback) {
    if (typeof value === "string") {
        return value.trim();
    }

    if (typeof value === "number") {
        return String(value);
    }

    return fallback;
}

function normalizeType(type) {
    if (type === "Domain" || type === "IP" || type === "URL") {
        return type;
    }

    return "URL";
}

function saveData() {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
}

function escapeHtml(value) {
    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

function getRecordedFutureUrl(item) {
    if (item.type === "Domain") {
        return `https://app.recordedfuture.com/portal/intelligence-card/idn%3A${encodeURIComponent(item.ioc)}/overview`;
    }

    if (item.type === "IP") {
        return `https://app.recordedfuture.com/portal/intelligence-card/ip%3A${encodeURIComponent(item.ioc)}/overview`;
    }

    return `https://app.recordedfuture.com/portal/intelligence-card/url%3A${encodeURIComponent(item.ioc)}/overview`;
}

function getTabConfig(tabName) {
    return {
        pending: {
            tabName,
            tbody: document.getElementById("pending-tbody"),
            searchInput: document.getElementById("search-input"),
            sortColumn: document.getElementById("sort-column"),
            sortOrder: document.getElementById("sort-order"),
            copyContainer: document.getElementById("copy-container"),
            feedback: document.getElementById("pending-feedback"),
            statusValue: "pending",
            emptyMessage: "No pending items match the current filters."
        },
        completed: {
            tabName,
            tbody: document.getElementById("completed-tbody"),
            searchInput: document.getElementById("search-input-completed"),
            sortColumn: document.getElementById("sort-column-completed"),
            sortOrder: document.getElementById("sort-order-completed"),
            copyContainer: document.getElementById("copy-container-completed"),
            feedback: document.getElementById("completed-feedback"),
            statusValue: "completed",
            emptyMessage: "No completed items match the current filters."
        }
    }[tabName];
}

function matchesSearch(item, query) {
    if (!query) {
        return true;
    }

    const searchable = TEXT_FIELDS.map((field) => item[field]).join(" ").toLowerCase();
    return searchable.includes(query);
}

function compareValues(a, b, column, order) {
    let left = a[column];
    let right = b[column];

    if (column === "recordId") {
        left = Number.parseInt(left, 10);
        right = Number.parseInt(right, 10);
    } else {
        left = String(left).toLowerCase();
        right = String(right).toLowerCase();
    }

    const result = left > right ? 1 : left < right ? -1 : 0;
    return order === "asc" ? result : -result;
}

function getVisibleItems(tabName) {
    const filters = state.filters[tabName];
    const statusValue = tabName === "completed" ? "completed" : "pending";

    return data
        .map((item, index) => ({ item, index }))
        .filter(({ item }) => item.status === statusValue && matchesSearch(item, filters.search))
        .sort((left, right) => compareValues(left.item, right.item, filters.column, filters.order));
}

function buildEmptyStateRow(message) {
    return `
        <tr class="empty-row">
            <td colspan="14">
                <div class="empty-state">${escapeHtml(message)}</div>
            </td>
        </tr>
    `;
}

function getRiskPillClass(riskScore) {
    const normalized = String(riskScore).toLowerCase();

    if (normalized === "high") {
        return "risk-pill risk-pill-high";
    }

    if (normalized === "medium") {
        return "risk-pill risk-pill-medium";
    }

    return "risk-pill risk-pill-low";
}

function buildRow(item, index) {
    const tooltipId = `tooltip-${item.status}-${index}`;
    const recordUrl = `https://sigdb.insikt.aux.recfut.com/records/${encodeURIComponent(item.recordId)}`;
    const googleUrl = `https://www.google.com/search?q=${encodeURIComponent(item.ioc)}`;
    const recordedFutureUrl = getRecordedFutureUrl(item);
    const triageUrl = `https://tria.ge/s?q=${encodeURIComponent(item.ioc)}`;
    const urlscanUrl = `https://pro.urlscan.io/triage?query=${encodeURIComponent(item.ioc)}`;
    const virusTotalUrl = `https://www.virustotal.com/gui/search/${encodeURIComponent(item.ioc)}`;
    const displayTimestamp = item.timestamp.split(" ")[0] || item.timestamp;

    return `
        <tr data-index="${index}"${item.selected ? ' class="row-selected"' : ''}>
            <td><input type="checkbox" class="row-select" data-index="${index}" ${item.selected ? "checked" : ""} aria-label="Select record ${escapeHtml(item.recordId)}"></td>
            <td><a class="record-link" href="${recordUrl}" target="_blank" rel="noopener noreferrer">${escapeHtml(item.recordId)}</a></td>
            <td>${escapeHtml(item.recordName)}</td>
            <td>${escapeHtml(item.signatureId)}</td>
            <td class="ioc-container">
                <button
                    type="button"
                    class="ioc-button"
                    aria-expanded="false"
                    aria-haspopup="true"
                    aria-controls="${tooltipId}"
                >${escapeHtml(item.ioc)}</button>
                <div id="${tooltipId}" class="tooltip" aria-label="IOC lookup links">
                    <a href="${googleUrl}" target="_blank" rel="noopener noreferrer">Search on Google</a>
                    <a href="${recordedFutureUrl}" target="_blank" rel="noopener noreferrer">Search on Recorded Future</a>
                    <a href="${triageUrl}" target="_blank" rel="noopener noreferrer">Search on Triage</a>
                    <a href="${urlscanUrl}" target="_blank" rel="noopener noreferrer">Search on URLScan</a>
                    <a href="${virusTotalUrl}" target="_blank" rel="noopener noreferrer">Search on Virus Total</a>
                </div>
            </td>
            <td>${escapeHtml(item.type)}</td>
            <td>${escapeHtml(item.country)}</td>
            <td>${escapeHtml(displayTimestamp)}</td>
            <td><span class="${getRiskPillClass(item.riskScore)}">${escapeHtml(item.riskScore)}</span></td>
            <td>${escapeHtml(item.threatActor)}</td>
            <td>${escapeHtml(item.malware)}</td>
            <td class="notes-cell">
                <input
                    type="text"
                    class="notes-input"
                    data-index="${index}"
                    value="${escapeHtml(item.analystNotes)}"
                    placeholder="Add note…"
                    aria-label="Analyst notes for record ${escapeHtml(item.recordId)}"
                >
            </td>
            <td>${escapeHtml(item.tippyTag)}</td>
            <td><input type="checkbox" class="status-toggle" data-index="${index}" ${item.status === "completed" ? "checked" : ""} aria-label="Mark record ${escapeHtml(item.recordId)} as completed"></td>
        </tr>
    `;
}

function renderTab(tabName) {
    const config = getTabConfig(tabName);
    const visibleItems = getVisibleItems(tabName);
    const totalItems = data.filter(item => item.status === (tabName === "completed" ? "completed" : "pending")).length;
    const showing = visibleItems.length;

    config.tbody.innerHTML = visibleItems.length
        ? visibleItems.map(({ item, index }) => buildRow(item, index)).join("")
        : buildEmptyStateRow(config.emptyMessage);

    const countEl = document.getElementById(`${tabName}-record-count`);
    if (countEl) {
        if (showing === totalItems) {
            countEl.innerHTML = `<span class="record-count-highlight">${showing}</span> record${showing !== 1 ? "s" : ""}`;
        } else {
            countEl.innerHTML = `<span class="record-count-highlight">${showing}</span> of ${totalItems} records`;
        }
    }

    updateCopyButtonVisibility();
}

function renderTable() {
    renderTab("pending");
    renderTab("completed");
    updateSummaryCards();
}

function updateSummaryCards() {
    const pendingCount = data.filter((item) => item.status === "pending").length;
    const completedCount = data.filter((item) => item.status === "completed").length;
    const uniqueThreatActorCount = new Set(
        data
            .map((item) => item.threatActor.trim())
            .filter((value) => value)
    ).size;
    const uniqueMalwareFamilyCount = new Set(
        data
            .map((item) => item.malware.trim())
            .filter((value) => value)
    ).size;

    document.getElementById("pending-count").textContent = String(pendingCount);
    document.getElementById("completed-count").textContent = String(completedCount);
    document.getElementById("threat-actor-count").textContent = String(uniqueThreatActorCount);
    document.getElementById("malware-family-count").textContent = String(uniqueMalwareFamilyCount);
    document.getElementById("pending-tab-count").textContent = String(pendingCount);
    document.getElementById("completed-tab-count").textContent = String(completedCount);
}

function setFeedback(tabName, message, isError = false) {
    const feedback = getTabConfig(tabName).feedback;
    feedback.textContent = message;
    feedback.classList.toggle("is-error", isError);
}

function updateCopyButtonVisibility() {
    ["pending", "completed"].forEach((tabName) => {
        const config = getTabConfig(tabName);
        const hasSelected = data.some((item) => item.status === config.statusValue && item.selected);
        config.copyContainer.style.display = hasSelected ? "flex" : "none";
    });
}

function defangIOC(ioc) {
    return ioc.replace(/\./g, "[.]");
}

async function copySelectedIOCs(tabName) {
    const statusValue = tabName === "completed" ? "completed" : "pending";
    const selectedItems = data.filter((item) => item.selected && item.status === statusValue);

    if (!selectedItems.length) {
        setFeedback(tabName, "Select at least one IOC before copying.", true);
        return;
    }

    try {
        await navigator.clipboard.writeText(selectedItems.map((item) => defangIOC(item.ioc)).join("\n"));
        setFeedback(tabName, "");
    } catch (error) {
        console.error("Failed to copy IOCs:", error);
        setFeedback(tabName, "Clipboard access failed. Please try again.", true);
    }
}

function getSelectedItems(tabName) {
    const statusValue = tabName === "completed" ? "completed" : "pending";
    return data.filter((item) => item.selected && item.status === statusValue);
}

function openAutoIrlModal(tabName) {
    const selectedItems = getSelectedItems(tabName);

    if (!selectedItems.length) {
        setFeedback(tabName, "Select at least one IOC before starting Auto IRL.", true);
        return;
    }

    // Gather prefill values from selected rows
    const uniqueThreatActors = [...new Set(selectedItems.map(i => i.threatActor).filter(Boolean))].join(", ");
    const uniqueMalware      = [...new Set(selectedItems.map(i => i.malware).filter(Boolean))].join(", ");
    const iocList            = selectedItems.map(i => i.ioc).join("\n");

    // Open the new-project modal with prefilled data
    const modal = document.getElementById("new-project-modal");
    document.getElementById("new-proj-title").value          = "";
    document.getElementById("new-proj-status").value         = "In Progress";
    document.getElementById("new-proj-threat-actor").value   = uniqueThreatActors;
    document.getElementById("new-proj-malware").value        = uniqueMalware;
    document.getElementById("new-proj-infrastructure").value = iocList;
    document.getElementById("new-proj-victims").value        = "";
    document.getElementById("new-proj-miq").value            = "";
    document.getElementById("new-proj-notes").value          = "";
    modal.hidden = false;
    document.getElementById("new-proj-title").focus();
}

function closeAutoIrlModal() {
    const modal = document.getElementById("auto-irl-modal");
    const textarea = document.getElementById("auto-irl-textarea");

    textarea.value = "";
    modal.hidden = true;
}

function moveSelectedToCompleted() {
    const selectedItems = data.filter((item) => item.selected && item.status === "pending");

    if (!selectedItems.length) {
        setFeedback("pending", "Select at least one IOC before moving items.", true);
        return;
    }

    selectedItems.forEach((item) => {
        item.status = "completed";
        item.selected = false;
    });

    saveData();
    renderTable();
    setFeedback("pending", "");
}

function clearSort(tabName) {
    state.filters[tabName] = {
        ...state.filters[tabName],
        ...DEFAULT_SORT
    };

    const config = getTabConfig(tabName);
    config.sortColumn.value = DEFAULT_SORT.column;
    config.sortOrder.value = DEFAULT_SORT.order;
    renderTab(tabName);
}

function showTab(tabName) {
    state.activeTab = tabName;

    // Always hide the terminal panel when switching to a table tab
    const terminalPanel = document.getElementById("terminal-panel");
    const terminalBtn = document.getElementById("auto-irl-terminal-btn");
    if (terminalPanel) terminalPanel.hidden = true;
    if (terminalBtn) terminalBtn.classList.remove("is-open");

    const pendingPanel = document.getElementById("pending");
    const completedPanel = document.getElementById("completed");
    const pendingButton = document.getElementById("pending-tab-button");
    const completedButton = document.getElementById("completed-tab-button");

    const isPending = tabName === "pending";
    pendingPanel.style.display = isPending ? "block" : "none";
    completedPanel.style.display = isPending ? "none" : "block";
    pendingPanel.classList.toggle("active", isPending);
    completedPanel.classList.toggle("active", !isPending);
    pendingButton.classList.toggle("active", isPending);
    completedButton.classList.toggle("active", !isPending);
    pendingButton.setAttribute("aria-selected", String(isPending));
    completedButton.setAttribute("aria-selected", String(!isPending));
}

function closeAllTooltips() {
    document.querySelectorAll(".ioc-container.is-open").forEach((container) => {
        container.classList.remove("is-open");
    });

    document.querySelectorAll(".ioc-button[aria-expanded='true']").forEach((button) => {
        button.setAttribute("aria-expanded", "false");
    });
}

function openTooltip(container) {
    closeAllTooltips();
    container.classList.add("is-open");
    const button = container.querySelector(".ioc-button");
    if (button) {
        button.setAttribute("aria-expanded", "true");
    }
}

function closeTooltip(container) {
    container.classList.remove("is-open");
    const button = container.querySelector(".ioc-button");
    if (button) {
        button.setAttribute("aria-expanded", "false");
    }
}

function handleTableClick(event) {
    const rowSelect = event.target.closest(".row-select");
    if (rowSelect) {
        const index = Number.parseInt(rowSelect.dataset.index, 10);
        data[index].selected = rowSelect.checked;
        const row = rowSelect.closest("tr");
        if (row) row.classList.toggle("row-selected", rowSelect.checked);
        saveData();
        updateCopyButtonVisibility();
        return;
    }

    const statusToggle = event.target.closest(".status-toggle");
    if (statusToggle) {
        const index = Number.parseInt(statusToggle.dataset.index, 10);
        data[index].status = statusToggle.checked ? "completed" : "pending";
        saveData();
        renderTable();
        return;
    }

    const iocButton = event.target.closest(".ioc-button");
    if (iocButton) {
        const container = iocButton.closest(".ioc-container");
        const isOpen = container.classList.contains("is-open");
        if (isOpen) {
            closeTooltip(container);
        } else {
            openTooltip(container);
        }
        return;
    }

    if (!event.target.closest(".ioc-container")) {
        closeAllTooltips();
    }
}

function handleTableInput(event) {
    const notesInput = event.target.closest(".notes-input");
    if (!notesInput) {
        return;
    }

    const index = Number.parseInt(notesInput.dataset.index, 10);
    data[index].analystNotes = notesInput.value;
    saveData();
}

function bindTooltipEvents() {
    document.addEventListener("mouseover", (event) => {
        const container = event.target.closest(".ioc-container");
        if (container) {
            openTooltip(container);
        }
    });

    document.addEventListener("mouseout", (event) => {
        const container = event.target.closest(".ioc-container");
        if (!container) {
            return;
        }

        const relatedTarget = event.relatedTarget;
        if (relatedTarget && container.contains(relatedTarget)) {
            return;
        }

        closeTooltip(container);
    });

    document.addEventListener("focusin", (event) => {
        const container = event.target.closest(".ioc-container");
        if (container) {
            openTooltip(container);
        }
    });

    document.addEventListener("focusout", (event) => {
        const container = event.target.closest(".ioc-container");
        if (!container) {
            return;
        }

        const nextTarget = event.relatedTarget;
        if (nextTarget && container.contains(nextTarget)) {
            return;
        }

        closeTooltip(container);
    });

    document.addEventListener("keydown", (event) => {
        if (event.key === "Escape") {
            closeAllTooltips();
        }
    });
}

function bindControls() {
    document.getElementById("pending-tab-button").addEventListener("click", () => showTab("pending"));
    document.getElementById("completed-tab-button").addEventListener("click", () => showTab("completed"));

    document.getElementById("search-input").addEventListener("input", (event) => {
        state.filters.pending.search = event.target.value.trim().toLowerCase();
        renderTab("pending");
    });

    document.getElementById("search-input-completed").addEventListener("input", (event) => {
        state.filters.completed.search = event.target.value.trim().toLowerCase();
        renderTab("completed");
    });

    document.getElementById("sort-column").addEventListener("change", (event) => {
        state.filters.pending.column = event.target.value;
        renderTab("pending");
    });

    document.getElementById("sort-order").addEventListener("change", (event) => {
        state.filters.pending.order = event.target.value;
        renderTab("pending");
    });

    document.getElementById("sort-column-completed").addEventListener("change", (event) => {
        state.filters.completed.column = event.target.value;
        renderTab("completed");
    });

    document.getElementById("sort-order-completed").addEventListener("change", (event) => {
        state.filters.completed.order = event.target.value;
        renderTab("completed");
    });

    document.getElementById("clear-sort-btn").addEventListener("click", () => clearSort("pending"));
    document.getElementById("clear-sort-btn-completed").addEventListener("click", () => clearSort("completed"));
    document.getElementById("copy-iocs-btn").addEventListener("click", () => copySelectedIOCs("pending"));
    document.getElementById("copy-iocs-btn-completed").addEventListener("click", () => copySelectedIOCs("completed"));
    document.getElementById("start-auto-irl-btn").disabled = false;
    document.getElementById("start-auto-irl-btn-completed").disabled = false;
    document.getElementById("start-auto-irl-btn").addEventListener("click", () => openAutoIrlModal("pending"));
    document.getElementById("start-auto-irl-btn-completed").addEventListener("click", () => openAutoIrlModal("completed"));
    document.getElementById("move-to-completed-btn").addEventListener("click", moveSelectedToCompleted);
    document.getElementById("auto-irl-discard-btn").addEventListener("click", closeAutoIrlModal);
    document.getElementById("auto-irl-send-btn").addEventListener("click", () => {});

    // ── Add to Existing Auto IRL ───────────────────────────────
    const addToExistingModal   = document.getElementById("add-to-existing-modal");
    const addToExistingList    = document.getElementById("add-to-existing-project-list");
    const addToExistingPreview = document.getElementById("add-to-existing-preview");
    const addToExistingIocs    = document.getElementById("add-to-existing-iocs");
    const addToExistingSaveBtn = document.getElementById("add-to-existing-save-btn");
    let   selectedExistingId   = null;

    function openAddToExistingModal() {
        const selectedItems = getSelectedItems("pending");
        if (!selectedItems.length) {
            setFeedback("pending", "Select at least one IOC before adding to a project.", true);
            return;
        }

        const iocText = selectedItems.map(i => i.ioc).join("\n");
        const pipelineProjects = loadIrlProjects().filter(p => p.status === "pipeline");

        if (!pipelineProjects.length) {
            setFeedback("pending", "No projects in the Current Auto IRL Pipeline.", true);
            return;
        }

        selectedExistingId = null;
        addToExistingSaveBtn.disabled = true;
        addToExistingPreview.hidden = true;
        addToExistingIocs.value = iocText;

        addToExistingList.innerHTML = pipelineProjects.map(p => `
            <button class="add-to-existing-item" type="button" data-project-id="${escapeHtml(p.id)}">
                <span class="add-to-existing-radio"></span>
                <span class="add-to-existing-item-info">
                    <span class="add-to-existing-item-name">${escapeHtml(p.title)}</span>
                    <span class="add-to-existing-item-meta">${countIocs(p.infrastructure)} IOCs &middot; ${escapeHtml(p.updatedLabel)} &middot; ${escapeHtml(p.pipelineStatus)}</span>
                </span>
            </button>
        `).join("");

        addToExistingList.querySelectorAll(".add-to-existing-item").forEach(btn => {
            btn.addEventListener("click", () => {
                addToExistingList.querySelectorAll(".add-to-existing-item").forEach(b => b.classList.remove("is-selected"));
                btn.classList.add("is-selected");
                selectedExistingId = btn.dataset.projectId;
                addToExistingSaveBtn.disabled = false;
                addToExistingPreview.hidden = false;
            });
        });

        addToExistingModal.hidden = false;
    }

    function closeAddToExistingModal() {
        addToExistingModal.hidden = true;
        selectedExistingId = null;
    }

    document.getElementById("add-to-existing-irl-btn").addEventListener("click", openAddToExistingModal);
    document.getElementById("add-to-existing-discard-btn").addEventListener("click", closeAddToExistingModal);
    document.getElementById("add-to-existing-close-btn").addEventListener("click", closeAddToExistingModal);

    addToExistingSaveBtn.addEventListener("click", () => {
        if (!selectedExistingId) return;
        const projects = loadIrlProjects();
        const project = projects.find(p => p.id === selectedExistingId);
        if (!project) return;

        const newIocs = addToExistingIocs.value.trim();
        project.infrastructure = project.infrastructure
            ? project.infrastructure + "\n" + newIocs
            : newIocs;
        project.updatedLabel = "Updated just now";

        saveIrlProjects(projects);
        renderIrlProjects();
        closeAddToExistingModal();
        setFeedback("pending", `IOCs added to "${project.title}".`);
        setTimeout(() => setFeedback("pending", ""), 3000);
    });

    addToExistingModal.addEventListener("click", (event) => {
        if (event.target === addToExistingModal) closeAddToExistingModal();
    });

    document.addEventListener("keydown", (event) => {
        if (event.key === "Escape" && !addToExistingModal.hidden) closeAddToExistingModal();
    });

    const terminalBtn = document.getElementById("auto-irl-terminal-btn");
    const terminalPanel = document.getElementById("terminal-panel");
    const terminalCloseBtn = document.getElementById("terminal-close-btn");

    terminalBtn.addEventListener("click", () => {
        const isOpen = !terminalPanel.hidden;
        terminalPanel.hidden = isOpen;
        terminalBtn.classList.toggle("is-open", !isOpen);
        // Always hide both table panels when terminal is open
        document.getElementById("pending").style.display = "none";
        document.getElementById("completed").style.display = "none";
        // Restore active tab when closing
        if (isOpen) showTab(state.activeTab);
    });

    terminalCloseBtn.addEventListener("click", () => {
        terminalPanel.hidden = true;
        terminalBtn.classList.remove("is-open");
        showTab(state.activeTab);
    });

    const irlPipelineTab = document.getElementById("irl-pipeline-tab");
    const irlPublishedTab = document.getElementById("irl-published-tab");
    const irlPipelinePanel = document.getElementById("irl-pipeline-panel");
    const irlPublishedPanel = document.getElementById("irl-published-panel");

    irlPipelineTab.addEventListener("click", () => {
        irlPipelineTab.classList.add("active");
        irlPublishedTab.classList.remove("active");
        irlPipelinePanel.classList.add("active");
        irlPublishedPanel.classList.remove("active");
    });

    irlPublishedTab.addEventListener("click", () => {
        irlPublishedTab.classList.add("active");
        irlPipelineTab.classList.remove("active");
        irlPublishedPanel.classList.add("active");
        irlPipelinePanel.classList.remove("active");
    });

    // ── IRL Projects data ──────────────────────────────────────
    const IRL_STORAGE_KEY = "tippyIrlProjects_v2";

    const DEFAULT_IRL_PROJECTS = [
        { id: "p1", title: "Malware 1 New Infrastructure",         iocCount: 12, updatedLabel: "Updated 2h ago",  status: "pipeline", pipelineStatus: "In Progress", threatActor: "", malware: "",   infrastructure: "", victims: "", miq: "", notes: "" },
        { id: "p2", title: "Actor B C2 Expansion — Q4",            iocCount: 8,  updatedLabel: "Updated 5h ago",  status: "pipeline", pipelineStatus: "In Progress", threatActor: "", malware: "",   infrastructure: "", victims: "", miq: "", notes: "" },
        { id: "p3", title: "Phishing Wave — EU Targets",           iocCount: 23, updatedLabel: "Updated 1d ago",  status: "pipeline", pipelineStatus: "In Review",   threatActor: "", malware: "",   infrastructure: "", victims: "", miq: "", notes: "" },
        { id: "p4", title: "Ransomware Group X — New Domains",     iocCount: 5,  updatedLabel: "Updated 2d ago",  status: "pipeline", pipelineStatus: "In Review",   threatActor: "", malware: "",   infrastructure: "", victims: "", miq: "", notes: "" },
        { id: "p5", title: "SIG007 Dropper Infrastructure",        iocCount: 17, updatedLabel: "Updated 3d ago",  status: "pipeline", pipelineStatus: "In Progress", threatActor: "", malware: "",   infrastructure: "", victims: "", miq: "", notes: "" },
        { id: "p6", title: "Actor A — Initial Access Broker Network", iocCount: 34, updatedLabel: "Ready 4d ago",  status: "published", pipelineStatus: "Ready", threatActor: "", malware: "", infrastructure: "", victims: "", miq: "", notes: "" },
        { id: "p7", title: "Malware Z — Loader Infrastructure",    iocCount: 19, updatedLabel: "Ready 1w ago", status: "published", pipelineStatus: "Ready", threatActor: "", malware: "",   infrastructure: "", victims: "", miq: "", notes: "" },
        { id: "p8", title: "CN Threat Cluster — Spearphish Domains", iocCount: 11, updatedLabel: "Ready 2w ago", status: "published", pipelineStatus: "Ready", threatActor: "", malware: "", infrastructure: "", victims: "", miq: "", notes: "" },
        { id: "p9", title: "RU APT — Credential Harvesting URLs",  iocCount: 28, updatedLabel: "Ready 3w ago", status: "published", pipelineStatus: "Ready", threatActor: "", malware: "",   infrastructure: "", victims: "", miq: "", notes: "" },
        { id: "p10", title: "SIG003 — Bad Domain Cluster Report",  iocCount: 9,  updatedLabel: "Ready 1mo ago", status: "published", pipelineStatus: "Ready", threatActor: "", malware: "",  infrastructure: "", victims: "", miq: "", notes: "" }
    ];

    function loadIrlProjects() {
        try {
            const raw = localStorage.getItem(IRL_STORAGE_KEY);
            return raw ? JSON.parse(raw) : DEFAULT_IRL_PROJECTS;
        } catch {
            return DEFAULT_IRL_PROJECTS;
        }
    }

    function saveIrlProjects(projects) {
        localStorage.setItem(IRL_STORAGE_KEY, JSON.stringify(projects));
    }

    function getPipelineStatusClass(pipelineStatus) {
        if (pipelineStatus === "In Progress") return "irl-status-active";
        if (pipelineStatus === "In Review")   return "irl-status-review";
        return "irl-status-published";
    }

    function countIocs(infrastructure) {
        if (!infrastructure || !infrastructure.trim()) return 0;
        return new Set(
            infrastructure.split("\n")
                .map(line => line.trim())
                .filter(Boolean)
        ).size;
    }

    function buildProjectRow(project) {
        const pillClass = getPipelineStatusClass(project.pipelineStatus);
        const iocCount = countIocs(project.infrastructure);

        return `
            <button class="irl-project-item" type="button" data-project-id="${escapeHtml(project.id)}">
                <div class="irl-project-main">
                    <span class="irl-project-name">${escapeHtml(project.title)}</span>
                    <span class="irl-project-meta">
                        ${iocCount} IOC${iocCount !== 1 ? "s" : ""} &middot; ${escapeHtml(project.updatedLabel)}
                    </span>
                </div>
                <div class="irl-project-right">
                    <span class="irl-status-pill ${pillClass}">${escapeHtml(project.pipelineStatus)}</span>
                    <span class="irl-chevron">›</span>
                </div>
            </button>
        `;
    }

    function renderIrlProjects() {
        const projects = loadIrlProjects();
        const pipelineProjects = projects.filter(p => p.status === "pipeline");
        const publishedProjects = projects.filter(p => p.status === "published");

        irlPipelinePanel.querySelector(".irl-project-list").innerHTML =
            pipelineProjects.map(buildProjectRow).join("");
        irlPublishedPanel.querySelector(".irl-project-list").innerHTML =
            publishedProjects.map(buildProjectRow).join("");

        document.querySelectorAll(".irl-project-item").forEach((btn) => {
            btn.addEventListener("click", () => {
                const projectId = btn.dataset.projectId;
                const projects = loadIrlProjects();
                const project = projects.find(p => p.id === projectId);
                if (project) openProjectModal(project);
            });
        });
    }

    // ── Project modal ──────────────────────────────────────────
    const projectModal = document.getElementById("project-config-modal");
    const projectModalTitle = document.getElementById("project-modal-title");
    let activeProjectId = null;

    function openProjectModal(project) {
        activeProjectId = project.id;
        projectModalTitle.textContent = project.title;
        document.getElementById("proj-title").value           = project.title;
        document.getElementById("proj-status").value          = project.pipelineStatus;
        document.getElementById("proj-threat-actor").value    = project.threatActor;
        document.getElementById("proj-malware").value         = project.malware;
        document.getElementById("proj-infrastructure").value  = project.infrastructure;
        document.getElementById("proj-victims").value         = project.victims;
        document.getElementById("proj-miq").value             = project.miq;
        document.getElementById("proj-notes").value           = project.notes;
        projectModal.hidden = false;
    }

    function closeProjectModal() {
        projectModal.hidden = true;
        activeProjectId = null;
    }

    document.getElementById("project-discard-btn").addEventListener("click", closeProjectModal);
    document.getElementById("project-discard-btn-2").addEventListener("click", closeProjectModal);

    document.getElementById("project-save-btn").addEventListener("click", () => {
        if (!activeProjectId) return;

        const projects = loadIrlProjects();
        const project = projects.find(p => p.id === activeProjectId);
        if (!project) return;

        const newTitle = document.getElementById("proj-title").value.trim() || project.title;
        const newStatus = document.getElementById("proj-status").value;
        project.title          = newTitle;
        project.pipelineStatus = newStatus;
        project.status         = newStatus === "Ready" ? "published" : "pipeline";
        project.threatActor    = document.getElementById("proj-threat-actor").value.trim();
        project.malware        = document.getElementById("proj-malware").value.trim();
        project.infrastructure = document.getElementById("proj-infrastructure").value.trim();
        project.victims        = document.getElementById("proj-victims").value.trim();
        project.miq            = document.getElementById("proj-miq").value.trim();
        project.notes          = document.getElementById("proj-notes").value.trim();
        project.updatedLabel   = "Updated just now";

        saveIrlProjects(projects);
        renderIrlProjects();
        closeProjectModal();
    });

    projectModal.addEventListener("click", (event) => {
        if (event.target === projectModal) closeProjectModal();
    });

    document.addEventListener("keydown", (event) => {
        if (event.key === "Escape" && !projectModal.hidden) closeProjectModal();
    });

    renderIrlProjects();

    renderIrlProjects();

    // ── New Project modal ──────────────────────────────────────
    const newProjectModal = document.getElementById("new-project-modal");

    function openNewProjectModal() {
        document.getElementById("new-proj-title").value          = "";
        document.getElementById("new-proj-status").value         = "In Progress";
        document.getElementById("new-proj-threat-actor").value   = "";
        document.getElementById("new-proj-malware").value        = "";
        document.getElementById("new-proj-infrastructure").value = "";
        document.getElementById("new-proj-victims").value        = "";
        document.getElementById("new-proj-miq").value            = "";
        document.getElementById("new-proj-notes").value          = "";
        newProjectModal.hidden = false;
    }

    function closeNewProjectModal() {
        newProjectModal.hidden = true;
    }

    document.getElementById("new-project-btn").addEventListener("click", openNewProjectModal);
    document.getElementById("new-project-discard-btn").addEventListener("click", closeNewProjectModal);
    document.getElementById("new-project-discard-btn-x").addEventListener("click", closeNewProjectModal);

    document.getElementById("new-project-save-btn").addEventListener("click", () => {
        const title = document.getElementById("new-proj-title").value.trim();
        if (!title) {
            document.getElementById("new-proj-title").focus();
            return;
        }
        const newStatus = document.getElementById("new-proj-status").value;
        const newProject = {
            id:             "p" + Date.now(),
            title,
            iocCount:       0,
            updatedLabel:   "Created just now",
            status:         newStatus === "Ready" ? "published" : "pipeline",
            pipelineStatus: newStatus,
            threatActor:    document.getElementById("new-proj-threat-actor").value.trim(),
            malware:        document.getElementById("new-proj-malware").value.trim(),
            infrastructure: document.getElementById("new-proj-infrastructure").value.trim(),
            victims:        document.getElementById("new-proj-victims").value.trim(),
            miq:            document.getElementById("new-proj-miq").value.trim(),
            notes:          document.getElementById("new-proj-notes").value.trim()
        };
        const projects = loadIrlProjects();
        projects.push(newProject);
        saveIrlProjects(projects);
        renderIrlProjects();
        closeNewProjectModal();

        // Open the terminal panel and navigate to the right tab so user sees the new project
        const terminalPanelEl = document.getElementById("terminal-panel");
        const terminalBtnEl   = document.getElementById("auto-irl-terminal-btn");
        if (terminalPanelEl.hidden) {
            terminalPanelEl.hidden = false;
            terminalBtnEl.classList.add("is-open");
            document.getElementById("pending").style.display = "none";
            document.getElementById("completed").style.display = "none";
        }

        if (newStatus === "Ready") {
            irlPublishedTab.click();
        } else {
            irlPipelineTab.click();
        }
    });

    newProjectModal.addEventListener("click", (event) => {
        if (event.target === newProjectModal) closeNewProjectModal();
    });

    document.addEventListener("keydown", (event) => {
        if (event.key === "Escape" && !newProjectModal.hidden) closeNewProjectModal();
    });

    const autoIrlModal = document.getElementById("auto-irl-modal");
    autoIrlModal.addEventListener("click", (event) => {
        if (event.target === autoIrlModal) {
            closeAutoIrlModal();
        }
    });

    document.getElementById("pending-table").addEventListener("click", handleTableClick);
    document.getElementById("completed-table").addEventListener("click", handleTableClick);
    document.getElementById("pending-table").addEventListener("input", handleTableInput);
    document.getElementById("completed-table").addEventListener("input", handleTableInput);
}

function initializeApp() {
    bindControls();
    bindTooltipEvents();
    document.addEventListener("keydown", (event) => {
        if (event.key === "Escape" && !document.getElementById("auto-irl-modal").hidden) {
            closeAutoIrlModal();
        }
    });
    renderTable();
    showTab("pending");
}

document.addEventListener("DOMContentLoaded", initializeApp);
