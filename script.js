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

    const modal = document.getElementById("auto-irl-modal");
    const textarea = document.getElementById("auto-irl-textarea");

    textarea.value = selectedItems.map((item) => item.ioc).join("\n");
    modal.hidden = false;
    textarea.focus();
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
