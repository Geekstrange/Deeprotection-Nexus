// app.js
document.addEventListener('DOMContentLoaded', function () {
    // ============================================================
    // Auth guard — redirect to /login if not authenticated
    // ============================================================
    (async function checkAuth() {
        try {
            const res = await fetch('/api/auth/status');
            const data = await res.json();
            if (!data.authenticated) {
                window.location.href = '/login';
            }
        } catch (_) {
            window.location.href = '/login';
        }
    })();

    // Logout button
    const logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', async function () {
            try {
                await fetch('/api/logout', { method: 'POST' });
            } finally {
                window.location.href = '/login';
            }
        });
    }

    // ============================================================
    // Password Change Modal
    // ============================================================
    const modal = document.getElementById('password-modal');
    const changeBtn = document.getElementById('change-password-btn');
    const closeBtn = document.getElementById('close-password-modal');
    const cancelBtn = document.getElementById('cancel-password');
    const submitBtn = document.getElementById('submit-password');
    const oldPass = document.getElementById('old-password');
    const newPass = document.getElementById('new-password');
    const confirmPass = document.getElementById('confirm-password');
    const errorDiv = document.getElementById('password-error');

    if (changeBtn) {
        changeBtn.addEventListener('click', () => {
            modal.style.display = 'flex';
            oldPass.value = '';
            newPass.value = '';
            confirmPass.value = '';
            errorDiv.textContent = '';
        });
    }

    function closeModal() {
        modal.style.display = 'none';
    }

    if (closeBtn) closeBtn.addEventListener('click', closeModal);
    if (cancelBtn) cancelBtn.addEventListener('click', closeModal);
    window.addEventListener('click', (e) => {
        if (e.target === modal) closeModal();
    });

    if (submitBtn) {
        submitBtn.addEventListener('click', async () => {
            errorDiv.textContent = '';
            const old = oldPass.value;
            const newP = newPass.value;
            const confirm = confirmPass.value;

            if (!old) {
                errorDiv.textContent = 'Current password is required';
                return;
            }
            if (!newP) {
                errorDiv.textContent = 'New password cannot be empty';
                return;
            }
            if (newP !== confirm) {
                errorDiv.textContent = 'New passwords do not match';
                return;
            }

            try {
                const res = await fetch('/api/change-password', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ old_password: old, new_password: newP })
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.error || 'Password change failed');
                Toast.success('Password changed successfully');
                closeModal();
            } catch (err) {
                errorDiv.textContent = err.message;
            }
        });
    }

    // ============================================================
    // State
    // ============================================================
    let currentConfig = null;
    let currentRules = [];
    let currentPaths = [];
    let currentAllowlist = [];

    // ============================================================
    // Navigation
    // ============================================================
    document.querySelectorAll('nav a').forEach(link => {
        link.addEventListener('click', function (e) {
            e.preventDefault();
            document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
            document.querySelectorAll('nav a').forEach(a => a.classList.remove('active'));
            this.classList.add('active');
            document.getElementById(this.dataset.page).classList.add('active');
        });
    });

    const copyright = document.querySelector('.copyright');
    if (copyright) {
        copyright.textContent = copyright.textContent.replace('%year%', new Date().getFullYear());
    }

    // ============================================================
    // API helpers
    // ============================================================

    async function fetchConfig() {
        try {
            const res = await fetch('/api/config');
            if (res.status === 401) { window.location.href = '/login'; return null; }
            if (!res.ok) throw new Error('Failed to fetch configuration');
            return await res.json();
        } catch (err) {
            console.error('Error fetching config:', err);
            showNotification('Error loading configuration', 'error');
            return null;
        }
    }

    async function fetchStats() {
        try {
            const res = await fetch('/api/stats');
            if (res.status === 401) { window.location.href = '/login'; return null; }
            if (!res.ok) throw new Error('Failed to fetch stats');
            return await res.json();
        } catch (err) {
            console.error('Error fetching stats:', err);
            return null;
        }
    }

    async function fetchPlugins() {
        try {
            const res = await fetch('/api/plugins');
            if (res.status === 401) { window.location.href = '/login'; return { data: [] }; }
            if (!res.ok) throw new Error('Failed to fetch plugins');
            return await res.json();
        } catch (err) {
            console.error(err);
            return { data: [] };
        }
    }

    async function updateBasicConfig(config) {
        try {
            const res = await fetch('/api/config', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(config)
            });
            if (res.status === 401) { window.location.href = '/login'; return null; }
            if (!res.ok) {
                const err = await res.json();
                throw new Error(err.error || 'Failed to update configuration');
            }
            return await res.json();
        } catch (err) {
            console.error('Error updating config:', err);
            showNotification(err.message, 'error');
            return null;
        }
    }

    async function apiAddPath(path) {
        const res = await fetch('/api/protected-paths', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path })
        });
        if (res.status === 401) { window.location.href = '/login'; return; }
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Failed to add path');
        return data;
    }

    async function apiDeletePath(path) {
        const res = await fetch(`/api/protected-paths?path=${encodeURIComponent(path)}`, {
            method: 'DELETE'
        });
        if (res.status === 401) { window.location.href = '/login'; return; }
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Failed to delete path');
        return data;
    }

    async function fetchAllowlist() {
        const res = await fetch('/api/command-allowlist');
        if (res.status === 401) { window.location.href = '/login'; return []; }
        const data = await res.json();
        return data.data || [];
    }

    async function apiAddAllowlistCommand(cmd) {
        const res = await fetch('/api/command-allowlist', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ command: cmd })
        });
        if (res.status === 401) { window.location.href = '/login'; return; }
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Failed to add command');
        return data;
    }

    async function apiDeleteAllowlistCommand(cmd) {
        const res = await fetch(`/api/command-allowlist?command=${encodeURIComponent(cmd)}`, {
            method: 'DELETE'
        });
        if (res.status === 401) { window.location.href = '/login'; return; }
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Failed to delete command');
        return data;
    }

    async function apiAddRule(input) {
        const res = await fetch('/api/command-rules', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(input)
        });
        if (res.status === 401) { window.location.href = '/login'; return; }
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Failed to add rule');
        return data;
    }

    async function apiPatchRule(id, patch) {
        const res = await fetch(`/api/command-rules/${id}`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(patch)
        });
        if (res.status === 401) { window.location.href = '/login'; return; }
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Failed to update rule');
        return data;
    }

    async function apiDeleteRule(id) {
        const res = await fetch(`/api/command-rules/${id}`, { method: 'DELETE' });
        if (res.status === 401) { window.location.href = '/login'; return; }
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Failed to delete rule');
        return data;
    }

    // ============================================================
    // UI helpers
    // ============================================================

    function showNotification(message, type = 'success') {
        if (type === 'error') Toast.error(message);
        else if (type === 'warning') Toast.warning(message);
        else Toast.success(message);
    }

    function updateStatus(config) {
        const dot = document.getElementById('status-indicator');
        const text = document.getElementById('status-text');
        if (!config || !config.basic) {
            if (dot) dot.className = 'status-dot';
            if (text) text.textContent = 'ERROR LOADING STATUS';
            return;
        }
        if (dot) dot.className = 'status-dot status-active';
        if (text) text.textContent = 'SYSTEM ACTIVE';
    }

    function updateStats(stats) {
        const el = document.getElementById('log-count');
        if (el) el.textContent = stats.protection_count;
    }

    async function updateEnabledPluginsCount() {
        const data = await fetchPlugins();
        const enabled = data.data.filter(p => p.enabled !== false).length;
        const el = document.getElementById('enabled-plugins-count');
        if (el) el.textContent = enabled;
    }

    function setModeSelectValue(mode) {
        const select = document.getElementById('mode-select');
        if (!select) return;
        const modeLower = mode ? mode.toLowerCase() : 'permissive';
        const option = Array.from(select.options).find(o => o.value.toLowerCase() === modeLower);
        select.value = option ? option.value : 'permissive';
    }

    function escapeHtml(str) {
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    function escapeAttr(str) {
        return String(str).replace(/"/g, '&quot;');
    }

    // ============================================================
    // Protected Paths rendering (with inline add row)
    // ============================================================

    function renderProtectedPaths(paths) {
        const tbody = document.getElementById('protectedPathsBody');
        if (!tbody) return;
        tbody.innerHTML = '';

        paths.forEach((path, index) => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td class="number-cell">${index + 1}.</td>
                <td class="path-cell">
                    <input type="text" class="path-input confirmed font-mono" value="${escapeHtml(path)}" readonly>
                </td>
                <td class="action-cell">
                    <button class="action-btn remove-btn btn-sm" data-path="${escapeAttr(path)}">Remove</button>
                </td>
            `;
            row.querySelector('.remove-btn').addEventListener('click', async function () {
                try {
                    const path = this.dataset.path;
                    await apiDeletePath(path);
                    currentPaths = currentPaths.filter(p => p !== path);
                    renderProtectedPaths(currentPaths);
                    showNotification(`Path "${path}" removed`, 'success');
                } catch (err) {
                    showNotification(err.message, 'error');
                }
            });
            tbody.appendChild(row);
        });

        const emptyRow = document.createElement('tr');
        emptyRow.innerHTML = `
            <td class="number-cell">${paths.length + 1}.</td>
            <td class="path-cell">
                <input type="text" class="path-input font-mono" placeholder="e.g., /var/www/html/secure">
            </td>
            <td class="action-cell">
                <button class="action-btn add-btn btn-sm">Add Rule</button>
            </td>
        `;

        const input = emptyRow.querySelector('.path-input');
        const addBtn = emptyRow.querySelector('.add-btn');

        addBtn.addEventListener('click', async () => {
            const path = input.value.trim();
            if (!path) {
                showNotification('Path cannot be empty', 'error');
                return;
            }
            try {
                await apiAddPath(path);
                currentPaths.push(path);
                renderProtectedPaths(currentPaths);
                showNotification(`Path "${path}" added`, 'success');
            } catch (err) {
                showNotification(err.message, 'error');
            }
        });

        input.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') addBtn.click();
        });

        tbody.appendChild(emptyRow);
    }

    // ============================================================
    // Command Allowlist rendering
    // ============================================================

    function renderAllowlist(commands) {
        const tbody = document.getElementById('allowlistBody');
        if (!tbody) return;
        tbody.innerHTML = '';

        commands.forEach((cmd, index) => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td class="number-cell">${index + 1}.</td>
                <td>
                    <input type="text" class="font-mono" value="${escapeHtml(cmd)}" readonly>
                </td>
                <td class="action-cell">
                    <button class="action-btn remove-btn btn-sm" data-command="${escapeAttr(cmd)}">Remove</button>
                </td>
            `;
            row.querySelector('.remove-btn').addEventListener('click', async function () {
                const command = this.dataset.command;
                try {
                    await apiDeleteAllowlistCommand(command);
                    currentAllowlist = currentAllowlist.filter(c => c !== command);
                    renderAllowlist(currentAllowlist);
                    showNotification(`Command "${command}" removed from allowlist`, 'success');
                } catch (err) {
                    showNotification(err.message, 'error');
                }
            });
            tbody.appendChild(row);
        });

        const emptyRow = document.createElement('tr');
        emptyRow.innerHTML = `
            <td class="number-cell">${commands.length + 1}.</td>
            <td>
                <input type="text" class="font-mono" placeholder="e.g., rm" id="new-allowlist-input">
            </td>
            <td class="action-cell">
                <button class="action-btn add-btn btn-sm" id="add-allowlist-btn">Add Command</button>
            </td>
        `;

        tbody.appendChild(emptyRow);

        const input = document.getElementById('new-allowlist-input');
        const addBtn = document.getElementById('add-allowlist-btn');

        addBtn.addEventListener('click', async () => {
            const cmd = input.value.trim();
            if (!cmd) {
                showNotification('Command cannot be empty', 'error');
                return;
            }
            try {
                await apiAddAllowlistCommand(cmd);
                currentAllowlist.push(cmd);
                renderAllowlist(currentAllowlist);
                showNotification(`Command "${cmd}" added to allowlist`, 'success');
            } catch (err) {
                showNotification(err.message, 'error');
            }
        });

        input.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') addBtn.click();
        });
    }

    // ============================================================
    // Command Rules rendering (with inline add row)
    // ============================================================

    function renderCommandRules(rules) {
        const tbody = document.getElementById('commandRulesBody');
        if (!tbody) return;
        tbody.innerHTML = '';

        rules.forEach((rule, index) => {
            const isBlock = !rule.action?.replace;
            const replaceVal = rule.action?.replace ?? '';
            const enabled = rule.enabled !== false;

            const row = document.createElement('tr');
            row.dataset.ruleId = rule.id;
            row.innerHTML = `
            <td class="number-cell">${index + 1}</td>
            <td>
                <input type="text" class="rule-name-input font-mono" value="${escapeHtml(rule.name || '')}" readonly>
            </td>
            <td>
                <input type="text" class="original-input font-mono" value="${escapeHtml(rule.pattern)}" readonly>
            </td>
            <td class="arrow-cell font-mono">&gt;</td>
            <td>
                <input type="text" class="replace-input font-mono" value="${escapeHtml(isBlock ? '' : replaceVal)}" readonly>
            </td>
            <td style="text-align: center;">
                <label class="toggle-switch">
                    <input type="checkbox" class="rule-enabled-toggle" ${enabled ? 'checked' : ''}>
                    <span class="toggle-slider"></span>
                </label>
            </td>
            <td class="action-cell">
                <button class="action-btn remove-btn btn-sm">Remove</button>
            </td>
        `;

            const toggle = row.querySelector('.rule-enabled-toggle');
            toggle.addEventListener('change', async function () {
                try {
                    const newEnabled = this.checked;
                    await apiPatchRule(rule.id, { enabled: newEnabled });
                    rule.enabled = newEnabled;
                    const ruleName = rule.name || rule.id;
                    showNotification(`Rule "${ruleName}" ${newEnabled ? 'enabled' : 'disabled'}`, 'success');
                } catch (err) {
                    this.checked = !this.checked;
                    showNotification(err.message, 'error');
                }
            });

            row.querySelector('.remove-btn').addEventListener('click', async function () {
                try {
                    const ruleId = rule.id;
                    const ruleName = rule.name || ruleId;
                    await apiDeleteRule(ruleId);
                    currentRules = currentRules.filter(r => r.id !== ruleId);
                    renderCommandRules(currentRules);
                    showNotification(`Rule "${ruleName}" deleted`, 'success');
                } catch (err) {
                    showNotification(err.message, 'error');
                }
            });

            tbody.appendChild(row);
        });

        const emptyRow = document.createElement('tr');
        emptyRow.classList.add('rule-new-row');
        emptyRow.innerHTML = `
        <td class="number-cell">${rules.length + 1}</td>
        <td>
            <input type="text" class="rule-name-input font-mono" placeholder="Rule name (optional)">
        </td>
        <td>
            <input type="text" class="original-input font-mono" placeholder="Original command *">
            <div class="error-message" style="display: none; color: #e74c3c; font-size: 0.8rem;">Pattern cannot be empty</div>
        </td>
        <td class="arrow-cell font-mono">&gt;</td>
        <td><input type="text" class="replace-input font-mono" placeholder="Sanitized command"></td>
        <td style="text-align: center;">
            <label class="toggle-switch disabled">
                <input type="checkbox" class="rule-enabled-toggle" checked disabled>
                <span class="toggle-slider"></span>
            </label>
        </td>
        <td class="action-cell">
            <button class="action-btn add-btn btn-sm">Add Rule</button>
        </td>
    `;

        const nameInput = emptyRow.querySelector('.rule-name-input');
        const originalInput = emptyRow.querySelector('.original-input');
        const replaceInput = emptyRow.querySelector('.replace-input');
        const addBtn = emptyRow.querySelector('.add-btn');
        const errorMsg = emptyRow.querySelector('.error-message');

        addBtn.addEventListener('click', async () => {
            const pattern = originalInput.value.trim();
            if (!pattern) {
                originalInput.classList.add('original-required');
                errorMsg.style.display = 'block';
                return;
            }

            const name = nameInput.value.trim();
            const replacement = replaceInput.value.trim();
            const action = replacement ? { replace: replacement } : { block: true };

            const payload = { pattern, action };
            if (name) payload.name = name;

            try {
                const result = await apiAddRule(payload);
                currentRules.push(result.data);
                renderCommandRules(currentRules);
                const ruleName = result.data.name || result.data.id;
                showNotification(`Rule "${ruleName}" added`, 'success');
            } catch (err) {
                showNotification(err.message, 'error');
            }
        });

        originalInput.addEventListener('input', () => {
            originalInput.classList.remove('original-required');
            errorMsg.style.display = 'none';
        });

        [nameInput, originalInput, replaceInput].forEach(input => {
            input.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') addBtn.click();
            });
        });

        tbody.appendChild(emptyRow);
    }

    // ============================================================
    // Rules page initialization
    // ============================================================

    function initRulesPage() {
        fetchConfig().then(config => {
            if (!config) return;
            currentPaths = config.protected_paths || [];
            currentAllowlist = config.command_allowlist || [];
            currentRules = config.command_rules || [];
            renderProtectedPaths(currentPaths);
            renderAllowlist(currentAllowlist);
            renderCommandRules(currentRules);
        });
    }

    // ============================================================
    // Dashboard
    // ============================================================

    async function initDashboard() {
        currentConfig = await fetchConfig();
        if (currentConfig) {
            updateStatus(currentConfig);
            setModeSelectValue(currentConfig.basic?.mode);
        }

        const stats = await fetchStats();
        if (stats) updateStats(stats);
        await updateEnabledPluginsCount();

        const modeSelect = document.getElementById('mode-select');
        if (modeSelect) {
            modeSelect.addEventListener('change', async function () {
                const newMode = this.value;
                const result = await updateBasicConfig({ basic: { mode: newMode } });
                if (result) {
                    showNotification('Protection mode updated');
                    currentConfig = await fetchConfig();
                    updateStatus(currentConfig);
                } else {
                    setModeSelectValue(currentConfig?.basic?.mode);
                }
            });
        }
    }

    // ============================================================
    // Logs page
    // ============================================================

    function initLogsPage() {
        const logOutput = document.getElementById('log-output');
        const filterLevel = document.getElementById('filter-level');
        const filterUser = document.getElementById('filter-user');
        const filterCommand = document.getElementById('filter-command');
        const filterTimeStart = document.getElementById('filter-time-start');
        const filterTimeEnd = document.getElementById('filter-time-end');
        const clearFiltersBtn = document.getElementById('clear-filters');

        if (!logOutput) return;

        let logLines = [];
        const MAX_LOG_LINES = 5000;
        const logStreamStartTime = new Date();

        const eventSource = new EventSource('/api/logs');

        function extractLogDate(line) {
            const match = line.match(/^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]/);
            if (!match) return null;
            return new Date(match[1].replace(' ', 'T'));
        }

        function renderFilteredLogs() {
            const levelFilter = filterLevel?.value || '';
            const userFilter = (filterUser?.value || '').trim().toLowerCase();
            const cmdFilter = (filterCommand?.value || '').trim().toLowerCase();
            const startStr = filterTimeStart?.value;
            const endStr = filterTimeEnd?.value;

            let startDate = startStr ? new Date(startStr) : null;
            let endDate = endStr ? new Date(endStr) : null;
            if (startDate && isNaN(startDate)) startDate = null;
            if (endDate && isNaN(endDate)) endDate = null;

            const filtered = logLines.filter(line => {
                if (levelFilter && !line.includes(levelFilter)) return false;
                if (userFilter && !line.toLowerCase().includes(userFilter)) return false;
                if (cmdFilter && !line.toLowerCase().includes(cmdFilter)) return false;
                if (startDate || endDate) {
                    const logDate = extractLogDate(line);
                    if (!logDate) return false;
                    if (startDate && logDate < startDate) return false;
                    if (endDate && logDate > endDate) return false;
                }
                return true;
            });

            logOutput.textContent = [...filtered].reverse().join('\n');
            logOutput.scrollTop = 0;
        }

        function addLogLine(line) {
            logLines.push(line);
            if (logLines.length > MAX_LOG_LINES) logLines.shift();
            renderFilteredLogs();

            const logDate = extractLogDate(line);
            if (logDate && logDate >= logStreamStartTime) {
                if (typeof showLogNotification === 'function') showLogNotification(line);
                playNotificationSound();
            }
        }

        eventSource.addEventListener('log', e => { if (e.data) addLogLine(e.data); });
        eventSource.addEventListener('error', e => { addLogLine('[SYSTEM ERROR] ' + (e.data || 'Connection lost')); });

        if (filterLevel) filterLevel.addEventListener('change', renderFilteredLogs);
        if (filterUser) filterUser.addEventListener('input', renderFilteredLogs);
        if (filterCommand) filterCommand.addEventListener('input', renderFilteredLogs);
        if (filterTimeStart) filterTimeStart.addEventListener('change', renderFilteredLogs);
        if (filterTimeEnd) filterTimeEnd.addEventListener('change', renderFilteredLogs);

        if (clearFiltersBtn) {
            clearFiltersBtn.addEventListener('click', function () {
                if (filterLevel) filterLevel.value = '';
                if (filterUser) filterUser.value = '';
                if (filterCommand) filterCommand.value = '';
                if (filterTimeStart) filterTimeStart.value = '';
                if (filterTimeEnd) filterTimeEnd.value = '';
                renderFilteredLogs();
            });
        }

        window.addEventListener('beforeunload', () => eventSource.close());
    }

    // ============================================================
    // Plugin Management Page
    // ============================================================

    function renderPluginCards(plugins) {
        const container = document.getElementById('plugin-list');
        const countBadge = document.getElementById('plugin-count');
        if (!container) return;

        container.innerHTML = '';
        if (plugins.length === 0) {
            container.innerHTML = '<div class="empty-state">No plugins installed. Install one to extend functionality.</div>';
            if (countBadge) countBadge.textContent = '0 Loaded';
            return;
        }

        if (countBadge) countBadge.textContent = `${plugins.length} Loaded`;

        plugins.forEach(p => {
            const card = document.createElement('div');
            card.className = 'plugin-card';
            card.dataset.id = p.id;

            const enabled = p.enabled !== false;
            const statusClass = enabled ? 'enabled' : 'disabled';
            const statusText = enabled ? 'ENABLED' : 'DISABLED';

            card.innerHTML = `
            <div class="plugin-card-header">
                <div class="plugin-icon">🔌</div>
                <div class="plugin-info">
                    <h5>${escapeHtml(p.name)}</h5>
                    <span class="plugin-version">v${escapeHtml(p.version)}</span>
                </div>
            </div>
            <div class="plugin-description">${escapeHtml(p.description || 'No description')}</div>
            <div class="plugin-meta">
                <div>Type: ${escapeHtml(p.type)} | Author: ${escapeHtml(p.author)}</div>
            </div>
            <div class="plugin-actions">
                <div class="plugin-status">
                    <span class="status-badge ${statusClass}">${statusText}</span>
                </div>
                <div style="display: flex; gap: 8px;">
                    <label class="toggle-switch">
                        <input type="checkbox" class="plugin-toggle" ${enabled ? 'checked' : ''}>
                        <span class="toggle-slider"></span>
                    </label>
                    <button class="action-btn remove-btn btn-sm plugin-delete">Delete</button>
                </div>
            </div>
        `;

            const toggle = card.querySelector('.plugin-toggle');
            toggle.addEventListener('change', async (e) => {
                const newEnabled = e.target.checked;
                try {
                    const res = await fetch('/api/plugins/toggle', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ id: p.id, enabled: newEnabled })
                    });
                    if (res.status === 401) { window.location.href = '/login'; return; }
                    if (!res.ok) throw new Error('Toggle failed');
                    Toast.success(`Plugin ${newEnabled ? 'enabled' : 'disabled'}`);
                    const badge = card.querySelector('.status-badge');
                    badge.className = `status-badge ${newEnabled ? 'enabled' : 'disabled'}`;
                    badge.textContent = newEnabled ? 'ENABLED' : 'DISABLED';
                    p.enabled = newEnabled;
                    updateEnabledPluginsCount(); // refresh dashboard count
                } catch (err) {
                    Toast.error(err.message);
                    e.target.checked = !newEnabled;
                }
            });

            const deleteBtn = card.querySelector('.plugin-delete');
            deleteBtn.addEventListener('click', async () => {
                if (!confirm(`Delete plugin "${p.name}"?`)) return;
                try {
                    const res = await fetch(`/api/plugins/${encodeURIComponent(p.id)}`, {
                        method: 'DELETE'
                    });
                    if (res.status === 401) { window.location.href = '/login'; return; }
                    if (!res.ok) throw new Error('Delete failed');
                    Toast.success('Plugin deleted');
                    initPluginPage();
                    updateEnabledPluginsCount();
                } catch (err) {
                    Toast.error(err.message);
                }
            });

            container.appendChild(card);
        });
    }

    async function initPluginPage() {
        const data = await fetchPlugins();
        renderPluginCards(data.data);
    }

    function initPluginInstall() {
        const form = document.getElementById('install-plugin-form');
        if (!form) return;
        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            const fileInput = document.getElementById('plugin-file');
            const file = fileInput.files[0];
            if (!file) {
                Toast.error('Please select a plugin package');
                return;
            }

            const formData = new FormData();
            formData.append('plugin', file);

            try {
                const res = await fetch('/api/plugins/install', {
                    method: 'POST',
                    body: formData
                });
                if (res.status === 401) { window.location.href = '/login'; return; }
                const data = await res.json();
                if (!res.ok) {
                    throw new Error(data.error || 'Installation failed');
                }
                Toast.success(`Plugin "${data.data.name}" installed successfully`);
                fileInput.value = '';
                initPluginPage();
                updateEnabledPluginsCount();
            } catch (err) {
                Toast.error(err.message);
            }
        });
    }

    function initPluginManagement() {
        const pluginPage = document.getElementById('plugin');
        if (!pluginPage) return;

        const observer = new MutationObserver(mutations => {
            mutations.forEach(m => {
                if (m.attributeName === 'class' && pluginPage.classList.contains('active')) {
                    initPluginPage();
                }
            });
        });
        observer.observe(pluginPage, { attributes: true });

        const refreshBtn = document.getElementById('refresh-plugins-btn');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', initPluginPage);
        }

        initPluginInstall();

        if (pluginPage.classList.contains('active')) {
            initPluginPage();
        }
    }

    // ============================================================
    // Utilities
    // ============================================================

    function playNotificationSound() {
        try {
            const audio = new Audio('/msg.mp3');
            audio.volume = 0.5;
            audio.play().catch(() => { });
        } catch (_) { }
    }

    if (typeof showLogNotification === 'undefined') {
        window.showLogNotification = function (line) {
            const match = line.match(/\[(.*?)\] (.*?) - (.*)/);
            if (match) {
                Toast.info(`[${match[1]}] ${match[3]}`, 3000);
            }
        };
    }

    // ============================================================
    // Periodic stats refresh
    // ============================================================

    setInterval(async () => {
        const dashboard = document.getElementById('dashboard');
        if (dashboard && dashboard.classList.contains('active')) {
            const stats = await fetchStats();
            if (stats) updateStats(stats);
            await updateEnabledPluginsCount();
        }
    }, 5000);

    // ============================================================
    // Toast notification manager
    // ============================================================
    const Toast = (() => {
        const container = document.getElementById('toast-container');

        if (!container) {
            console.warn('Toast container not found');
        }

        function createToast(message, type = 'info', duration = 5000) {
            const toast = document.createElement('div');
            toast.className = `toast ${type}`;

            const icon = document.createElement('div');
            icon.className = 'toast-icon';
            if (type === 'success') icon.textContent = '✓';
            else if (type === 'error') icon.textContent = '✕';
            else if (type === 'warning') icon.textContent = '⚠';
            else icon.textContent = 'ℹ';

            const content = document.createElement('div');
            content.className = 'toast-content';
            content.textContent = message;

            const closeBtn = document.createElement('button');
            closeBtn.className = 'toast-close';
            closeBtn.innerHTML = '×';
            closeBtn.addEventListener('click', () => removeToast(toast));

            toast.appendChild(icon);
            toast.appendChild(content);
            toast.appendChild(closeBtn);

            container.appendChild(toast);

            const timeoutId = setTimeout(() => removeToast(toast), duration);
            toast.dataset.timeoutId = timeoutId;

            return toast;
        }

        function removeToast(toast) {
            if (!toast || !toast.parentNode) return;

            clearTimeout(parseInt(toast.dataset.timeoutId));
            toast.classList.add('removing');

            setTimeout(() => {
                if (toast.parentNode) {
                    toast.parentNode.removeChild(toast);
                }
            }, 300);
        }

        return {
            success: (msg, duration) => createToast(msg, 'success', duration),
            error: (msg, duration) => createToast(msg, 'error', duration),
            warning: (msg, duration) => createToast(msg, 'warning', duration),
            info: (msg, duration) => createToast(msg, 'info', duration)
        };
    })();

    // ============================================================
    // Boot
    // ============================================================

    initDashboard();
    initRulesPage();
    initLogsPage();
    initPluginManagement();
});