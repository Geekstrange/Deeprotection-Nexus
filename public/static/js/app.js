document.addEventListener('DOMContentLoaded', function() {
    // 全局变量
    let currentConfig = null;

    // Navigation
    document.querySelectorAll('nav a').forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            document.querySelectorAll('.page').forEach(page => {
                page.classList.remove('active');
            });
            document.querySelectorAll('nav a').forEach(a => {
                a.classList.remove('active');
            });
            this.classList.add('active');
            document.getElementById(this.dataset.page).classList.add('active');
        });
    });

    // Copyright info
    document.querySelector('.copyright').textContent = document.querySelector('.copyright').textContent.replace('%year%', new Date().getFullYear());

    // API functions
    async function fetchConfig() {
        try {
            const response = await fetch('/api/config');

            if (!response.ok) {
                throw new Error('Failed to fetch configuration');
            }

            return await response.json();
        } catch (error) {
            console.error('Error fetching config:', error);
            showNotification('Error loading configuration', 'error');
            return null;
        }
    }

    async function fetchStats() {
        try {
            const response = await fetch('/api/stats');

            if (!response.ok) {
                throw new Error('Failed to fetch stats');
            }

            return await response.json();
        } catch (error) {
            console.error('Error fetching stats:', error);
            return null;
        }
    }

    async function fetchLanguages() {
        try {
            const response = await fetch('/api/languages');

            if (!response.ok) {
                throw new Error('Failed to fetch languages');
            }

            return await response.json();
        } catch (error) {
            console.error('Error fetching languages:', error);
            showNotification('Error loading languages', 'error');
            return [];
        }
    }

    async function updateConfig(config) {
        try {
            const response = await fetch('/api/config', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(config)
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Failed to update configuration');
            }

            return await response.json();
        } catch (error) {
            console.error('Error updating config:', error);
            showNotification(error.message, 'error');
            return null;
        }
    }

    async function reloadService() {
        try {
            const response = await fetch('/api/reload', {
                method: 'POST'
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Failed to reload service');
            }

            return await response.json();
        } catch (error) {
            console.error('Error reloading service:', error);
            showNotification(error.message, 'error');
            return null;
        }
    }

    async function restartService() {
        try {
            const response = await fetch('/api/restart', {
                method: 'POST'
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Failed to restart service');
            }

            return await response.json();
        } catch (error) {
            console.error('Error restarting service:', error);
            showNotification(error.message, 'error');
            return null;
        }
    }

    async function executeCommand(command) {
        try {
            const response = await fetch('/api/command', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    command
                })
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Command execution failed');
            }

            return await response.json();
        } catch (error) {
            console.error('Error executing command:', error);
            showNotification(error.message, 'error');
            return null;
        }
    }

    // UI functions
    function updateStatus(config) {
        const statusIndicator = document.getElementById('status-indicator');
        const statusText = document.getElementById('status-text');
        const protectionStatus = document.getElementById('protection-status');
        const expirationStatus = document.getElementById('expiration-status');
        const lastUpdated = document.getElementById('last-updated');
        const updateMode = document.getElementById('update-mode');
        const protectionMode = document.getElementById('protection-mode');

        if (!config || !config.basic) {
            statusIndicator.className = 'status-dot';
            statusText.textContent = 'ERROR LOADING STATUS';
            return;
        }

        const basic = config.basic;

        if (basic.disable === 'false') {
            statusIndicator.className = 'status-dot status-active';
            statusText.textContent = 'SYSTEM ACTIVE';
            protectionStatus.textContent = 'Enabled';
            protectionStatus.style.color = '#10b981'; // 新深色主题绿色
        } else {
            statusIndicator.className = 'status-dot';
            statusText.textContent = 'SYSTEM DISABLED';
            protectionStatus.textContent = 'Disabled';
            protectionStatus.style.color = '#ef4444'; // 新深色主题红色
        }

        lastUpdated.textContent = new Date(parseInt(basic.timestamp) * 1000).toLocaleString();
        updateMode.textContent = basic.update === 'enable' ? 'Enabled' : 'Disabled';
        protectionMode.textContent = basic.mode || 'Permissive';
    }

    function updateStats(stats) {
        const protectionCount = document.getElementById('protection-count');
        const expirationStatus = document.getElementById('expiration-status');

        protectionCount.textContent = stats.protection_count;

        if (stats.remaining_time) {
            expirationStatus.textContent = stats.remaining_time;
            expirationStatus.style.color = '#ef4444';
        } else {
            expirationStatus.textContent = currentConfig.basic.expire_hours + ' hours (default)';
            expirationStatus.style.color = '#10b981';
        }
    }

    function loadConfigToForm(config) {
        if (!config || !config.basic) return;

        const basic = config.basic;

        document.getElementById('language').value = basic.language || '';
        document.getElementById('disable').value = basic.disable || 'false';
        document.getElementById('expire_hours').value = basic.expire_hours || '24';
        document.getElementById('update').value = basic.update || 'enable';
        document.getElementById('mode').value = basic.mode || 'Permissive';
        document.getElementById('web_ip').value = basic.web_ip || '127.0.0.1';
        document.getElementById('web_port').value = basic.web_port || '8080';
    }

    function loadRulesToForm(config) {
        if (!config) return;

        // 清空现有表格数据
        document.getElementById('protectedPathsBody').innerHTML = '';
        document.getElementById('commandRulesBody').innerHTML = '';

        // 加载保护路径
        if (config.protected_paths) {
            config.protected_paths.forEach((path, index) => {
                if (!path) return;

                const row = document.createElement('tr');
                row.innerHTML = `
                <td class="number-cell">${index + 1}.</td>
                <td class="path-cell">
                    <input type="text" class="path-input confirmed font-mono" value="${path}" readonly>
                </td>
                <td class="action-cell">
                    <button class="action-btn remove-btn btn-sm">Remove</button>
                </td>
            `;
                document.getElementById('protectedPathsBody').appendChild(row);
            });
        }

        // 添加一个空行用于新输入
        const emptyPathRow = document.createElement('tr');
        emptyPathRow.innerHTML = `
        <td class="number-cell">${(config.protected_paths?.length || 0) + 1}.</td>
        <td class="path-cell">
            <input type="text" class="path-input font-mono" placeholder="Enter a path rule">
        </td>
        <td class="action-cell">
            <button class="action-btn add-btn btn-sm">Add Rule</button>
        </td>
    `;
        document.getElementById('protectedPathsBody').appendChild(emptyPathRow);
        initProtectedPathsTable();

        // 加载命令拦截规则
        if (config.command_rules) {
            config.command_rules.forEach((rule, index) => {
                if (!rule) return;

                const [original, replacement] = rule.split('>').map(s => s.trim());

                const row = document.createElement('tr');
                row.classList.add('confirmed');
                row.innerHTML = `
                <td class="number-cell">${index + 1}</td>
                <td>
                    <input type="text" class="original-input font-mono" value="${original || ''}" readonly>
                </td>
                <td class="arrow-cell font-mono">&gt;</td>
                <td><input type="text" class="replace-input font-mono" value="${replacement || ''}" readonly></td>
                <td class="action-cell">
                    <button class="action-btn remove-btn btn-sm">Remove</button>
                </td>
            `;
                document.getElementById('commandRulesBody').appendChild(row);
            });
        }

        // 添加一个空行用于新输入
        const emptyCommandRow = document.createElement('tr');
        emptyCommandRow.innerHTML = `
        <td class="number-cell">${(config.command_rules?.length || 0) + 1}</td>
        <td>
            <input type="text" class="original-input font-mono" placeholder="Original command">
            <div class="error-message">Vector cannot be empty</div>
        </td>
        <td class="arrow-cell font-mono">&gt;</td>
        <td><input type="text" class="replace-input font-mono" placeholder="Sanitized command"></td>
        <td class="action-cell">
            <button class="action-btn add-btn btn-sm">Add Rule</button>
        </td>
    `;
        document.getElementById('commandRulesBody').appendChild(emptyCommandRow);
        initCommandRulesTable();
    }

    function populateLanguageSelect(languages) {
        const select = document.getElementById('language');
        select.innerHTML = '';

        languages.forEach(lang => {
            const option = document.createElement('option');
            option.value = lang.code;
            option.textContent = lang.name;
            select.appendChild(option);
        });

        fetchConfig().then(config => {
            if (config && config.basic && config.basic.language) {
                select.value = config.basic.language;
            }
        });
    }

    function showNotification(message, type = 'success') {
        alert(`${type.toUpperCase()}: ${message}`);
    }

    // Initialize dashboard
    async function initDashboard() {
        currentConfig = await fetchConfig();
        updateStatus(currentConfig);

        const stats = await fetchStats();
        if (stats) {
            updateStats(stats);
        }
    }

    // 配置页面初始化
    function initConfigPage() {
        fetchLanguages().then(languages => {
            populateLanguageSelect(languages);
        });

        fetchConfig().then(config => {
            loadConfigToForm(config);
        });

        document.getElementById('save-config').addEventListener('click', async function() {
            const basic = {
                language: document.getElementById('language').value,
                disable: document.getElementById('disable').value,
                expire_hours: document.getElementById('expire_hours').value,
                update: document.getElementById('update').value,
                mode: document.getElementById('mode').value,
                web_ip: document.getElementById('web_ip').value,
                web_port: document.getElementById('web_port').value
            };

            const configData = {
                basic: basic
            };

            const result = await updateConfig(configData);
            if (result) {
                showNotification('Configuration saved');
                currentConfig = await fetchConfig();
                updateStatus(currentConfig);
            }
        });
    }

    // 规则页面初始化
    function initRulesPage() {
        // 初始化保护路径表格
        initProtectedPathsTable();

        // 初始化命令拦截规则表格
        initCommandRulesTable();

        // 加载配置到表格
        fetchConfig().then(config => {
            if (config) {
                loadRulesToForm(config);
            }
        });

        document.getElementById('save-rules').addEventListener('click', async function() {
            const protectedPaths = getProtectedPaths();
            const commandRules = getCommandRules();

            const configData = {
                protected_paths: protectedPaths,
                command_rules: commandRules
            };

            const result = await updateConfig(configData);
            if (result) {
                showNotification('Rules policies committed successfully');
            }
        });
    }

    // 初始化保护路径表格
    function initProtectedPathsTable() {
        const tableBody = document.getElementById('protectedPathsBody');

        // 重排行号
        function updateRowNumbers() {
            const rows = tableBody.querySelectorAll('tr');
            rows.forEach((row, idx) => {
                const numCell = row.querySelector('.number-cell');
                if (numCell) {
                    numCell.textContent = `${idx + 1}.`;
                }
            });
        }

        // 检查是否有空行 (即等待输入的行)
        function hasEmptyRow() {
            return Array.from(tableBody.querySelectorAll('tr')).some(row => {
                const input = row.querySelector('.path-input');
                const button = row.querySelector('.action-btn');
                return !input.classList.contains('confirmed') &&
                    button.classList.contains('add-btn');
            });
        }

        // 创建新的空行
        function addNewEmptyRow() {
            const newRow = document.createElement('tr');

            const numberCell = document.createElement('td');
            numberCell.className = 'number-cell';
            numberCell.textContent = `${tableBody.querySelectorAll('tr').length + 1}.`;

            const pathCell = document.createElement('td');
            pathCell.className = 'path-cell';
            const input = document.createElement('input');
            input.type = 'text';
            input.className = 'path-input font-mono';
            input.placeholder = 'e.g., /var/www/html/secure';
            pathCell.appendChild(input);

            const actionCell = document.createElement('td');
            actionCell.className = 'action-cell';
            const button = document.createElement('button');
            button.className = 'action-btn add-btn btn-sm';
            button.textContent = 'Add Rule';
            actionCell.appendChild(button);

            newRow.appendChild(numberCell);
            newRow.appendChild(pathCell);
            newRow.appendChild(actionCell);

            tableBody.appendChild(newRow);
            setupRowEvents(newRow);
            updateRowNumbers();
        }

        // 设置行事件处理
        function setupRowEvents(row) {
            const input = row.querySelector('.path-input');
            let button = row.querySelector('.action-btn');

            if (button) {
                const newButton = button.cloneNode(true);
                button.parentNode.replaceChild(newButton, button);
                button = newButton;
            }

            button.addEventListener('click', function() {
                const content = input.value.trim();

                if (button.classList.contains('add-btn')) {
                    if (content) {
                        input.classList.add('confirmed');
                        input.readOnly = true;

                        button.classList.remove('add-btn');
                        button.classList.add('remove-btn');
                        button.textContent = 'Remove';

                        addNewEmptyRow();
                    } else {
                        alert('Please enter a path rule before adding');
                    }
                } else {
                    row.remove();
                    updateRowNumbers();
                    if (!hasEmptyRow()) {
                        addNewEmptyRow();
                    }
                }
            });
        }

        const existingRows = tableBody.querySelectorAll('tr');
        existingRows.forEach(r => {
            setupRowEvents(r);
        });

        if (!hasEmptyRow()) {
            addNewEmptyRow();
        }
    }

    // 初始化命令拦截规则表格
    function initCommandRulesTable() {
        const tableBody = document.getElementById('commandRulesBody');

        function updateRowNumbers() {
            const rows = tableBody.querySelectorAll('tr');
            rows.forEach((row, idx) => {
                const numCell = row.querySelector('.number-cell');
                if (numCell) {
                    numCell.textContent = idx + 1;
                }
            });
        }

        function hasEmptyCommandRow() {
            const rows = tableBody.querySelectorAll('tr');
            for (const row of rows) {
                if (!row.classList.contains('confirmed')) {
                    return true;
                }
            }
            return false;
        }

        function addEmptyRow() {
            const index = tableBody.querySelectorAll('tr').length + 1;
            const row = document.createElement('tr');
            row.innerHTML = `
            <td class="number-cell">${index}</td>
            <td>
                <input type="text" class="original-input font-mono" placeholder="Original command">
                <div class="error-message">Vector cannot be empty</div>
            </td>
            <td class="arrow-cell font-mono">&gt;</td>
            <td><input type="text" class="replace-input font-mono" placeholder="Sanitized command"></td>
            <td class="action-cell">
                <button class="action-btn add-btn btn-sm">Add Rule</button>
            </td>
        `;
            tableBody.appendChild(row);
            setupRowEvents(row);
        }

        function setupRowEvents(row) {
            const originalInput = row.querySelector('.original-input');
            const replaceInput = row.querySelector('.replace-input');
            const button = row.querySelector('button');
            const errorMessage = row.querySelector('.error-message');

            button.addEventListener('click', function() {
                if (button.classList.contains('add-btn')) {
                    if (!originalInput.value.trim()) {
                        originalInput.classList.add('original-required');
                        errorMessage.style.display = 'block';
                        return;
                    }

                    row.classList.add('confirmed');
                    originalInput.readOnly = true;
                    replaceInput.readOnly = true;

                    button.classList.remove('add-btn');
                    button.classList.add('remove-btn');
                    button.textContent = 'Remove';

                    if (!hasEmptyCommandRow()) {
                        addEmptyRow();
                    }
                } else {
                    row.remove();
                    updateRowNumbers();
                    if (!hasEmptyCommandRow()) {
                        addEmptyRow();
                    }
                }
            });

            originalInput.addEventListener('input', function() {
                if (this.value.trim()) {
                    this.classList.remove('original-required');
                    errorMessage.style.display = 'none';
                }
            });
        }

        const existingRows = tableBody.querySelectorAll('tr');
        existingRows.forEach(r => {
            setupRowEvents(r);
        });
        if (!hasEmptyCommandRow()) {
            addEmptyRow();
        }
    }

    function getProtectedPaths() {
        const paths = [];
        const rows = document.querySelectorAll('#protectedPathsBody tr');

        rows.forEach(row => {
            const input = row.querySelector('.path-input');
            if (input && input.value.trim()) {
                paths.push(input.value.trim());
            }
        });

        return paths;
    }

    function getCommandRules() {
        const rules = [];
        const rows = document.querySelectorAll('#commandRulesBody tr');

        rows.forEach(row => {
            const originalInput = row.querySelector('.original-input');
            const replaceInput = row.querySelector('.replace-input');

            if (originalInput && originalInput.value.trim()) {
                const original = originalInput.value.trim();
                const replacement = replaceInput.value.trim();
                const rule = replacement ? `${original} > ${replacement}` : `${original} >`;
                rules.push(rule);
            }
        });

        return rules;
    }

    function playNotificationSound() {
        try {
            const audio = new Audio('/msg.mp3');
            audio.volume = 0.5;
            audio.play().catch(error => {
                console.log('Notification playback failed:', error);
            });
        } catch (error) {
            console.log('Notification initialization failed:', error);
        }
    }

    // 日志页面初始化
    function initLogsPage() {
        const logOutput = document.getElementById('log-output');
        const pauseBtn = document.getElementById('pause-logs');
        const clearBtn = document.getElementById('clear-logs');
        let paused = false;
        const logStreamStartTime = new Date();

        const eventSource = new EventSource('/api/logs');

        eventSource.addEventListener('log', function(event) {
            if (paused) return;
            if (event.data) {
                logOutput.textContent += event.data + '\n';
                logOutput.scrollTop = logOutput.scrollHeight;

                const logTimeStr = event.data.substring(0, 19).trim();
                const logTime = new Date(logTimeStr);

                if (logTime >= logStreamStartTime) {
                    showLogNotification(event.data);
                    playNotificationSound();
                }
            }
        });

        function showLogNotification(message) {
            const container = document.getElementById('notificationContainer');

            if (!container) {
                const containerDiv = document.createElement('div');
                containerDiv.id = 'notificationContainer';
                containerDiv.className = 'notification-container';
                document.body.appendChild(containerDiv);
            }

            const notification = document.createElement('div');
            notification.className = 'notification msg';
            notification.innerHTML = `
        <div class="notification-content">${message}</div>
        <button class="notification-close" onclick="this.parentElement.remove()">×</button>
    `;

            document.getElementById('notificationContainer').appendChild(notification);

            setTimeout(() => {
                notification.style.animation = 'slideIn 0.3s cubic-bezier(0.2, 0.8, 0.2, 1) forwards, fadeOut 0.4s ease forwards 4.6s';
            }, 10);

            setTimeout(() => {
                if (notification.parentNode) {
                    notification.remove();
                }
            }, 5000);
        }

        eventSource.addEventListener('error', function(event) {
            logOutput.textContent += '[SYSTEM ERROR] ' + event.data + '\n';
            logOutput.scrollTop = logOutput.scrollHeight;
        });

        pauseBtn.addEventListener('click', function() {
            paused = !paused;
            this.textContent = paused ? 'Resume Stream' : 'Pause Stream';
            this.classList.toggle('btn-ghost');
            this.classList.toggle('btn-primary');
        });

        clearBtn.addEventListener('click', function() {
            logOutput.textContent = '';
        });
    }

    // 工具页面初始化
    function initToolsPage() {
        const commandInput = document.getElementById('command');
        const executeBtn = document.getElementById('execute-btn');
        const commandOutput = document.getElementById('command-output');
        const toolsPage = document.getElementById('tools');

        function showWarningBanner() {
            if (document.querySelector('.warning-banner')) return;

            const banner = document.createElement('div');
            banner.className = 'warning-banner blinking';
            banner.innerHTML = '<span>[CRITICAL] CAUTION: NATIVE HOST SHELL ENVIRONMENT ACTIVE.</span>';

            document.body.prepend(banner);

            setTimeout(() => {
                if (banner && banner.style.display !== 'none') {
                    banner.style.transition = 'opacity 0.5s ease';
                    banner.style.opacity = '0';
                    setTimeout(() => {
                        if (banner && banner.parentNode) {
                            banner.parentNode.removeChild(banner);
                        }
                    }, 500);
                }
            }, 5000);
        }

        const observer = new MutationObserver((mutations) => {
            mutations.forEach(mutation => {
                if (mutation.attributeName === 'class') {
                    if (toolsPage.classList.contains('active')) {
                        showWarningBanner();
                    }
                }
            });
        });

        observer.observe(toolsPage, {
            attributes: true
        });

        if (toolsPage.classList.contains('active')) {
            showWarningBanner();
        }

        executeBtn.addEventListener('click', async function() {
            if (!commandInput.value.trim()) return;
            
            commandOutput.textContent = 'Executing...';
            const result = await executeCommand(commandInput.value);
            if (result) {
                commandOutput.textContent = result.output;
            } else {
                commandOutput.textContent = 'Execution failed or timeout.';
            }
        });

        commandInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                executeBtn.click();
            }
        });
    }

    // 定期刷新仪表盘
    setInterval(async () => {
        if (document.getElementById('dashboard').classList.contains('active')) {
            const stats = await fetchStats();
            if (stats) {
                updateStats(stats);
            }
        }
    }, 5000);

    // 初始化所有页面
    initDashboard();
    initConfigPage();
    initRulesPage();
    initLogsPage();
    initToolsPage();

    // 操作按钮
    document.getElementById('reload-btn').addEventListener('click', async function() {
        const result = await reloadService();
        if (result) {
            showNotification('Engine configuration reloaded successfully');
            initDashboard();
        }
    });

    document.getElementById('restart-btn').addEventListener('click', async function() {
        if(confirm("WARNING: This will momentarily interrupt protection services. Proceed?")) {
            const result = await restartService();
            if (result) {
                showNotification('Protection service restarted');
                initDashboard();
            }
        }
    });
});