// PyShield Dashboard JavaScript
let charts = {};
let activityData = [];
let authHeaders = {};

// Initialize dashboard
document.addEventListener('DOMContentLoaded', function() {
    // Setup authentication
    setupAuth();
    
    // Initialize charts
    initializeCharts();
    
    // Setup settings navigation
    setupSettingsNavigation();
    
    // Start data refresh
    refreshData();
    refreshProxyData();
    setInterval(refreshData, 5000); // Refresh every 5 seconds
    setInterval(refreshProxyData, 3000); // Refresh proxy data every 3 seconds
    
    // Setup form handlers
    setupFormHandlers();
});

function setupAuth() {
    // Get auth from session storage or prompt
    let credentials = sessionStorage.getItem('pyshield_auth');
    if (!credentials) {
        const username = prompt('Username:', 'admin');
        const password = prompt('Password:', 'admin');
        credentials = btoa(username + ':' + password);
        sessionStorage.setItem('pyshield_auth', credentials);
    }
    
    authHeaders = {
        'Authorization': 'Basic ' + credentials,
        'Content-Type': 'application/json'
    };
}

function initializeCharts() {
    // Blocked IPs Chart
    const ipCtx = document.getElementById('blockedIpsChart').getContext('2d');
    charts.blockedIps = new Chart(ipCtx, {
        type: 'doughnut',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: [
                    '#ff6b6b', '#4ecdc4', '#45b7d1', '#96ceb4', '#feca57',
                    '#ff9ff3', '#54a0ff', '#5f27cd', '#00d2d3', '#ff9f43'
                ]
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom'
                }
            }
        }
    });

    // Attack Types Chart
    const attackCtx = document.getElementById('attackTypesChart').getContext('2d');
    charts.attackTypes = new Chart(attackCtx, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Attack Count',
                data: [],
                backgroundColor: '#ff6b6b',
                borderColor: '#ee5a52',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });

    // Timeline Chart
    const timelineCtx = document.getElementById('timelineChart').getContext('2d');
    charts.timeline = new Chart(timelineCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Blocked Requests',
                data: [],
                borderColor: '#4ecdc4',
                backgroundColor: 'rgba(78, 205, 196, 0.1)',
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
}

function setupSettingsNavigation() {
    document.querySelectorAll('#settingsSidebar .list-group-item').forEach(item => {
        item.addEventListener('click', function(e) {
            e.preventDefault();
            
            // Update active state
            document.querySelectorAll('#settingsSidebar .list-group-item').forEach(i => i.classList.remove('active'));
            this.classList.add('active');
            
            // Show corresponding section
            const section = this.dataset.section;
            document.querySelectorAll('.settings-section').forEach(s => s.classList.remove('active'));
            document.getElementById(section + '-settings').classList.add('active');
        });
    });
}

function setupFormHandlers() {
    // DDoS form
    document.getElementById('ddosForm').addEventListener('submit', function(e) {
        e.preventDefault();
        saveDDoSSettings();
    });
}

async function refreshData() {
    try {
        const response = await fetch('/stats', { headers: authHeaders });
        if (response.ok) {
            const data = await response.json();
            updateStats(data);
            updateCharts(data);
            updateStatus(true);
        } else {
            updateStatus(false);
        }
    } catch (error) {
        console.error('Error fetching data:', error);
        updateStatus(false);
    }
}

function updateStats(data) {
    document.getElementById('blockedIpsCount').textContent = Object.keys(data.blocked_ips || {}).length;
    document.getElementById('blockedUrlsCount').textContent = Object.keys(data.blocked_urls || {}).length;
    document.getElementById('blockedPortsCount').textContent = (data.blocked_ports || []).length;
    document.getElementById('activeAttacksCount').textContent = Object.keys(data.active_attacks || {}).length;
}

function updateCharts(data) {
    // Update blocked IPs chart
    const ips = Object.entries(data.blocked_ips || {});
    charts.blockedIps.data.labels = ips.map(([ip]) => ip);
    charts.blockedIps.data.datasets[0].data = ips.map(([, count]) => count);
    charts.blockedIps.update();

    // Update attack types chart
    const attacks = Object.entries(data.active_attacks || {});
    charts.attackTypes.data.labels = attacks.map(([type]) => type);
    charts.attackTypes.data.datasets[0].data = attacks.map(([, count]) => count);
    charts.attackTypes.update();

    // Update timeline (simulate for now)
    const now = new Date();
    charts.timeline.data.labels.push(now.toLocaleTimeString());
    charts.timeline.data.datasets[0].data.push(Object.keys(data.blocked_ips || {}).length);
    
    // Keep only last 20 points
    if (charts.timeline.data.labels.length > 20) {
        charts.timeline.data.labels.shift();
        charts.timeline.data.datasets[0].data.shift();
    }
    charts.timeline.update();
}

function updateStatus(online) {
    const indicator = document.getElementById('statusIndicator');
    const text = document.getElementById('statusText');
    
    if (online) {
        indicator.className = 'status-indicator status-online';
        text.textContent = 'Online';
    } else {
        indicator.className = 'status-indicator status-offline';
        text.textContent = 'Offline';
    }
}

function addActivity(type, message) {
    const timestamp = new Date().toLocaleString();
    const activity = { timestamp, type, message };
    activityData.unshift(activity);
    
    // Keep only last 100 items
    if (activityData.length > 100) {
        activityData = activityData.slice(0, 100);
    }
    
    updateActivityLog();
}

function updateActivityLog() {
    const log = document.getElementById('activityLog');
    if (activityData.length === 0) {
        log.innerHTML = '<div class="text-muted text-center p-4">No recent activity</div>';
        return;
    }
    
    log.innerHTML = activityData.map(activity => `
        <div class="d-flex justify-content-between align-items-center border-bottom py-2">
            <div>
                <span class="badge bg-${getActivityBadgeColor(activity.type)} me-2">${activity.type}</span>
                ${activity.message}
            </div>
            <small class="text-muted">${activity.timestamp}</small>
        </div>
    `).join('');
}

function getActivityBadgeColor(type) {
    const colors = {
        'block': 'danger',
        'alert': 'warning',
        'config': 'info',
        'system': 'secondary'
    };
    return colors[type] || 'secondary';
}

function clearLog() {
    activityData = [];
    updateActivityLog();
}

// Settings functions
async function saveDDoSSettings() {
    const settings = {
        request_limit: parseInt(document.getElementById('ddosLimit').value),
        window_seconds: parseInt(document.getElementById('ddosWindow').value),
        ban_seconds: parseInt(document.getElementById('ddosBan').value)
    };
    
    try {
        const response = await fetch('/settings/ddos', {
            method: 'POST',
            headers: authHeaders,
            body: JSON.stringify(settings)
        });
        
        if (response.ok) {
            showAlert('DDoS settings saved successfully', 'success');
            addActivity('config', 'DDoS protection settings updated');
        } else {
            showAlert('Failed to save DDoS settings', 'error');
        }
    } catch (error) {
        showAlert('Error saving settings: ' + error.message, 'error');
    }
}

async function addUrl() {
    const url = document.getElementById('urlInput').value.trim();
    if (!url) return;
    
    try {
        const response = await fetch('/urls/add', {
            method: 'POST',
            headers: authHeaders,
            body: JSON.stringify({ items: [url] })
        });
        
        if (response.ok) {
            document.getElementById('urlInput').value = '';
            showAlert('URL added to blacklist', 'success');
            addActivity('block', `Added URL to blacklist: ${url}`);
            loadUrlList();
        } else {
            showAlert('Failed to add URL', 'error');
        }
    } catch (error) {
        showAlert('Error: ' + error.message, 'error');
    }
}

async function removeUrl(url) {
    try {
        const response = await fetch('/urls/remove', {
            method: 'POST',
            headers: authHeaders,
            body: JSON.stringify({ items: [url] })
        });
        
        if (response.ok) {
            showAlert('URL removed from blacklist', 'success');
            addActivity('config', `Removed URL from blacklist: ${url}`);
            loadUrlList();
        } else {
            showAlert('Failed to remove URL', 'error');
        }
    } catch (error) {
        showAlert('Error: ' + error.message, 'error');
    }
}

async function loadUrlList() {
    // This would need an endpoint to list current URLs
    // For now, show placeholder
    document.getElementById('urlList').innerHTML = '<div class="text-muted">URL list endpoint not yet implemented</div>';
}

async function blockPorts() {
    const portsInput = document.getElementById('portInput').value.trim();
    if (!portsInput) return;
    
    const ports = portsInput.split(',').map(p => parseInt(p.trim())).filter(p => !isNaN(p));
    if (ports.length === 0) return;
    
    try {
        const response = await fetch('/ports/block', {
            method: 'POST',
            headers: authHeaders,
            body: JSON.stringify({ ports })
        });
        
        if (response.ok) {
            document.getElementById('portInput').value = '';
            showAlert('Ports blocked successfully', 'success');
            addActivity('block', `Blocked ports: ${ports.join(', ')}`);
            loadPortList();
        } else {
            showAlert('Failed to block ports', 'error');
        }
    } catch (error) {
        showAlert('Error: ' + error.message, 'error');
    }
}

async function unblockPorts() {
    const portsInput = document.getElementById('portInput').value.trim();
    if (!portsInput) return;
    
    const ports = portsInput.split(',').map(p => parseInt(p.trim())).filter(p => !isNaN(p));
    if (ports.length === 0) return;
    
    try {
        const response = await fetch('/ports/unblock', {
            method: 'POST',
            headers: authHeaders,
            body: JSON.stringify({ ports })
        });
        
        if (response.ok) {
            document.getElementById('portInput').value = '';
            showAlert('Ports unblocked successfully', 'success');
            addActivity('config', `Unblocked ports: ${ports.join(', ')}`);
            loadPortList();
        } else {
            showAlert('Failed to unblock ports', 'error');
        }
    } catch (error) {
        showAlert('Error: ' + error.message, 'error');
    }
}

async function loadPortList() {
    try {
        const response = await fetch('/stats', { headers: authHeaders });
        if (response.ok) {
            const data = await response.json();
            const ports = data.blocked_ports || [];
            
            if (ports.length === 0) {
                document.getElementById('portList').innerHTML = '<div class="text-muted">No ports currently blocked</div>';
            } else {
                document.getElementById('portList').innerHTML = ports.map(port => `
                    <span class="badge bg-danger me-2 mb-2">
                        ${port}
                        <button class="btn-close btn-close-white ms-1" onclick="unblockSinglePort(${port})" style="font-size: 0.7em;"></button>
                    </span>
                `).join('');
            }
        }
    } catch (error) {
        console.error('Error loading port list:', error);
    }
}

async function unblockSinglePort(port) {
    try {
        const response = await fetch('/ports/unblock', {
            method: 'POST',
            headers: authHeaders,
            body: JSON.stringify({ ports: [port] })
        });
        
        if (response.ok) {
            showAlert(`Port ${port} unblocked`, 'success');
            addActivity('config', `Unblocked port: ${port}`);
            loadPortList();
        }
    } catch (error) {
        showAlert('Error: ' + error.message, 'error');
    }
}

function testAlert(type) {
    addActivity('system', `Test ${type} alert sent`);
    showAlert(`Test ${type} alert sent (check your ${type} for delivery)`, 'info');
}

function showAlert(message, type) {
    // Simple alert system - could be enhanced with toast notifications
    const alertClass = type === 'success' ? 'alert-success' : type === 'error' ? 'alert-danger' : 'alert-info';
    
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert ${alertClass} alert-dismissible fade show position-fixed`;
    alertDiv.style.cssText = 'top: 20px; right: 20px; z-index: 9999; min-width: 300px;';
    alertDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    document.body.appendChild(alertDiv);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (alertDiv.parentNode) {
            alertDiv.remove();
        }
    }, 5000);
}

// Initialize port list when ports tab is loaded
document.addEventListener('shown.bs.tab', function(e) {
    if (e.target.getAttribute('href') === '#settings') {
        loadPortList();
    } else if (e.target.getAttribute('href') === '#proxy') {
        refreshProxyRequests();
    }
});

// Proxy functionality
async function refreshProxyData() {
    try {
        const response = await fetch('/proxy/stats', { headers: authHeaders });
        if (response.ok) {
            const data = await response.json();
            updateProxyStats(data);
        }
    } catch (error) {
        console.error('Error fetching proxy data:', error);
    }
}

async function refreshProxyRequests() {
    try {
        const response = await fetch('/proxy/requests', { headers: authHeaders });
        if (response.ok) {
            const data = await response.json();
            updateProxyRequests(data.requests || []);
            updateProxyStatus(data.proxy_enabled, data.proxy_port);
        }
    } catch (error) {
        console.error('Error fetching proxy requests:', error);
        updateProxyStatus(false, 8888);
    }
}

function updateProxyStats(data) {
    document.getElementById('totalRequests').textContent = data.total_requests || 0;
    document.getElementById('allowedRequests').textContent = data.allowed_requests || 0;
    document.getElementById('blockedRequests').textContent = data.blocked_requests || 0;
    document.getElementById('blockRate').textContent = (data.block_rate || 0).toFixed(1) + '%';
}

function updateProxyStatus(enabled, port) {
    const indicator = document.getElementById('proxyStatus');
    const text = document.getElementById('proxyStatusText');
    
    if (enabled) {
        indicator.className = 'status-indicator status-online';
        text.textContent = `Proxy Running (Port ${port})`;
    } else {
        indicator.className = 'status-indicator status-offline';
        text.textContent = `Proxy Offline (Configure: 127.0.0.1:${port})`;
    }
}

function updateProxyRequests(requests) {
    const tbody = document.getElementById('proxyRequestsBody');
    
    if (requests.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">No requests yet</td></tr>';
        return;
    }
    
    tbody.innerHTML = requests.reverse().slice(0, 50).map(req => {
        const time = new Date(req.timestamp * 1000).toLocaleTimeString();
        const statusBadge = req.blocked 
            ? `<span class="badge bg-danger">Blocked</span>`
            : `<span class="badge bg-success">Allowed</span>`;
        
        const domain = req.domain || new URL(req.url).hostname;
        const displayUrl = req.url.length > 50 ? req.url.substring(0, 50) + '...' : req.url;
        
        return `
            <tr ${req.blocked ? 'class="table-danger"' : ''}>
                <td>${time}</td>
                <td><span class="badge bg-info">${req.method}</span></td>
                <td>${domain}</td>
                <td title="${req.url}">${displayUrl}</td>
                <td>${statusBadge}${req.blocked ? `<br><small class="text-muted">${req.block_reason}</small>` : ''}</td>
                <td>${req.client_ip}</td>
            </tr>
        `;
    }).join('');
}