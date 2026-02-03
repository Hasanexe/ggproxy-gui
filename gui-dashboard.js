// Dashboard metrics polling and rendering

// Update metrics every 2 seconds
function updateMetrics() {
    fetch('/api/dashboard/metrics')
        .then(response => {
            if (!response.ok) {
                throw new Error('Failed to fetch metrics');
            }
            return response.json();
        })
        .then(data => renderMetrics(data))
        .catch(error => {
            console.error('Error fetching metrics:', error);
            displayMetricsError();
        });
}

// Render metrics on the dashboard
function renderMetrics(data) {
    // Service status badge
    const statusBadge = document.querySelector('.status-badge');
    if (statusBadge) {
        statusBadge.textContent = data.service_status || 'unknown';
        statusBadge.className = 'status-badge status-' + (data.service_status || 'down');
    }

    // Uptime
    const uptimeElement = document.getElementById('uptime');
    if (uptimeElement) {
        uptimeElement.textContent = data.uptime || 'N/A';
    }

    // Active connections
    const activeConnsElement = document.getElementById('active-conns');
    if (activeConnsElement) {
        activeConnsElement.textContent = formatNumber(data.active_connections || 0);
    }

    // Total connections
    const totalConnsElement = document.getElementById('total-conns');
    if (totalConnsElement) {
        totalConnsElement.textContent = formatNumber(data.total_connections || 0);
    }

    // Bandwidth in
    const bandwidthInElement = document.getElementById('bandwidth-in');
    if (bandwidthInElement) {
        const mbps = data.bandwidth?.current_in_mbps || 0;
        bandwidthInElement.textContent = mbps.toFixed(2) + ' Mbps';
    }

    // Bandwidth out
    const bandwidthOutElement = document.getElementById('bandwidth-out');
    if (bandwidthOutElement) {
        const mbps = data.bandwidth?.current_out_mbps || 0;
        bandwidthOutElement.textContent = mbps.toFixed(2) + ' Mbps';
    }

    // CPU usage
    const cpuElement = document.getElementById('cpu-usage');
    if (cpuElement) {
        const cpu = data.cpu_percent || 0;
        cpuElement.textContent = cpu.toFixed(1) + '%';
    }

    // Memory usage
    const memoryElement = document.getElementById('memory-usage');
    if (memoryElement) {
        const bytes = data.memory?.rss_bytes || 0;
        const mb = bytes / 1024 / 1024;
        memoryElement.textContent = mb.toFixed(1) + ' MB';
    }

    // Goroutines
    const goroutinesElement = document.getElementById('goroutines');
    if (goroutinesElement) {
        goroutinesElement.textContent = formatNumber(data.goroutines || 0);
    }

    // Open sockets
    const socketsElement = document.getElementById('open-sockets');
    if (socketsElement) {
        socketsElement.textContent = formatNumber(data.open_sockets || 0);
    }

    // Bytes in/out (for reference)
    const bytesInElement = document.getElementById('bytes-in');
    if (bytesInElement) {
        const bytes = data.bandwidth?.bytes_in || 0;
        bytesInElement.textContent = formatBytes(bytes);
    }

    const bytesOutElement = document.getElementById('bytes-out');
    if (bytesOutElement) {
        const bytes = data.bandwidth?.bytes_out || 0;
        bytesOutElement.textContent = formatBytes(bytes);
    }
}

// Display error message when metrics are unavailable
function displayMetricsError() {
    const elements = [
        'active-conns', 'total-conns', 'bandwidth-in', 'bandwidth-out',
        'cpu-usage', 'memory-usage', 'goroutines', 'open-sockets',
        'bytes-in', 'bytes-out', 'uptime'
    ];

    elements.forEach(id => {
        const element = document.getElementById(id);
        if (element) {
            element.textContent = 'N/A';
        }
    });

    const statusBadge = document.querySelector('.status-badge');
    if (statusBadge) {
        statusBadge.textContent = 'down';
        statusBadge.className = 'status-badge status-down';
    }
}

// Format number with thousands separator
function formatNumber(num) {
    return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

// Format bytes to human-readable format
function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return (bytes / Math.pow(k, i)).toFixed(2) + ' ' + sizes[i];
}

// Initialize dashboard on page load
document.addEventListener('DOMContentLoaded', function() {
    // Initial update
    updateMetrics();
    
    // Set up polling interval (2 seconds)
    setInterval(updateMetrics, 2000);
});
