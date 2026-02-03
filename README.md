# GGProxy GUI

GGProxy GUI is a lightweight SOCKS5/HTTP forward proxy written in Go with an integrated web-based dashboard. It aims for minimal overhead, no caching, no traffic modification, and no filtering.

## Features

- **SOCKS5** or **HTTP** modes (`proxy_mode`).
- IP-based allowlisting via `allowed_ip` (CIDR, IPv4 only).
- Optional authentication (HTTP Basic Auth and SOCKS5 username/password).
- **Web Dashboard**: Real-time monitoring of proxy metrics, connections, and logs.
- **Config Editor**: Manage proxy settings directly from the web interface.
- **Log streaming**: View live proxy logs from the web interface in realtime.

## Installation

Download the latest `.deb` package from [Releases](https://github.com/hasanexe/ggproxy-gui/releases).

Install using:

```bash
sudo dpkg -i ggproxy-gui_<version>.deb
```

### Windows

Download the executable from [Releases](https://github.com/hasanexe/ggproxy-gui/releases) and run it with a config file.

## Configuration

By default, GGProxy reads `/etc/ggproxy.conf` on Linux or `ggproxy.conf` in the current directory on Windows. You can also pass `--config=/path/to/ggproxy.conf`. Example:

```ini
proxy_mode = http
port = 3128
log_level = debug
allowed_ip = 192.168.1.0/24
allowed_ip = 10.0.0.0/8

idle_timeout = 30s
buffer_size = 65536
auth_user = username
auth_pass = password

# GUI Configuration
gui_enabled = true
gui_port = 8080
gui_user = admin
gui_pass = password
gui_bind = 127.0.0.1
```

**Configuration fields**:

- `proxy_mode`: `http` or `socks` (default: `http`)
- `port`: Listening port (default: `3128`)
- `log_level`: `debug`, `basic`, or `off` (default: `basic`)
- `allowed_ip`: One per line, CIDR format (IPv4 only)
- `idle_timeout`: Connection idle timeout (default: `30s`)
- `buffer_size`: Internal buffer size for copy operations (default: `32KB`)
- `auth_user` / `auth_pass`: Optional credentials for authentication (both required if used)
- `gui_enabled`: Enable/disable web dashboard (default: `true`)
- `gui_port`: Web dashboard port (default: `8080`)
- `gui_user` / `gui_pass`: Dashboard login credentials
- `gui_bind`: Dashboard bind address (IP only, no CIDR)

## Usage

### Linux

GGProxy runs automatically as a systemd service. Manage it with:

```bash
sudo systemctl status ggproxy
sudo systemctl restart ggproxy
sudo systemctl stop ggproxy
```

Access the web dashboard at `http://localhost:8080` (or configured `gui_port`).

### Windows

Run the executable directly with a config file:

```cmd
ggproxy.exe --config=ggproxy.conf
```

Then access the web dashboard at `http://localhost:8080`.

## Testing

### HTTP Mode with Authentication

```bash
curl -U username:password -x http://127.0.0.1:3128 http://example.com
```

### SOCKS5 Mode with Authentication

```bash
curl -U username:password --socks5 127.0.0.1:3128 http://example.com
```

### View Logs

On Linux, check logs via journald:

```bash
journalctl -u ggproxy -f
```

### Web Dashboard

Access the dashboard at `http://localhost:8080` (default) with configured credentials to:
- Monitor real-time proxy metrics (CPU, memory, bandwidth)
- View active connections
- Check proxy logs
- Edit configuration settings

## Architecture

GGProxy uses a goroutine-based concurrent architecture:

- **Connection Handling**: Each client connection is handled in its own goroutine
- **Bidirectional Tunneling**: Symmetric goroutines manage client→remote and remote→client data flow
- **Buffer Pooling**: Efficient memory management via `sync.Pool` during data copying
- **Async Logging**: Non-blocking log writes to stdout via buffered channel (captured by systemd on Linux)

## License

GGProxy GUI is licensed under the [MIT License](https://opensource.org/licenses/MIT).