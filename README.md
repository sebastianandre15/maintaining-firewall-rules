# Firewall Rule Server & Client

> A multi-threaded server and client system to maintain and interact with a firewall configuration, written in C for an Operating Systems and Systems Programming assignment at the University of Birmingham.

---

## Description

This project implements a server that manages firewall rules and a client that communicates with it. The server can be run in **interactive** or **socket** mode and supports concurrent connections.

It handles commands to:
- Add and delete firewall rules
- Check IP/port combinations against rules
- List all previous requests
- List all rules and matched queries

---

## Technologies Used

- Language: **C**
- Tools: `make`, POSIX sockets, `valgrind` (for leak checks)
- OS: Linux

---

## Compilation

```bash
make
```

This will build `server` and `client` using the provided `Makefile`.

## Run Server

### 1. Interactive Mode
```bash
./server -i
```

### 2. Socket Mode
```bash
./server <port>
```

## Run Client

```bash
./client <serverHost> <serverPort> <command>
```

Example:
```bash
./client localhost 2200 A 147.188.193.15 22
```

---

## Supported Commands

| Command | Description |
|---------|-------------|
| `R` | List all previous requests |
| `A <rule>` | Add a new firewall rule |
| `C <ip> <port>` | Check IP and port against rules |
| `D <rule>` | Delete an existing rule |
| `L` | List all rules and matched queries |
| *other* | Returns `Illegal request` |

---

## Rule Format

Rules are formatted as:

```
<IPaddress or range> <port or range>
```

Examples:
```
147.188.192.41 443
147.188.193.0-147.188.194.255 21-22
```

- IPs: `x.x.x.x` format, each segment 0–255
- Ports: 0–65535
- Ranges use the `start-end` format

---

## 📜 License

This project was developed as coursework for academic purposes.
