# Multithreaded TCP Port Scanner with Simulated Services

A Python-based multithreaded TCP port scanner with a custom test server that simulates multiple network services.

The project demonstrates how port scanning works, how services respond to probes, how SSL/TLS connections are detected, and how reachable services may still reject or deny requests.

The system consists of two components:

* **Port Scanner (Client)** — scans ports concurrently using worker threads
* **Test Server (Server)** — simulates multiple services including TLS and rejection/error scenarios

This project was developed as part of the **Computer Networks course (UE24CS252B)**.

---

## Architecture

```text
             SCANNER MACHINE                         SERVER MACHINE
        ------------------------------------------------------------------
        Port_scanner.py      ---- TCP / TLS ---->    Test_server.py
              |                                              |
              |                                              |
      200 Worker Threads                           Multiple Service Threads
              |                                              |
       Queue (ports 9000-9500)                     Port 9000  HTTP-Sim
              |                                    Port 9001  SSH-Sim
          scan_port()                              Port 9002  FTP-Sim
              |                                    Port 9003  SMTP-Sim
          grab_banner()                            Port 9004  POP3-Sim
              |                                    Port 9443  HTTPS-Sim (TLS)
          check_ssl()                              Port 9005  403-Forbidden
              |                                    Port 9006  503-Unavailable
     print_port_distribution()                     Port 9007  SSH-Overloaded
              |                                    Port 9008  SMTP-Rejected
          Scan Report
```

---

## Features

* Multithreaded port scanning using 200 worker threads
* Concurrent scanning using a thread-safe queue
* Detects open ports
* Detects closed / filtered ports
* Detects reachable services that return error or rejection messages
* Service identification using known port numbers
* Banner grabbing from active services
* TLS detection with SSL handshake
* TLS version reporting for encrypted ports
* Simulated network services for testing
* Simulated rejection and error services
* Automatic SSL certificate generation
* Performance statistics for scan speed
* Terminal-based port distribution graph

---

## Simulated Services

### Normal Services

| Port | Service         |
| ---- | --------------- |
| 9000 | HTTP-Sim        |
| 9001 | SSH-Sim         |
| 9002 | FTP-Sim         |
| 9003 | SMTP-Sim        |
| 9004 | POP3-Sim        |
| 9443 | HTTPS-Sim (TLS) |

### Error / Rejection Services

| Port | Service         |
| ---- | --------------- |
| 9005 | 403-Forbidden   |
| 9006 | 503-Unavailable |
| 9007 | SSH-Overloaded  |
| 9008 | SMTP-Rejected   |

---

## File Structure

```text
project/
│
├── Port_scanner.py      # Multithreaded port scanner client
├── Test_server.py       # Multi-service test server
├── server.crt           # Auto-generated TLS certificate
├── server.key           # Auto-generated TLS private key
└── README.md
```

---

## How the System Works

### Server Workflow

1. Server starts
2. Generates a self-signed SSL certificate if none exists
3. Creates an SSL context for TLS services
4. Spawns a thread for each simulated service
5. Each service:

   * Opens a TCP socket
   * Binds to its port
   * Starts listening for connections
6. When a connection arrives:

   * Accept connection
   * Wrap socket with SSL if required
   * Spawn a client handler thread
7. Client handler:

   * Reads incoming probe
   * Sends service banner
   * Closes connection

### Scanner Workflow

1. User enters the target IP
2. Scanner creates:

   * Queue containing ports `9000–9500`
   * `200` worker threads
3. Each worker thread repeatedly:

   * Pulls a port from the queue
   * Runs `scan_port(port)`
4. `scan_port()` performs:

   * TCP connection attempt using `socket.connect()`
   * Banner grabbing if connection succeeds
   * Error banner detection for rejected services
5. For SSL ports:

   * Creates TLS client context
   * Performs handshake
   * Detects TLS version
6. Failed ports are retried once before being marked as closed / filtered
7. Results are recorded using thread-safe counters
8. When all ports are scanned:

   * Threads terminate
   * Final report is printed
   * Port distribution graph is displayed

---

## Sample Scanner Output

```text
===========================================================================
  SCAN SUMMARY
===========================================================================
  Total scanned        : 501
  Open                 : 6
  Error / Rejected     : 4
  Closed / Filtered    : 491

  Total time           : 6.19s
  Speed                : 80.9 ports/sec

===========================================================================
  PORT DISTRIBUTION
===========================================================================
  Open                 [#---------------------------------------]    6 ports ( 1.2%)
  Closed / Filtered    [#######################################-]  491 ports (98.0%)
  Error / Rejected     [#---------------------------------------]    4 ports ( 0.8%)
===========================================================================
```

---

## Authors

* Pushkar S Kulkarni
* R Saurav Srrinivas
* Prathamesh Kumar Singh

**Course:** UE24CS252B – Computer Networks
