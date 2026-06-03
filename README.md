# Network Programming Assignment
Standard Multi-Process TCP Client-Server Application built using C and Python.

## Features
- **Server (C):** Multi-process using `fork()`, Rate Limiting via Shared Memory, SHA-256 Password Hashing, Session Token Management, and automated log rotation.
- **Client (Python):** Interactive CLI with Custom Framing (`LEN:<n>`), Input validation, and continuous response handling.

## How to Run
1. **Start the Server:**
```bash
   make -f Makefile_2161
   ./server_2161
