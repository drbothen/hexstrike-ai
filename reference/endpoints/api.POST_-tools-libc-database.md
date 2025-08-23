---
title: POST /api/tools/libc-database
group: api
handler: libc_database
module: __main__
line_range: [10526, 10565]
discovered_in_chunk: 10
---

# POST /api/tools/libc-database

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute libc-database for libc identification and offset lookup

## Complete Signature & Definition
```python
@app.route("/api/tools/libc-database", methods=["POST"])
def libc_database():
    """Execute libc-database for libc identification and offset lookup"""
```

## Purpose & Behavior
Libc-database identification endpoint providing:
- **Libc Identification:** Find libc versions based on symbol offsets
- **Offset Lookup:** Dump symbol offsets from known libc versions
- **Database Management:** Download and manage libc database entries
- **Enhanced Logging:** Detailed logging of libc analysis operations

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/libc-database
- **Content-Type:** application/json

### Request Body
```json
{
    "action": "string",              // Required: Action type (find, dump, download)
    "symbols": "string",             // Required for find: Symbol offsets format "symbol1:offset1 symbol2:offset2"
    "libc_id": "string",             // Required for dump/download: Libc identifier
    "additional_args": "string"      // Optional: Additional libc-database arguments
}
```

## Response

### Success Response (200 OK)
```json
{
    "stdout": "string",
    "stderr": "string",
    "return_code": 0,
    "success": true,
    "execution_time": 2.1,
    "timestamp": "2024-01-01T12:00:00Z",
    "command": "cd /opt/libc-database && ./find printf:0x7f0 system:0x4f0"
}
```

## Code Reproduction
```python
@app.route("/api/tools/libc-database", methods=["POST"])
def libc_database():
    """Execute libc-database for libc identification and offset lookup"""
    try:
        params = request.json
        action = params.get("action", "find")  # find, dump, download
        symbols = params.get("symbols", "")  # format: "symbol1:offset1 symbol2:offset2"
        libc_id = params.get("libc_id", "")
        additional_args = params.get("additional_args", "")
        
        if action == "find" and not symbols:
            logger.warning("🔧 libc-database find called without symbols")
            return jsonify({"error": "Symbols parameter is required for find action"}), 400
        
        if action in ["dump", "download"] and not libc_id:
            logger.warning("🔧 libc-database called without libc_id for dump/download")
            return jsonify({"error": "libc_id parameter is required for dump/download actions"}), 400
        
        # Navigate to libc-database directory (assuming it's installed)
        base_command = "cd /opt/libc-database 2>/dev/null || cd ~/libc-database 2>/dev/null || echo 'libc-database not found'"
        
        if action == "find":
            command = f"{base_command} && ./find {symbols}"
        elif action == "dump":
            command = f"{base_command} && ./dump {libc_id}"
        elif action == "download":
            command = f"{base_command} && ./download {libc_id}"
        else:
            return jsonify({"error": f"Invalid action: {action}"}), 400
        
        if additional_args:
            command += f" {additional_args}"
        
        logger.info(f"🔧 Starting libc-database {action}: {symbols or libc_id}")
        result = execute_command(command)
        logger.info(f"📊 libc-database {action} completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in libc-database endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```
