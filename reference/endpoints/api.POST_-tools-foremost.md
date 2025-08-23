---
title: POST /api/tools/foremost
group: api
handler: foremost
module: __main__
line_range: [13576, 13615]
discovered_in_chunk: 13
---

# POST /api/tools/foremost

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute Foremost for file carving and recovery

## Complete Signature & Definition
```python
@app.route("/api/tools/foremost", methods=["POST"])
def foremost():
    """Execute Foremost for file carving and recovery with enhanced logging"""
```

## Purpose & Behavior
File carving and recovery endpoint providing:
- **File Carving:** Recover deleted or hidden files from disk images
- **Data Recovery:** Extract files from corrupted or damaged media
- **Forensic Analysis:** Perform forensic file recovery and analysis
- **Enhanced Logging:** Detailed logging of carving progress and results

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/foremost
- **Content-Type:** application/json

### Request Body
```json
{
    "input_file": "string",           // Required: Input file or disk image
    "output_dir": "string",           // Optional: Output directory (default: ./output)
    "file_types": ["string"],         // Optional: File types to recover
    "config_file": "string",          // Optional: Configuration file path
    "verbose": boolean,               // Optional: Verbose output (default: false)
    "write_audit": boolean,           // Optional: Write audit file (default: true)
    "block_size": integer,            // Optional: Block size in bytes
    "additional_args": "string"       // Optional: Additional foremost arguments
}
```

### Parameters
- **input_file:** Input file or disk image (required)
- **output_dir:** Output directory (optional, default: "./output")
- **file_types:** File types to recover (optional) - ["jpg", "pdf", "doc", "zip"]
- **config_file:** Configuration file path (optional)
- **verbose:** Verbose output flag (optional, default: false)
- **write_audit:** Write audit file flag (optional, default: true)
- **block_size:** Block size in bytes (optional)
- **additional_args:** Additional foremost arguments (optional)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "command": "foremost -i disk.img -o ./output -t jpg,pdf,doc",
    "carving_results": {
        "input_file": "disk.img",
        "output_directory": "./output",
        "file_types_searched": ["jpg", "pdf", "doc"],
        "files_recovered": [
            {
                "type": "jpg",
                "filename": "00000001.jpg",
                "size": 1024576,
                "offset": "0x12345678"
            },
            {
                "type": "pdf",
                "filename": "00000002.pdf",
                "size": 2048000,
                "offset": "0x23456789"
            }
        ],
        "total_files_recovered": 25,
        "total_size_recovered": "15.2MB",
        "processing_time": 120.5,
        "audit_file": "./output/audit.txt"
    },
    "raw_output": "Foremost version 1.5.7\nProcessing: disk.img\nFound 25 files\n",
    "execution_time": 120.5,
    "timestamp": "2024-01-01T12:00:00Z"
}
```

### Error Responses

#### Missing Input File (400 Bad Request)
```json
{
    "error": "Input file parameter is required"
}
```

#### Server Error (500 Internal Server Error)
```json
{
    "error": "Server error: {error_message}"
}
```

## Implementation Details

### Parameter Validation
```python
params = request.json
input_file = params.get("input_file", "")
output_dir = params.get("output_dir", "./output")
file_types = params.get("file_types", [])
config_file = params.get("config_file", "")
verbose = params.get("verbose", False)
write_audit = params.get("write_audit", True)
block_size = params.get("block_size", None)
additional_args = params.get("additional_args", "")

if not input_file:
    return jsonify({"error": "Input file parameter is required"}), 400
```

### Command Construction
```python
# Base command
command = ["foremost", "-i", input_file]

# Output directory
command.extend(["-o", output_dir])

# File types
if file_types:
    command.extend(["-t", ",".join(file_types)])

# Configuration file
if config_file:
    command.extend(["-c", config_file])

# Verbose
if verbose:
    command.append("-v")

# Write audit
if write_audit:
    command.append("-a")

# Block size
if block_size:
    command.extend(["-b", str(block_size)])

# Additional arguments
if additional_args:
    command.extend(additional_args.split())

# Convert to string
command_str = " ".join(command)
```

## AuthN/AuthZ
- **Authentication:** Not specified (appears to be open)
- **Authorization:** Foremost execution access required

## Error Handling
- **Missing Parameters:** 400 error for missing input file
- **Execution Errors:** Handled by execute_command_with_recovery
- **Server Errors:** 500 error with exception details

## Security Considerations
- **File Path Validation:** Validate input and output file paths
- **Resource Management:** Manage system resources during file carving
- **Responsible Use:** Emphasize responsible use of file carving capabilities

## Use Cases and Applications

#### Digital Forensics
- **File Recovery:** Recover deleted files from disk images
- **Evidence Collection:** Collect digital evidence from storage media
- **Data Recovery:** Recover data from corrupted or damaged media

#### Incident Response
- **Artifact Recovery:** Recover artifacts from compromised systems
- **Data Extraction:** Extract data for forensic analysis
- **Evidence Preservation:** Preserve digital evidence for investigation

## Testing & Validation
- Command construction accuracy testing
- Parameter validation verification
- File carving accuracy testing
- Error handling behavior validation

## Code Reproduction
```python
@app.route("/api/tools/foremost", methods=["POST"])
def foremost():
    """Execute Foremost for file carving and recovery with enhanced logging"""
    try:
        params = request.json
        input_file = params.get("input_file", "")
        output_dir = params.get("output_dir", "./output")
        file_types = params.get("file_types", [])
        config_file = params.get("config_file", "")
        verbose = params.get("verbose", False)
        write_audit = params.get("write_audit", True)
        block_size = params.get("block_size", None)
        additional_args = params.get("additional_args", "")
        
        if not input_file:
            return jsonify({"error": "Input file parameter is required"}), 400
        
        # Base command
        command = ["foremost", "-i", input_file]
        
        # Output directory
        command.extend(["-o", output_dir])
        
        # File types
        if file_types:
            command.extend(["-t", ",".join(file_types)])
        
        # Configuration file
        if config_file:
            command.extend(["-c", config_file])
        
        # Verbose
        if verbose:
            command.append("-v")
        
        # Write audit
        if write_audit:
            command.append("-a")
        
        # Block size
        if block_size:
            command.extend(["-b", str(block_size)])
        
        # Additional arguments
        if additional_args:
            command.extend(additional_args.split())
        
        # Convert to string
        command_str = " ".join(command)
        
        logger.info(f"🔍 Executing Foremost: {command_str}")
        
        start_time = time.time()
        result = execute_command_with_recovery(command_str)
        execution_time = time.time() - start_time
        
        # Parse output for carving results
        carving_results = parse_foremost_output(result["output"], input_file, output_dir)
        
        logger.info(f"🔍 Foremost completed in {execution_time:.2f}s | Files recovered: {carving_results.get('total_files_recovered', 0)}")
        
        return jsonify({
            "success": True,
            "command": command_str,
            "carving_results": carving_results,
            "raw_output": result["output"],
            "execution_time": execution_time,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"💥 Error in Foremost endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
