---
title: POST /api/tools/exiftool
group: api
handler: exiftool
module: __main__
line_range: [13616, 13650]
discovered_in_chunk: 13
---

# POST /api/tools/exiftool

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute ExifTool for metadata extraction and analysis

## Complete Signature & Definition
```python
@app.route("/api/tools/exiftool", methods=["POST"])
def exiftool():
    """Execute ExifTool for metadata extraction and analysis with enhanced logging"""
```

## Purpose & Behavior
Metadata extraction and analysis endpoint providing:
- **Metadata Extraction:** Extract metadata from various file types
- **EXIF Analysis:** Analyze EXIF data from images and documents
- **Forensic Analysis:** Perform forensic metadata analysis
- **Enhanced Logging:** Detailed logging of extraction progress and results

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/exiftool
- **Content-Type:** application/json

### Request Body
```json
{
    "file_path": "string",            // Required: Path to file for analysis
    "output_format": "string",        // Optional: Output format (default: json)
    "extract_all": boolean,           // Optional: Extract all metadata (default: true)
    "remove_metadata": boolean,       // Optional: Remove metadata (default: false)
    "tags": ["string"],               // Optional: Specific tags to extract
    "recursive": boolean,             // Optional: Recursive directory processing (default: false)
    "output_file": "string",          // Optional: Output file path
    "additional_args": "string"       // Optional: Additional exiftool arguments
}
```

### Parameters
- **file_path:** Path to file for analysis (required)
- **output_format:** Output format (optional, default: "json") - "json", "xml", "csv", "html"
- **extract_all:** Extract all metadata flag (optional, default: true)
- **remove_metadata:** Remove metadata flag (optional, default: false)
- **tags:** Specific tags to extract (optional) - ["GPS:GPSLatitude", "EXIF:DateTime"]
- **recursive:** Recursive directory processing flag (optional, default: false)
- **output_file:** Output file path (optional)
- **additional_args:** Additional exiftool arguments (optional)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "command": "exiftool -json /path/to/image.jpg",
    "metadata_results": {
        "file_path": "/path/to/image.jpg",
        "file_type": "JPEG",
        "file_size": "2.5MB",
        "metadata": {
            "EXIF": {
                "DateTime": "2024:01:01 12:00:00",
                "Camera": "Canon EOS 5D Mark IV",
                "GPS": {
                    "GPSLatitude": "40.7128",
                    "GPSLongitude": "-74.0060",
                    "GPSAltitude": "10m"
                }
            },
            "IPTC": {
                "Keywords": ["security", "testing"],
                "Copyright": "Example Corp"
            }
        },
        "privacy_concerns": [
            {
                "type": "GPS Location",
                "data": "40.7128, -74.0060",
                "risk": "High"
            }
        ],
        "total_tags": 45,
        "extraction_time": 1.2
    },
    "raw_output": "[{\"SourceFile\":\"/path/to/image.jpg\",\"ExifTool\":{\"ExifToolVersion\":12.40}}]",
    "execution_time": 1.2,
    "timestamp": "2024-01-01T12:00:00Z"
}
```

### Error Responses

#### Missing File Path (400 Bad Request)
```json
{
    "error": "File path parameter is required"
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
file_path = params.get("file_path", "")
output_format = params.get("output_format", "json")
extract_all = params.get("extract_all", True)
remove_metadata = params.get("remove_metadata", False)
tags = params.get("tags", [])
recursive = params.get("recursive", False)
output_file = params.get("output_file", "")
additional_args = params.get("additional_args", "")

if not file_path:
    return jsonify({"error": "File path parameter is required"}), 400
```

### Command Construction
```python
# Base command
command = ["exiftool"]

# Output format
if output_format == "json":
    command.append("-json")
elif output_format == "xml":
    command.append("-X")
elif output_format == "csv":
    command.append("-csv")
elif output_format == "html":
    command.append("-h")

# Extract all metadata
if extract_all:
    command.append("-a")

# Remove metadata
if remove_metadata:
    command.append("-all=")

# Specific tags
if tags:
    for tag in tags:
        command.extend(["-" + tag])

# Recursive
if recursive:
    command.append("-r")

# Output file
if output_file:
    command.extend(["-o", output_file])

# Additional arguments
if additional_args:
    command.extend(additional_args.split())

# File path
command.append(file_path)

# Convert to string
command_str = " ".join(command)
```

## AuthN/AuthZ
- **Authentication:** Not specified (appears to be open)
- **Authorization:** ExifTool execution access required

## Error Handling
- **Missing Parameters:** 400 error for missing file path
- **Execution Errors:** Handled by execute_command_with_recovery
- **Server Errors:** 500 error with exception details

## Security Considerations
- **File Path Validation:** Validate file paths to prevent directory traversal
- **Privacy Protection:** Identify and warn about privacy-sensitive metadata
- **Responsible Use:** Emphasize responsible use of metadata extraction capabilities

## Use Cases and Applications

#### Digital Forensics
- **Evidence Analysis:** Extract metadata from digital evidence
- **Timeline Construction:** Build timelines from metadata timestamps
- **Location Analysis:** Analyze GPS metadata for location intelligence

#### Privacy Assessment
- **Metadata Auditing:** Audit files for privacy-sensitive metadata
- **Data Sanitization:** Remove metadata before file sharing
- **Compliance Checking:** Check metadata compliance with privacy policies

## Testing & Validation
- Command construction accuracy testing
- Parameter validation verification
- Metadata extraction accuracy testing
- Error handling behavior validation

## Code Reproduction
```python
@app.route("/api/tools/exiftool", methods=["POST"])
def exiftool():
    """Execute ExifTool for metadata extraction and analysis with enhanced logging"""
    try:
        params = request.json
        file_path = params.get("file_path", "")
        output_format = params.get("output_format", "json")
        extract_all = params.get("extract_all", True)
        remove_metadata = params.get("remove_metadata", False)
        tags = params.get("tags", [])
        recursive = params.get("recursive", False)
        output_file = params.get("output_file", "")
        additional_args = params.get("additional_args", "")
        
        if not file_path:
            return jsonify({"error": "File path parameter is required"}), 400
        
        # Base command
        command = ["exiftool"]
        
        # Output format
        if output_format == "json":
            command.append("-json")
        elif output_format == "xml":
            command.append("-X")
        elif output_format == "csv":
            command.append("-csv")
        elif output_format == "html":
            command.append("-h")
        
        # Extract all metadata
        if extract_all:
            command.append("-a")
        
        # Remove metadata
        if remove_metadata:
            command.append("-all=")
        
        # Specific tags
        if tags:
            for tag in tags:
                command.extend(["-" + tag])
        
        # Recursive
        if recursive:
            command.append("-r")
        
        # Output file
        if output_file:
            command.extend(["-o", output_file])
        
        # Additional arguments
        if additional_args:
            command.extend(additional_args.split())
        
        # File path
        command.append(file_path)
        
        # Convert to string
        command_str = " ".join(command)
        
        logger.info(f"🔍 Executing ExifTool: {command_str}")
        
        start_time = time.time()
        result = execute_command_with_recovery(command_str)
        execution_time = time.time() - start_time
        
        # Parse output for metadata results
        metadata_results = parse_exiftool_output(result["output"], file_path, output_format)
        
        logger.info(f"🔍 ExifTool completed in {execution_time:.2f}s | Tags: {metadata_results.get('total_tags', 0)}")
        
        return jsonify({
            "success": True,
            "command": command_str,
            "metadata_results": metadata_results,
            "raw_output": result["output"],
            "execution_time": execution_time,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"💥 Error in ExifTool endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
