---
title: POST /api/files/modify
group: api
handler: modify_file
module: __main__
line_range: [7311, 7345]
discovered_in_chunk: 7
---

# POST /api/files/modify

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Modify an existing file

## Complete Signature & Definition
```python
@app.route("/api/files/modify", methods=["POST"])
def modify_file():
    """Modify an existing file"""
```

## Purpose & Behavior
File modification endpoint providing:
- **File Content Update:** Update content of existing files
- **Append Mode:** Support for appending to existing files
- **Binary Support:** Support for both text and binary file modification
- **Security Controls:** File size limits and path validation
- **Error Handling:** Comprehensive error handling with detailed responses

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/files/modify
- **Content-Type:** application/json

### Request Body
```json
{
    "filename": "string",       // Required: Name of file to modify
    "content": "string",        // Required: New content or content to append
    "append": boolean,          // Optional: Append mode flag (default: false)
    "binary": boolean           // Optional: Binary mode flag (default: false)
}
```

### Parameters
- **filename:** Name of the file to modify (required)
- **content:** New content or content to append to the file (required)
- **append:** Whether to append content to the file (optional, default: false)
- **binary:** Whether to modify file in binary mode (optional, default: false)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "path": "/tmp/hexstrike_files/example.txt",
    "size": 1024
}
```

### Error Responses

#### Missing Filename (400 Bad Request)
```json
{
    "error": "Filename is required"
}
```

#### File Not Found (404 Not Found)
```json
{
    "error": "File not found: example.txt"
}
```

#### Server Error (500 Internal Server Error)
```json
{
    "error": "Server error: {error_message}"
}
```

## Implementation Details

### Request Processing
1. **JSON Parsing:** Extract filename, content, append flag, and binary flag from request
2. **Parameter Validation:** Ensure filename is provided
3. **File Modification:** Use FileOperationsManager to modify file
4. **Response Generation:** Return modification results

### Parameter Extraction
```python
params = request.json
filename = params.get("filename", "")
content = params.get("content", "")
append = params.get("append", False)
binary = params.get("binary", False)
```

### Validation Logic
```python
if not filename:
    return jsonify({"error": "Filename is required"}), 400
```

### File Modification Integration
- **Manager Call:** file_manager.modify_file(filename, content, append, binary)
- **Result Passthrough:** Direct return of file manager results
- **Security Controls:** Handled by FileOperationsManager

## AuthN/AuthZ
- **Authentication:** Not specified (appears to be open)
- **Authorization:** File modification access required

## Error Handling
- **Missing Parameters:** 400 error for missing filename
- **File Not Found:** 404 error for non-existent files
- **File Modification Errors:** Handled by FileOperationsManager
- **Server Errors:** 500 error with exception details

## Security Considerations
- **File Size Limits:** 100MB limit enforced by FileOperationsManager
- **Path Validation:** Restricted to base directory by FileOperationsManager
- **Content Validation:** No content sanitization specified

## Use Cases and Applications

#### File Management
- **Content Updates:** Update generated content in files
- **Payload Modification:** Modify payload files for testing
- **Result Appending:** Append scan results and reports

#### Development and Testing
- **Test File Modification:** Modify test files for development
- **Content Testing:** Test file modification with various content types
- **Binary File Support:** Modify binary files for testing

## Testing & Validation
- File modification accuracy testing
- Parameter validation verification
- Append mode functionality testing
- Binary mode functionality testing
- Error handling behavior validation

## Code Reproduction
```python
@app.route("/api/files/modify", methods=["POST"])
def modify_file():
    """Modify an existing file"""
    try:
        params = request.json
        filename = params.get("filename", "")
        content = params.get("content", "")
        append = params.get("append", False)
        binary = params.get("binary", False)
        
        if not filename:
            return jsonify({"error": "Filename is required"}), 400
        
        result = file_manager.modify_file(filename, content, append, binary)
        return jsonify(result)
    except FileNotFoundError as e:
        logger.error(f"💥 File not found: {str(e)}")
        return jsonify({"error": f"File not found: {str(e)}"}), 404
    except Exception as e:
        logger.error(f"💥 Error modifying file: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```
