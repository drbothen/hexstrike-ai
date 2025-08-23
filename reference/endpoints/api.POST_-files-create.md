---
title: POST /api/files/create
group: api
handler: create_file
module: __main__
line_range: [7294, 7310]
discovered_in_chunk: 7
---

# POST /api/files/create

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Create a new file

## Complete Signature & Definition
```python
@app.route("/api/files/create", methods=["POST"])
def create_file():
    """Create a new file"""
```

## Purpose & Behavior
File creation endpoint providing:
- **File Creation:** Create new files with specified content
- **Binary Support:** Support for both text and binary file creation
- **Security Controls:** File size limits and path validation
- **Error Handling:** Comprehensive error handling with detailed responses

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/files/create
- **Content-Type:** application/json

### Request Body
```json
{
    "filename": "string",       // Required: Name of file to create
    "content": "string",        // Required: File content
    "binary": boolean           // Optional: Binary mode flag (default: false)
}
```

### Parameters
- **filename:** Name of the file to create (required)
- **content:** Content to write to the file (required)
- **binary:** Whether to create file in binary mode (optional, default: false)

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

#### Server Error (500 Internal Server Error)
```json
{
    "error": "Server error: {error_message}"
}
```

## Implementation Details

### Request Processing
1. **JSON Parsing:** Extract filename, content, and binary flag from request
2. **Parameter Validation:** Ensure filename is provided
3. **File Creation:** Use FileOperationsManager to create file
4. **Response Generation:** Return creation results

### Parameter Extraction
```python
params = request.json
filename = params.get("filename", "")
content = params.get("content", "")
binary = params.get("binary", False)
```

### Validation Logic
```python
if not filename:
    return jsonify({"error": "Filename is required"}), 400
```

### File Creation Integration
- **Manager Call:** file_manager.create_file(filename, content, binary)
- **Result Passthrough:** Direct return of file manager results
- **Security Controls:** Handled by FileOperationsManager

## AuthN/AuthZ
- **Authentication:** Not specified (appears to be open)
- **Authorization:** File creation access required

## Error Handling
- **Missing Parameters:** 400 error for missing filename
- **File Creation Errors:** Handled by FileOperationsManager
- **Server Errors:** 500 error with exception details

## Security Considerations
- **File Size Limits:** 100MB limit enforced by FileOperationsManager
- **Path Validation:** Restricted to base directory by FileOperationsManager
- **Content Validation:** No content sanitization specified

## Use Cases and Applications

#### File Management
- **Content Storage:** Store generated content as files
- **Payload Creation:** Create payload files for testing
- **Result Storage:** Store scan results and reports

#### Development and Testing
- **Test File Creation:** Create test files for development
- **Content Testing:** Test file creation with various content types
- **Binary File Support:** Create binary files for testing

## Testing & Validation
- File creation accuracy testing
- Parameter validation verification
- Binary mode functionality testing
- Error handling behavior validation

## Code Reproduction
```python
@app.route("/api/files/create", methods=["POST"])
def create_file():
    """Create a new file"""
    try:
        params = request.json
        filename = params.get("filename", "")
        content = params.get("content", "")
        binary = params.get("binary", False)
        
        if not filename:
            return jsonify({"error": "Filename is required"}), 400
        
        result = file_manager.create_file(filename, content, binary)
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error creating file: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```
