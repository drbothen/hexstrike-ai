---
title: DELETE /api/files/delete
group: api
handler: delete_file
module: __main__
line_range: [7311, 7345]
discovered_in_chunk: 7
---

# DELETE /api/files/delete

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Delete an existing file

## Complete Signature & Definition
```python
@app.route("/api/files/delete", methods=["DELETE"])
def delete_file():
    """Delete an existing file"""
```

## Purpose & Behavior
File deletion endpoint providing:
- **File Removal:** Permanently delete files
- **Security Controls:** Path validation to prevent directory traversal
- **Error Handling:** Comprehensive error handling with detailed responses

## Request

### HTTP Method
- **Method:** DELETE
- **Path:** /api/files/delete
- **Content-Type:** application/json

### Request Body
```json
{
    "filename": "string"       // Required: Name of file to delete
}
```

### Parameters
- **filename:** Name of the file to delete (required)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "path": "/tmp/hexstrike_files/example.txt"
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
1. **JSON Parsing:** Extract filename from request
2. **Parameter Validation:** Ensure filename is provided
3. **File Deletion:** Use FileOperationsManager to delete file
4. **Response Generation:** Return deletion results

### Parameter Extraction
```python
params = request.json
filename = params.get("filename", "")
```

### Validation Logic
```python
if not filename:
    return jsonify({"error": "Filename is required"}), 400
```

### File Deletion Integration
- **Manager Call:** file_manager.delete_file(filename)
- **Result Passthrough:** Direct return of file manager results
- **Security Controls:** Handled by FileOperationsManager

## AuthN/AuthZ
- **Authentication:** Not specified (appears to be open)
- **Authorization:** File deletion access required

## Error Handling
- **Missing Parameters:** 400 error for missing filename
- **File Not Found:** 404 error for non-existent files
- **File Deletion Errors:** Handled by FileOperationsManager
- **Server Errors:** 500 error with exception details

## Security Considerations
- **Path Validation:** Restricted to base directory by FileOperationsManager
- **Permission Checks:** Ensures file is deletable before attempting deletion

## Use Cases and Applications

#### File Management
- **Cleanup Operations:** Remove temporary files after processing
- **Test File Removal:** Delete test files after testing
- **Payload Cleanup:** Remove payload files after security testing

#### Security Operations
- **Sensitive Data Removal:** Delete files containing sensitive information
- **Artifact Cleanup:** Remove artifacts after security testing
- **Temporary File Management:** Clean up temporary files created during operations

## Testing & Validation
- File deletion accuracy testing
- Parameter validation verification
- Error handling behavior validation
- Security control effectiveness testing

## Code Reproduction
```python
@app.route("/api/files/delete", methods=["DELETE"])
def delete_file():
    """Delete an existing file"""
    try:
        params = request.json
        filename = params.get("filename", "")
        
        if not filename:
            return jsonify({"error": "Filename is required"}), 400
        
        result = file_manager.delete_file(filename)
        return jsonify(result)
    except FileNotFoundError as e:
        logger.error(f"💥 File not found: {str(e)}")
        return jsonify({"error": f"File not found: {str(e)}"}), 404
    except Exception as e:
        logger.error(f"💥 Error deleting file: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```
