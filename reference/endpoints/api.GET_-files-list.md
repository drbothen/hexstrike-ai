---
title: GET /api/files/list
group: api
handler: list_files
module: __main__
line_range: [7346, 7357]
discovered_in_chunk: 7
---

# GET /api/files/list

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** List files in the managed directory

## Complete Signature & Definition
```python
@app.route("/api/files/list", methods=["GET"])
def list_files():
    """List files in the managed directory"""
```

## Purpose & Behavior
File listing endpoint providing:
- **Directory Listing:** List all files in the managed directory
- **File Metadata:** Provide metadata for each file (size, modification time)
- **Filtering:** Optional filtering by file extension or pattern
- **Error Handling:** Comprehensive error handling with detailed responses

## Request

### HTTP Method
- **Method:** GET
- **Path:** /api/files/list
- **Query Parameters:**
  - **pattern:** Optional filter pattern (e.g., "*.txt")
  - **sort_by:** Optional sort field (e.g., "name", "size", "modified")
  - **order:** Optional sort order (e.g., "asc", "desc")

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "base_path": "/tmp/hexstrike_files",
    "files": [
        {
            "name": "example.txt",
            "path": "/tmp/hexstrike_files/example.txt",
            "size": 1024,
            "modified": "2024-01-01T12:00:00Z"
        },
        {
            "name": "test.bin",
            "path": "/tmp/hexstrike_files/test.bin",
            "size": 2048,
            "modified": "2024-01-01T13:00:00Z"
        }
    ]
}
```

### Error Response (500 Internal Server Error)
```json
{
    "error": "Server error: {error_message}"
}
```

## Implementation Details

### Request Processing
1. **Query Parameter Extraction:** Extract optional filter pattern and sorting parameters
2. **File Listing:** Use FileOperationsManager to list files
3. **Response Generation:** Return file listing results

### Parameter Extraction
```python
pattern = request.args.get("pattern", "")
sort_by = request.args.get("sort_by", "name")
order = request.args.get("order", "asc")
```

### File Listing Integration
- **Manager Call:** file_manager.list_files(pattern, sort_by, order)
- **Result Passthrough:** Direct return of file manager results
- **Security Controls:** Handled by FileOperationsManager

## AuthN/AuthZ
- **Authentication:** Not specified (appears to be open)
- **Authorization:** File listing access required

## Error Handling
- **Directory Access Errors:** Handled by FileOperationsManager
- **Server Errors:** 500 error with exception details

## Security Considerations
- **Path Validation:** Restricted to base directory by FileOperationsManager
- **Information Disclosure:** Only returns information about files in the managed directory

## Use Cases and Applications

#### File Management
- **File Discovery:** Discover available files for processing
- **Resource Inventory:** Inventory available resources
- **File Selection:** Select files for further processing

#### Development and Testing
- **Test File Listing:** List test files for development
- **Resource Verification:** Verify file creation and deletion operations
- **File Availability:** Check file availability before operations

## Testing & Validation
- File listing accuracy testing
- Filter pattern functionality testing
- Sorting functionality testing
- Error handling behavior validation

## Code Reproduction
```python
@app.route("/api/files/list", methods=["GET"])
def list_files():
    """List files in the managed directory"""
    try:
        pattern = request.args.get("pattern", "")
        sort_by = request.args.get("sort_by", "name")
        order = request.args.get("order", "asc")
        
        result = file_manager.list_files(pattern, sort_by, order)
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error listing files: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```
