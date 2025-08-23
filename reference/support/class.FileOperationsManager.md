---
title: class.FileOperationsManager
kind: class
module: __main__
line_range: [7060, 7148]
discovered_in_chunk: 7
---

# FileOperationsManager Class

## Entity Classification & Context
- **Kind:** Class
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Handle file operations with security and validation

## Complete Signature & Definition
```python
class FileOperationsManager:
    """Handle file operations with security and validation"""
    
    def __init__(self, base_dir: str = "/tmp/hexstrike_files"):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(exist_ok=True)
        self.max_file_size = 100 * 1024 * 1024  # 100MB
    
    def create_file(self, filename: str, content: str, binary: bool = False) -> Dict[str, Any]:
        """Create a file with the specified content"""
    
    def modify_file(self, filename: str, content: str, append: bool = False) -> Dict[str, Any]:
        """Modify an existing file"""
    
    def delete_file(self, filename: str) -> Dict[str, Any]:
        """Delete a file or directory"""
    
    def list_files(self, directory: str = ".") -> Dict[str, Any]:
        """List files in a directory"""
```

## Purpose & Behavior
Secure file operations management system providing:
- **File Creation:** Create files with content validation and size limits
- **File Modification:** Modify existing files with append/overwrite options
- **File Deletion:** Delete files and directories with safety checks
- **Directory Listing:** List directory contents with metadata
- **Security Controls:** File size limits and path validation

## Dependencies & Usage
- **Depends on:**
  - pathlib.Path for path management
  - shutil for directory operations
  - datetime for timestamp tracking
  - logger for operation logging
- **Used by:**
  - Flask API endpoints for file operations
  - Payload generation systems
  - File management workflows

## Implementation Details

### Core Attributes
- **base_dir:** Base directory for file operations (default: "/tmp/hexstrike_files")
- **max_file_size:** Maximum file size limit (100MB)

### Key Methods

#### File Operations
1. **create_file(filename: str, content: str, binary: bool = False) -> Dict[str, Any]:** Create file with content
2. **modify_file(filename: str, content: str, append: bool = False) -> Dict[str, Any]:** Modify existing file
3. **delete_file(filename: str) -> Dict[str, Any]:** Delete file or directory
4. **list_files(directory: str = ".") -> Dict[str, Any]:** List directory contents

### File Creation

#### Creation Process
1. **Path Construction:** Build file path from base directory and filename
2. **Directory Creation:** Create parent directories if needed
3. **Size Validation:** Check content size against maximum limit
4. **File Writing:** Write content in text or binary mode
5. **Result Return:** Return success status and file information

#### Size Validation
```python
if len(content.encode()) > self.max_file_size:
    return {"success": False, "error": f"File size exceeds {self.max_file_size} bytes"}
```

#### Binary Mode Support
```python
mode = "wb" if binary else "w"
with open(file_path, mode) as f:
    if binary:
        f.write(content.encode() if isinstance(content, str) else content)
    else:
        f.write(content)
```

#### Success Result
```python
{
    "success": True,
    "path": str,                    # Full file path
    "size": int                     # Content size in bytes
}
```

### File Modification

#### Modification Options
- **Overwrite Mode:** Replace entire file content (default)
- **Append Mode:** Add content to end of existing file
- **Existence Check:** Verify file exists before modification

#### Modification Process
```python
file_path = self.base_dir / filename
if not file_path.exists():
    return {"success": False, "error": "File does not exist"}

mode = "a" if append else "w"
with open(file_path, mode) as f:
    f.write(content)
```

### File Deletion

#### Deletion Support
- **File Deletion:** Delete individual files
- **Directory Deletion:** Recursively delete directories
- **Existence Check:** Verify target exists before deletion

#### Deletion Process
```python
if file_path.is_dir():
    shutil.rmtree(file_path)
else:
    file_path.unlink()
```

### Directory Listing

#### File Information Collection
```python
{
    "name": str,                    # File/directory name
    "type": str,                    # "file" or "directory"
    "size": int,                    # Size in bytes (0 for directories)
    "modified": str                 # ISO timestamp of last modification
}
```

#### Listing Process
1. **Directory Validation:** Check directory exists
2. **Item Iteration:** Iterate through directory contents
3. **Metadata Collection:** Collect file/directory metadata
4. **Result Compilation:** Compile list of file information

### Security Features

#### File Size Limits
- **Maximum Size:** 100MB limit for file creation
- **Size Validation:** Check content size before writing
- **Error Handling:** Return error for oversized content

#### Path Security
- **Base Directory Restriction:** All operations within base directory
- **Path Validation:** Use pathlib.Path for secure path handling
- **Directory Creation:** Safe parent directory creation

### Error Handling and Resilience

#### Comprehensive Error Handling
- **Exception Catching:** Catch and handle all file operation exceptions
- **Error Result Structure:** Consistent error response format
- **Logging Integration:** Log all operations and errors

#### Error Result Format
```python
{
    "success": False,
    "error": str                    # Error description
}
```

#### Success Result Format
```python
{
    "success": True,
    "path": str,                    # File path (for create/modify)
    "size": int,                    # File size (for create)
    "files": List[Dict]             # File list (for list_files)
}
```

### Logging Integration

#### Operation Logging
- **File Creation:** "📄 Created file: {filename} ({size} bytes)"
- **File Modification:** "✏️ Modified file: {filename}"
- **File Deletion:** "🗑️ Deleted: {filename}"
- **Error Logging:** "❌ Error {operation} {filename}: {error}"

### Base Directory Management

#### Directory Initialization
- **Automatic Creation:** Create base directory if it doesn't exist
- **Path Object:** Use pathlib.Path for robust path operations
- **Default Location:** "/tmp/hexstrike_files" for temporary file storage

#### Directory Structure
- **Hierarchical Support:** Support nested directory structures
- **Parent Creation:** Automatic parent directory creation
- **Safe Operations:** All operations contained within base directory

### Integration with API Endpoints

#### Flask API Integration
- **File Creation Endpoint:** /api/files/create
- **File Modification Endpoint:** /api/files/modify
- **File Deletion Endpoint:** /api/files/delete
- **File Listing Endpoint:** /api/files/list

#### Payload Generation Integration
- **Payload Storage:** Store generated payloads as files
- **Content Management:** Manage payload content and metadata
- **File Delivery:** Provide file access for payload delivery

### Use Cases and Applications

#### Security Testing
- **Payload Management:** Store and manage security testing payloads
- **Result Storage:** Store scan results and reports
- **Tool Output:** Manage tool output files

#### Development and Testing
- **File Testing:** Test file operations and validation
- **Content Management:** Manage test content and data
- **Temporary Storage:** Provide temporary file storage

#### API Operations
- **File API:** Provide file operations through REST API
- **Content Delivery:** Deliver files through web interface
- **File Management:** Manage uploaded and generated files

### Performance Considerations

#### File Size Management
- **Size Limits:** Prevent excessive memory usage with size limits
- **Efficient Operations:** Use efficient file I/O operations
- **Resource Management:** Proper file handle management

#### Directory Operations
- **Efficient Listing:** Efficient directory listing with metadata
- **Path Operations:** Use pathlib for efficient path operations
- **Memory Usage:** Minimize memory usage for large directories

## Testing & Validation
- File creation and modification accuracy testing
- Security validation for path traversal prevention
- Size limit enforcement verification
- Error handling and resilience testing

## Code Reproduction
Complete class implementation with 4 methods for secure file operations management, including file creation, modification, deletion, and directory listing with comprehensive security controls and validation. Essential for secure file management and API operations.
