#!/usr/bin/env python3
"""Check current migration status"""

import os
import re

def check_migration_status():
    with open('hexstrike_server.py', 'r') as f:
        content = f.read()
        
    endpoints = re.findall(r'@app\.route\(["\']([^"\']+)["\']', content)
    print(f"🔍 Flask endpoints still in monolith: {len(endpoints)}")
    print(f"📊 Monolith size: {len(content.splitlines()):,} lines")
    
    oversized_files = []
    for root, dirs, files in os.walk('src/'):
        for file in files:
            if file.endswith('.py'):
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, 'r') as f:
                        lines = len(f.readlines())
                    if lines > 300:
                        oversized_files.append((filepath, lines))
                except Exception as e:
                    print(f"Error reading {filepath}: {e}")

    print(f"\n📏 Modules exceeding 300 lines: {len(oversized_files)}")
    for filepath, lines in oversized_files:
        print(f"  {filepath}: {lines} lines")

    print(f"\n📊 Migration Status:")
    print(f"  - Endpoints in monolith: {len(endpoints)}")
    print(f"  - Oversized modules: {len(oversized_files)}")
    print(f"  - Target: 0 endpoints in monolith, 0 oversized modules")

    if endpoints:
        print(f"\nFirst 10 endpoints to migrate:")
        for i, endpoint in enumerate(endpoints[:10]):
            print(f"  {i+1}. {endpoint}")
    
    return len(endpoints), len(oversized_files)

if __name__ == "__main__":
    check_migration_status()
