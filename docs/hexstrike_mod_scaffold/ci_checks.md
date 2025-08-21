# HexStrike AI - CI Quality Gates

**Purpose:** Comprehensive CI/CD pipeline configuration to enforce DRY and SOLID principles, line limits, and code quality standards for the modularized HexStrike AI framework.

**Status:** Proposed (designed for modular architecture enforcement)

## GitHub Actions Workflows

### Line Limit Enforcement

#### `.github/workflows/line-limits.yml`
```yaml
name: Line Limit Enforcement

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

jobs:
  check-line-limits:
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      
    - name: Check Python file line limits
      run: |
        echo "Checking that all Python modules are ≤300 lines..."
        
        # Find all Python files in src/ directory (excluding legacy and __pycache__)
        find src/ -name "*.py" \
          -not -path "*/legacy/*" \
          -not -path "*/__pycache__/*" \
          -not -path "*/.*" \
          | while read file; do
          
          line_count=$(wc -l < "$file")
          
          if [ "$line_count" -gt 300 ]; then
            echo "❌ FAIL: $file has $line_count lines (exceeds 300 line limit)"
            echo "::error file=$file,line=1::File exceeds 300 line limit ($line_count lines)"
            exit 1
          else
            echo "✅ PASS: $file has $line_count lines"
          fi
        done
        
        echo "All Python modules comply with 300-line limit!"
        
    - name: Generate line count report
      run: |
        echo "# Line Count Report" > line_count_report.md
        echo "" >> line_count_report.md
        echo "| Module | Lines | Status |" >> line_count_report.md
        echo "|--------|-------|--------|" >> line_count_report.md
        
        find src/ -name "*.py" \
          -not -path "*/legacy/*" \
          -not -path "*/__pycache__/*" \
          | sort | while read file; do
          
          line_count=$(wc -l < "$file")
          relative_path=${file#src/}
          
          if [ "$line_count" -gt 300 ]; then
            status="❌ EXCEEDS LIMIT"
          elif [ "$line_count" -gt 280 ]; then
            status="⚠️ NEAR LIMIT"
          else
            status="✅ OK"
          fi
          
          echo "| $relative_path | $line_count | $status |" >> line_count_report.md
        done
        
    - name: Upload line count report
      uses: actions/upload-artifact@v3
      with:
        name: line-count-report
        path: line_count_report.md
```

### Import Cycle Detection

#### `.github/workflows/import-cycles.yml`
```yaml
name: Import Cycle Detection

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

jobs:
  detect-cycles:
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'
        
    - name: Install dependencies
      run: |
        pip install grimp import-linter
        
    - name: Check for import cycles with grimp
      run: |
        echo "Checking for import cycles in src/hexstrike..."
        
        # Check for cycles in the main package
        python -c "
        import grimp
        import sys
        
        try:
            graph = grimp.build_graph('src/hexstrike')
            cycles = graph.find_cycles()
            
            if cycles:
                print('❌ IMPORT CYCLES DETECTED:')
                for cycle in cycles:
                    print(f'  Cycle: {\" -> \".join(cycle)}')
                sys.exit(1)
            else:
                print('✅ No import cycles detected!')
        except Exception as e:
            print(f'Error analyzing imports: {e}')
            sys.exit(1)
        "
        
    - name: Validate layer dependencies with import-linter
      run: |
        # Create import-linter configuration
        cat > .importlinter << EOF
        [importlinter]
        root_package = hexstrike
        
        [importlinter:contract:1]
        name = Layer dependencies
        type = layers
        layers =
            hexstrike.interfaces
            hexstrike.services
            hexstrike.domain
            hexstrike.adapters
            hexstrike.platform
            hexstrike.utils
        
        [importlinter:contract:2]
        name = Domain isolation
        type = forbidden
        source_modules =
            hexstrike.domain
        forbidden_modules =
            hexstrike.services
            hexstrike.adapters
            hexstrike.interfaces
        
        [importlinter:contract:3]
        name = Utils isolation
        type = forbidden
        source_modules =
            hexstrike.utils
        forbidden_modules =
            hexstrike.interfaces
            hexstrike.services
            hexstrike.domain
            hexstrike.adapters
            hexstrike.platform
        EOF
        
        # Run import-linter
        lint-imports
```

### Code Duplication Detection

#### `.github/workflows/duplication.yml`
```yaml
name: Code Duplication Detection

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

jobs:
  detect-duplication:
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      
    - name: Set up Node.js for jscpd
      uses: actions/setup-node@v3
      with:
        node-version: '18'
        
    - name: Install jscpd
      run: npm install -g jscpd
      
    - name: Check code duplication
      run: |
        echo "Checking for code duplication (threshold: 3%)..."
        
        # Run jscpd with configuration
        jscpd \
          --threshold 3 \
          --min-lines 5 \
          --min-tokens 50 \
          --reporters console,json \
          --output ./duplication-report \
          --ignore "**/legacy/**,**/__pycache__/**,**/.*" \
          --formats python \
          src/
          
        # Check if duplication exceeds threshold
        if [ -f "./duplication-report/jscpd-report.json" ]; then
          duplication_percentage=$(python3 -c "
          import json
          with open('./duplication-report/jscpd-report.json') as f:
              data = json.load(f)
              print(data.get('statistics', {}).get('percentage', 0))
          ")
          
          echo "Code duplication: ${duplication_percentage}%"
          
          if (( $(echo "$duplication_percentage > 3" | bc -l) )); then
            echo "❌ FAIL: Code duplication (${duplication_percentage}%) exceeds 3% threshold"
            exit 1
          else
            echo "✅ PASS: Code duplication (${duplication_percentage}%) within acceptable limits"
          fi
        fi
        
    - name: Upload duplication report
      uses: actions/upload-artifact@v3
      if: always()
      with:
        name: duplication-report
        path: duplication-report/
```

### Code Complexity Analysis

#### `.github/workflows/complexity.yml`
```yaml
name: Code Complexity Analysis

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

jobs:
  analyze-complexity:
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'
        
    - name: Install radon
      run: pip install radon
      
    - name: Check cyclomatic complexity
      run: |
        echo "Checking cyclomatic complexity..."
        
        # Check average complexity (should be ≤ 8)
        avg_complexity=$(radon cc src/ -a -s | grep "Average complexity" | awk '{print $NF}' | sed 's/[()]//g')
        
        if [ ! -z "$avg_complexity" ]; then
          echo "Average cyclomatic complexity: $avg_complexity"
          
          if (( $(echo "$avg_complexity > 8" | bc -l) )); then
            echo "❌ FAIL: Average complexity ($avg_complexity) exceeds threshold (8)"
            exit 1
          else
            echo "✅ PASS: Average complexity within acceptable limits"
          fi
        fi
        
        # Check for functions with high complexity (> 12)
        echo "Checking for high-complexity functions..."
        high_complexity=$(radon cc src/ -s | grep -E "\([1-9][2-9]|[2-9][0-9]\)" || true)
        
        if [ ! -z "$high_complexity" ]; then
          echo "❌ FAIL: High complexity functions detected:"
          echo "$high_complexity"
          exit 1
        else
          echo "✅ PASS: No high-complexity functions detected"
        fi
        
    - name: Generate complexity report
      run: |
        echo "Generating detailed complexity report..."
        radon cc src/ -s > complexity_report.txt
        radon mi src/ > maintainability_report.txt
        
    - name: Upload complexity reports
      uses: actions/upload-artifact@v3
      with:
        name: complexity-reports
        path: |
          complexity_report.txt
          maintainability_report.txt
```

### Type Checking

#### `.github/workflows/type-checking.yml`
```yaml
name: Type Checking

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

jobs:
  type-check:
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'
        
    - name: Install dependencies
      run: |
        pip install mypy
        pip install -r requirements.txt
        
    - name: Run mypy type checking
      run: |
        echo "Running mypy type checking..."
        
        # Run mypy with strict configuration
        mypy src/hexstrike \
          --strict \
          --warn-return-any \
          --warn-unused-configs \
          --disallow-untyped-decorators \
          --disallow-any-generics \
          --disallow-subclassing-any \
          --warn-redundant-casts \
          --warn-unused-ignores \
          --warn-unreachable \
          --show-error-codes \
          --pretty
```

### Security Scanning

#### `.github/workflows/security.yml`
```yaml
name: Security Scanning

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'
        
    - name: Install security tools
      run: |
        pip install bandit safety semgrep
        
    - name: Run bandit security scan
      run: |
        echo "Running bandit security scan..."
        bandit -r src/ \
          -f json \
          -o bandit-report.json \
          --severity-level medium \
          --confidence-level medium
          
        # Check for high/medium severity issues
        high_issues=$(python3 -c "
        import json
        with open('bandit-report.json') as f:
            data = json.load(f)
            high = len([r for r in data.get('results', []) if r.get('issue_severity') in ['HIGH', 'MEDIUM']])
            print(high)
        ")
        
        if [ "$high_issues" -gt 0 ]; then
          echo "❌ FAIL: $high_issues high/medium severity security issues found"
          bandit -r src/ --severity-level medium
          exit 1
        else
          echo "✅ PASS: No high/medium severity security issues found"
        fi
        
    - name: Run safety dependency check
      run: |
        echo "Checking for known security vulnerabilities in dependencies..."
        safety check --json > safety-report.json || true
        
        vulnerabilities=$(python3 -c "
        import json
        try:
            with open('safety-report.json') as f:
                data = json.load(f)
                print(len(data))
        except:
            print(0)
        ")
        
        if [ "$vulnerabilities" -gt 0 ]; then
          echo "❌ FAIL: $vulnerabilities known vulnerabilities found in dependencies"
          safety check
          exit 1
        else
          echo "✅ PASS: No known vulnerabilities in dependencies"
        fi
        
    - name: Upload security reports
      uses: actions/upload-artifact@v3
      if: always()
      with:
        name: security-reports
        path: |
          bandit-report.json
          safety-report.json
```

### Comprehensive Quality Gate

#### `.github/workflows/quality-gate.yml`
```yaml
name: Quality Gate

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

jobs:
  quality-gate:
    runs-on: ubuntu-latest
    needs: [check-line-limits, detect-cycles, detect-duplication, analyze-complexity, type-check, security-scan]
    if: always()
    
    steps:
    - name: Check all quality gates
      run: |
        echo "Checking all quality gate results..."
        
        # Check if any job failed
        if [[ "${{ needs.check-line-limits.result }}" != "success" ]]; then
          echo "❌ Line limits check failed"
          exit 1
        fi
        
        if [[ "${{ needs.detect-cycles.result }}" != "success" ]]; then
          echo "❌ Import cycle detection failed"
          exit 1
        fi
        
        if [[ "${{ needs.detect-duplication.result }}" != "success" ]]; then
          echo "❌ Code duplication check failed"
          exit 1
        fi
        
        if [[ "${{ needs.analyze-complexity.result }}" != "success" ]]; then
          echo "❌ Code complexity check failed"
          exit 1
        fi
        
        if [[ "${{ needs.type-check.result }}" != "success" ]]; then
          echo "❌ Type checking failed"
          exit 1
        fi
        
        if [[ "${{ needs.security-scan.result }}" != "success" ]]; then
          echo "❌ Security scan failed"
          exit 1
        fi
        
        echo "✅ All quality gates passed!"
        
    - name: Generate quality report
      run: |
        echo "# Quality Gate Report" > quality_report.md
        echo "" >> quality_report.md
        echo "| Check | Status |" >> quality_report.md
        echo "|-------|--------|" >> quality_report.md
        echo "| Line Limits | ${{ needs.check-line-limits.result == 'success' && '✅ PASS' || '❌ FAIL' }} |" >> quality_report.md
        echo "| Import Cycles | ${{ needs.detect-cycles.result == 'success' && '✅ PASS' || '❌ FAIL' }} |" >> quality_report.md
        echo "| Code Duplication | ${{ needs.detect-duplication.result == 'success' && '✅ PASS' || '❌ FAIL' }} |" >> quality_report.md
        echo "| Code Complexity | ${{ needs.analyze-complexity.result == 'success' && '✅ PASS' || '❌ FAIL' }} |" >> quality_report.md
        echo "| Type Checking | ${{ needs.type-check.result == 'success' && '✅ PASS' || '❌ FAIL' }} |" >> quality_report.md
        echo "| Security Scan | ${{ needs.security-scan.result == 'success' && '✅ PASS' || '❌ FAIL' }} |" >> quality_report.md
```

## Local Development Tools

### Pre-commit Configuration

#### `.pre-commit-config.yaml`
```yaml
repos:
  - repo: local
    hooks:
      - id: line-limit-check
        name: Check line limits
        entry: bash -c 'find src/ -name "*.py" -not -path "*/legacy/*" | xargs wc -l | awk "$1 > 300 {print $2 \" exceeds 300 lines (\" $1 \")\"; exit 1}"'
        language: system
        files: \.py$
        
      - id: import-cycle-check
        name: Check import cycles
        entry: python -c "import grimp; graph = grimp.build_graph('src/hexstrike'); cycles = graph.find_cycles(); exit(1 if cycles else 0)"
        language: system
        files: \.py$
        
  - repo: https://github.com/psf/black
    rev: 23.3.0
    hooks:
      - id: black
        args: [--line-length=100]
        
  - repo: https://github.com/pycqa/isort
    rev: 5.12.0
    hooks:
      - id: isort
        args: [--profile=black, --line-length=100]
        
  - repo: https://github.com/pycqa/flake8
    rev: 6.0.0
    hooks:
      - id: flake8
        args: [--max-line-length=100, --max-complexity=12]
        
  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.3.0
    hooks:
      - id: mypy
        args: [--strict]
        
  - repo: https://github.com/PyCQA/bandit
    rev: 1.7.5
    hooks:
      - id: bandit
        args: [-r, src/, --severity-level, medium]
```

### Makefile for Local Quality Checks

#### `Makefile`
```makefile
.PHONY: quality-check line-limits import-cycles duplication complexity type-check security

# Run all quality checks
quality-check: line-limits import-cycles duplication complexity type-check security
	@echo "✅ All quality checks passed!"

# Check line limits
line-limits:
	@echo "Checking line limits..."
	@find src/ -name "*.py" -not -path "*/legacy/*" | while read file; do \
		lines=$$(wc -l < "$$file"); \
		if [ $$lines -gt 300 ]; then \
			echo "❌ $$file: $$lines lines (exceeds 300)"; \
			exit 1; \
		fi; \
	done
	@echo "✅ All modules within 300-line limit"

# Check import cycles
import-cycles:
	@echo "Checking import cycles..."
	@python -c "import grimp; graph = grimp.build_graph('src/hexstrike'); cycles = graph.find_cycles(); print('✅ No cycles' if not cycles else f'❌ Cycles: {cycles}'); exit(1 if cycles else 0)"

# Check code duplication
duplication:
	@echo "Checking code duplication..."
	@jscpd --threshold 3 --min-lines 5 --reporters console src/ || (echo "❌ Code duplication exceeds 3% threshold" && exit 1)
	@echo "✅ Code duplication within acceptable limits"

# Check code complexity
complexity:
	@echo "Checking code complexity..."
	@radon cc src/ -a -s | grep "Average complexity" || echo "No complexity data"
	@radon cc src/ -s | grep -E "\([1-9][2-9]|[2-9][0-9]\)" && (echo "❌ High complexity functions found" && exit 1) || echo "✅ No high complexity functions"

# Run type checking
type-check:
	@echo "Running type checking..."
	@mypy src/hexstrike --strict
	@echo "✅ Type checking passed"

# Run security checks
security:
	@echo "Running security checks..."
	@bandit -r src/ --severity-level medium --quiet
	@safety check --short-report
	@echo "✅ Security checks passed"

# Install development dependencies
install-dev:
	pip install grimp import-linter jscpd radon mypy bandit safety pre-commit
	pre-commit install

# Clean up generated files
clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf .mypy_cache/
	rm -rf duplication-report/
```

---

**Note:** These CI checks enforce the modularization principles by automatically validating line limits (≤300), import cycles (none allowed), code duplication (<3%), complexity (reasonable), type safety (strict), and security (no vulnerabilities).
