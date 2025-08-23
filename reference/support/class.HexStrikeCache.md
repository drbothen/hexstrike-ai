---
title: class.HexStrikeCache
kind: class
module: __main__
line_range: [6009, 6072]
discovered_in_chunk: 6
---

# HexStrikeCache Class

## Entity Classification & Context
- **Kind:** Class
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Advanced caching system for command results

## Complete Signature & Definition
```python
class HexStrikeCache:
    """Advanced caching system for command results"""
    
    def __init__(self, max_size: int = CACHE_SIZE, ttl: int = CACHE_TTL):
        self.cache = OrderedDict()
        self.max_size = max_size
        self.ttl = ttl
        self.stats = {"hits": 0, "misses": 0, "evictions": 0}
        
    def _generate_key(self, command: str, params: Dict[str, Any]) -> str:
        """Generate cache key from command and parameters"""
    
    def _is_expired(self, timestamp: float) -> bool:
        """Check if cache entry is expired"""
    
    def get(self, command: str, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Get cached result if available and not expired"""
    
    def set(self, command: str, params: Dict[str, Any], result: Dict[str, Any]):
        """Store result in cache"""
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
```

## Purpose & Behavior
Advanced caching system providing:
- **Command Result Caching:** Cache command execution results with parameters
- **TTL Management:** Time-based cache expiration with configurable TTL
- **LRU Eviction:** Least Recently Used eviction for memory management
- **Performance Analytics:** Hit/miss ratio tracking and cache statistics
- **MD5 Key Generation:** Secure key generation from command and parameters

## Dependencies & Usage
- **Depends on:**
  - collections.OrderedDict for LRU cache implementation
  - hashlib.md5 for key generation
  - json for parameter serialization
  - time for timestamp tracking
  - typing.Optional, Dict, Any for type annotations
  - CACHE_SIZE and CACHE_TTL constants
- **Used by:**
  - Command execution systems
  - Performance optimization frameworks
  - Result caching and retrieval systems

## Implementation Details

### Core Attributes
- **cache:** OrderedDict for LRU cache storage
- **max_size:** Maximum cache size (default: CACHE_SIZE)
- **ttl:** Time-to-live in seconds (default: CACHE_TTL)
- **stats:** Cache statistics tracking

### Key Methods

#### Cache Operations
1. **get(command: str, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:** Retrieve cached result if available and not expired
2. **set(command: str, params: Dict[str, Any], result: Dict[str, Any]):** Store result in cache
3. **get_stats() -> Dict[str, Any]:** Get comprehensive cache statistics

#### Internal Operations
4. **_generate_key(command: str, params: Dict[str, Any]) -> str:** Generate MD5 cache key
5. **_is_expired(timestamp: float) -> bool:** Check if cache entry is expired

### Cache Key Generation

#### Key Generation Algorithm
```python
key_data = f"{command}:{json.dumps(params, sort_keys=True)}"
return hashlib.md5(key_data.encode()).hexdigest()
```

#### Key Features
- **Command Integration:** Includes full command string
- **Parameter Serialization:** JSON serialization with sorted keys for consistency
- **MD5 Hashing:** Secure and consistent hash generation
- **Collision Resistance:** MD5 provides good collision resistance for cache keys

### TTL Management

#### Expiration Check
```python
def _is_expired(self, timestamp: float) -> bool:
    return time.time() - timestamp > self.ttl
```

#### TTL Features
- **Configurable TTL:** Uses CACHE_TTL constant (default: 3600 seconds)
- **Timestamp-based:** Uses creation timestamp for expiration calculation
- **Automatic Cleanup:** Expired entries removed on access

### Cache Retrieval Logic

#### Get Operation Flow
1. **Key Generation:** Generate MD5 key from command and parameters
2. **Existence Check:** Verify key exists in cache
3. **Expiration Check:** Validate entry hasn't expired
4. **LRU Update:** Move accessed entry to end (most recently used)
5. **Statistics Update:** Update hit/miss counters
6. **Cleanup:** Remove expired entries automatically

#### Cache Hit Handling
```python
if key in self.cache:
    timestamp, data = self.cache[key]
    if not self._is_expired(timestamp):
        self.cache.move_to_end(key)  # LRU update
        self.stats["hits"] += 1
        return data
    else:
        del self.cache[key]  # Remove expired
```

### Cache Storage Logic

#### Set Operation Flow
1. **Key Generation:** Generate cache key from command and parameters
2. **Capacity Management:** Remove oldest entries if cache is full
3. **Entry Storage:** Store timestamp and result data
4. **Statistics Update:** Update cache statistics

#### Capacity Management
```python
while len(self.cache) >= self.max_size:
    oldest_key = next(iter(self.cache))
    del self.cache[oldest_key]
    self.stats["evictions"] += 1
```

#### Storage Format
```python
self.cache[key] = (time.time(), result)
```

### LRU Eviction System

#### OrderedDict Integration
- **Insertion Order:** OrderedDict maintains insertion order
- **Move to End:** Recently accessed items moved to end
- **FIFO Eviction:** Oldest items (at beginning) evicted first

#### Eviction Process
- **Capacity Check:** Triggered when cache reaches max_size
- **Oldest First:** Remove items from beginning of OrderedDict
- **Statistics Tracking:** Count evictions for analytics

### Performance Analytics

#### Statistics Tracking
```python
self.stats = {
    "hits": 0,          # Successful cache retrievals
    "misses": 0,        # Failed cache retrievals
    "evictions": 0      # Number of evicted entries
}
```

#### Hit Rate Calculation
```python
total_requests = self.stats["hits"] + self.stats["misses"]
hit_rate = (self.stats["hits"] / total_requests * 100) if total_requests > 0 else 0
```

#### Statistics Output
```python
{
    "size": int,                    # Current cache size
    "max_size": int,                # Maximum cache capacity
    "hit_rate": str,                # Hit rate percentage
    "hits": int,                    # Total cache hits
    "misses": int,                  # Total cache misses
    "evictions": int                # Total evictions
}
```

### Logging Integration

#### Cache Operations Logging
- **Cache Hit:** Log successful cache retrieval with command
- **Cache Miss:** Log cache miss with command
- **Cache Set:** Log result storage with command

#### Log Messages
- **Hit:** "💾 Cache HIT for command: {command}"
- **Miss:** "🔍 Cache MISS for command: {command}"
- **Set:** "💾 Cached result for command: {command}"

### Error Handling and Resilience

#### Graceful Degradation
- **Key Generation Errors:** Handle JSON serialization errors
- **Cache Operation Errors:** Continue operation despite cache failures
- **Memory Pressure:** LRU eviction prevents memory exhaustion

#### Robustness Features
- **Consistent State:** Cache always in consistent state
- **Atomic Operations:** Cache operations are atomic
- **Error Recovery:** Graceful handling of cache errors

### Integration with Command Execution

#### Command Result Caching
- **Parameter Awareness:** Cache considers both command and parameters
- **Result Validation:** Only cache valid command results
- **Performance Optimization:** Avoid repeated command execution

#### Cache Strategy
- **Command Hashing:** Use command and parameters for cache key
- **Result Storage:** Store complete command execution results
- **TTL Management:** Configurable cache duration

### Use Cases and Applications

#### Performance Optimization
- **Command Caching:** Cache expensive command execution results
- **Parameter Sensitivity:** Handle parameter variations correctly
- **Memory Management:** Efficient memory usage with LRU eviction

#### Development and Testing
- **Faster Iterations:** Avoid re-executing expensive commands during development
- **Consistent Results:** Provide consistent results for same command/parameter combinations
- **Performance Testing:** Measure cache effectiveness with statistics

### Configuration Integration

#### Constant Integration
- **CACHE_SIZE:** Default maximum cache size (1000 entries)
- **CACHE_TTL:** Default time-to-live (3600 seconds)
- **Configurable Limits:** Adjustable cache parameters

## Testing & Validation
- Cache key generation consistency testing
- TTL expiration behavior validation
- LRU eviction correctness verification
- Performance analytics accuracy testing

## Code Reproduction
Complete class implementation with 5 methods for advanced command result caching, including MD5 key generation, TTL management, LRU eviction, and comprehensive performance analytics. Essential for command execution optimization and performance enhancement.
