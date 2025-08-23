---
title: class.AdvancedCache
kind: class
module: __main__
line_range: [5085, 5206]
discovered_in_chunk: 4
---

# AdvancedCache Class

## Entity Classification & Context
- **Kind:** Class
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Advanced caching system with intelligent TTL and LRU eviction

## Complete Signature & Definition
```python
class AdvancedCache:
    """Advanced caching system with intelligent TTL and LRU eviction"""
    
    def __init__(self, max_size=1000, default_ttl=3600):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.cache = {}
        self.access_times = {}
        self.ttl_times = {}
        self.cache_lock = threading.RLock()
        self.hit_count = 0
        self.miss_count = 0
```

## Purpose & Behavior
Advanced caching system providing:
- **Intelligent TTL Management:** Time-based cache expiration with configurable TTL
- **LRU Eviction Policy:** Least Recently Used eviction for memory management
- **Thread-safe Operations:** Concurrent access support with RLock synchronization
- **Performance Analytics:** Hit/miss ratio tracking and cache statistics
- **Automatic Cleanup:** Background cleanup of expired entries

## Dependencies & Usage
- **Depends on:**
  - threading.RLock for thread synchronization
  - time module for timestamp tracking and TTL management
  - typing.Any for value type flexibility
- **Used by:**
  - EnhancedProcessManager for command result caching
  - Performance optimization systems
  - Data caching and retrieval frameworks

## Implementation Details

### Core Attributes
- **max_size:** Maximum cache size (default: 1000 entries)
- **default_ttl:** Default time-to-live in seconds (default: 3600 = 1 hour)
- **cache:** Main cache storage dictionary
- **access_times:** LRU tracking with access timestamps
- **ttl_times:** TTL tracking with expiration timestamps
- **cache_lock:** Thread synchronization RLock
- **hit_count:** Cache hit counter for analytics
- **miss_count:** Cache miss counter for analytics

### Key Methods

#### Cache Operations
1. **get(key: str) -> Any:** Retrieve value from cache with TTL and LRU handling
2. **set(key: str, value: Any, ttl: int = None) -> None:** Store value with optional TTL
3. **delete(key: str) -> bool:** Remove specific key from cache
4. **clear() -> None:** Clear all cache entries

#### Internal Management
5. **_remove_key(key: str) -> None:** Internal key removal with metadata cleanup
6. **_evict_lru() -> None:** Evict least recently used entry
7. **_cleanup_expired() -> None:** Background cleanup of expired entries
8. **get_stats() -> Dict[str, Any]:** Get comprehensive cache statistics

### Cache Retrieval Logic

#### Get Operation Flow
1. **Existence Check:** Verify key exists in cache
2. **TTL Validation:** Check if entry has expired
3. **Access Update:** Update access time for LRU tracking
4. **Hit/Miss Tracking:** Update performance counters
5. **Cleanup:** Remove expired entries automatically

#### TTL Validation
```python
if key in self.cache and (key not in self.ttl_times or self.ttl_times[key] > current_time):
    # Valid entry - update access time and return
    self.access_times[key] = current_time
    self.hit_count += 1
    return self.cache[key]
```

#### Expiration Handling
- **Automatic Removal:** Expired entries removed on access
- **Miss Counting:** Expired entries count as cache misses
- **Cleanup Integration:** Expired entry cleanup during retrieval

### Cache Storage Logic

#### Set Operation Flow
1. **TTL Configuration:** Use provided TTL or default
2. **Capacity Check:** Verify cache capacity and evict if needed
3. **Entry Storage:** Store value with metadata
4. **Metadata Update:** Update access and TTL timestamps

#### Capacity Management
```python
if len(self.cache) >= self.max_size and key not in self.cache:
    self._evict_lru()
```

#### Metadata Management
- **Access Time:** Current timestamp for LRU tracking
- **TTL Time:** Current timestamp + TTL for expiration tracking
- **Atomic Updates:** All metadata updated together

### LRU Eviction System

#### Eviction Trigger
- **Capacity Limit:** Triggered when cache reaches max_size
- **New Entry Only:** Only evicts for new entries (not updates)

#### LRU Selection Algorithm
```python
lru_key = min(self.access_times.keys(), key=lambda k: self.access_times[k])
```

#### Eviction Process
1. **LRU Identification:** Find least recently accessed key
2. **Complete Removal:** Remove from all data structures
3. **Logging:** Debug log of evicted entry

### TTL Management System

#### TTL Configuration
- **Default TTL:** 3600 seconds (1 hour) if not specified
- **Custom TTL:** Per-entry TTL override capability
- **TTL Calculation:** Current time + TTL for expiration timestamp

#### Expiration Detection
- **Access-time Checking:** TTL validation on every get operation
- **Background Cleanup:** Periodic cleanup of expired entries
- **Immediate Removal:** Expired entries removed immediately on detection

### Background Cleanup System

#### Cleanup Thread
- **Daemon Thread:** Background cleanup thread started on initialization
- **Cleanup Interval:** 60-second cleanup cycle
- **Continuous Operation:** Runs for cache lifetime

#### Cleanup Process
1. **Expiration Scan:** Identify all expired entries
2. **Batch Removal:** Remove all expired entries in batch
3. **Logging:** Debug log of cleanup statistics

#### Cleanup Algorithm
```python
current_time = time.time()
expired_keys = []

for key, expiry_time in self.ttl_times.items():
    if expiry_time <= current_time:
        expired_keys.append(key)

for key in expired_keys:
    self._remove_key(key)
```

### Thread Safety and Synchronization

#### RLock Usage
- **Reentrant Lock:** Allows recursive locking within same thread
- **Operation Protection:** All cache operations protected by lock
- **Deadlock Prevention:** Careful lock ordering and release

#### Atomic Operations
- **Metadata Consistency:** All related metadata updated atomically
- **State Consistency:** Cache state always consistent across operations
- **Race Condition Prevention:** Proper synchronization of concurrent access

### Performance Analytics

#### Hit/Miss Tracking
- **Hit Count:** Successful cache retrievals
- **Miss Count:** Failed cache retrievals (not found or expired)
- **Hit Rate Calculation:** (hits / total_requests) * 100

#### Cache Statistics
```python
{
    "size": int,                    # Current cache size
    "max_size": int,                # Maximum cache capacity
    "hit_count": int,               # Total cache hits
    "miss_count": int,              # Total cache misses
    "hit_rate": float,              # Hit rate percentage
    "utilization": float            # Cache utilization percentage
}
```

#### Performance Metrics
- **Utilization:** (current_size / max_size) * 100
- **Hit Rate:** (hit_count / total_requests) * 100
- **Total Requests:** hit_count + miss_count

### Error Handling and Resilience

#### Exception Safety
- **Cleanup Errors:** Graceful handling of cleanup thread errors
- **Operation Errors:** Safe fallback for cache operation failures
- **Lock Errors:** Proper lock release in exception scenarios

#### Graceful Degradation
- **Cleanup Failures:** Continue operation despite cleanup errors
- **Memory Pressure:** LRU eviction prevents memory exhaustion
- **TTL Failures:** Fallback to LRU eviction if TTL fails

### Cache Key Management

#### Key Operations
- **String Keys:** Consistent string-based key interface
- **Key Validation:** Implicit key validation through dictionary operations
- **Key Cleanup:** Complete key removal from all data structures

#### Metadata Synchronization
- **Consistent State:** All key-related metadata kept in sync
- **Atomic Removal:** Complete key and metadata removal
- **State Integrity:** Cache state always consistent

### Integration with Process Management

#### Command Result Caching
- **Result Storage:** Cache command execution results
- **TTL Configuration:** Configurable cache duration for results
- **Performance Optimization:** Avoid repeated command execution

#### Cache Key Strategy
- **Command Hashing:** Use command hash as cache key
- **Result Validation:** Cache only successful command results
- **Context Awareness:** Consider context in cache key generation

## Testing & Validation
- TTL expiration accuracy testing
- LRU eviction behavior validation
- Thread safety and concurrency testing
- Performance analytics accuracy verification

## Code Reproduction
Complete class implementation with 8 methods for advanced caching with intelligent TTL and LRU eviction, including thread-safe operations, performance analytics, and automatic cleanup. Essential for high-performance caching and memory management.
