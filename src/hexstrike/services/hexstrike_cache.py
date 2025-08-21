"""
HexStrike caching service with intelligent cache management.

This module changes when caching strategies or cache management policies change.
"""

import hashlib
import time
import logging
from typing import Dict, Any, Optional
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class HexStrikeCache:
    """Advanced caching system with TTL and intelligent invalidation"""
    
    def __init__(self, default_ttl: int = 3600):
        self.cache = {}
        self.metadata = {}
        self.default_ttl = default_ttl
        self.hits = 0
        self.misses = 0
    
    def _generate_key(self, command: str, params: Dict[str, Any]) -> str:
        """Generate cache key from command and parameters"""
        key_data = f"{command}:{str(sorted(params.items()))}"
        return hashlib.md5(key_data.encode()).hexdigest()
    
    def _is_expired(self, key: str) -> bool:
        """Check if cache entry is expired"""
        if key not in self.metadata:
            return True
        
        expiry_time = self.metadata[key].get('expires_at', 0)
        return time.time() > expiry_time
    
    def get(self, command: str, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Get cached result if available and not expired"""
        key = self._generate_key(command, params)
        
        if key in self.cache and not self._is_expired(key):
            self.hits += 1
            result = self.cache[key].copy()
            
            result['_cache_hit'] = True
            result['_cached_at'] = self.metadata[key]['cached_at']
            
            logger.debug(f"🎯 Cache HIT for command: {command[:50]}...")
            return result
        elif key in self.cache:
            # Remove expired entry
            del self.cache[key]
            del self.metadata[key]
            logger.debug(f"🗑️ Removed expired cache entry for: {command[:50]}...")
        
        self.misses += 1
        logger.debug(f"❌ Cache MISS for command: {command[:50]}...")
        return None
    
    def set(self, command: str, params: Dict[str, Any], result: Dict[str, Any], ttl: int = None) -> None:
        """Cache the result with TTL"""
        key = self._generate_key(command, params)
        ttl = ttl or self.default_ttl
        
        clean_result = {k: v for k, v in result.items() if not k.startswith('_cache')}
        self.cache[key] = clean_result
        
        self.metadata[key] = {
            'cached_at': datetime.now().isoformat(),
            'expires_at': time.time() + ttl,
            'command': command[:100],  # Store truncated command for debugging
            'ttl': ttl
        }
        
        logger.debug(f"💾 Cached result for: {command[:50]}... (TTL: {ttl}s)")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        total_requests = self.hits + self.misses
        hit_rate = (self.hits / total_requests * 100) if total_requests > 0 else 0
        
        return {
            'hits': self.hits,
            'misses': self.misses,
            'hit_rate': f"{hit_rate:.1f}%",
            'total_entries': len(self.cache),
            'cache_size_mb': len(str(self.cache)) / (1024 * 1024)
        }
