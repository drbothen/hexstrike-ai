"""
Cache management endpoint handlers.

This module changes when cache management requirements change.
"""

from typing import Dict, Any
from flask import jsonify
import logging
import time

logger = logging.getLogger(__name__)

class CacheEndpoints:
    """Cache management endpoint handlers"""
    
    def __init__(self):
        self.cache = {}
        self.cache_stats = {
            "hits": 0,
            "misses": 0,
            "created": time.time()
        }
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        try:
            stats = {
                "cache_size": len(self.cache),
                "hits": self.cache_stats["hits"],
                "misses": self.cache_stats["misses"],
                "hit_rate": self.cache_stats["hits"] / max(1, self.cache_stats["hits"] + self.cache_stats["misses"]),
                "created": self.cache_stats["created"],
                "uptime": time.time() - self.cache_stats["created"]
            }
            
            logger.info(f"📊 Cache stats: {len(self.cache)} items, {stats['hit_rate']:.2%} hit rate")
            
            return jsonify(stats)
            
        except Exception as e:
            logger.error(f"💥 Error getting cache stats: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500
    
    def clear_cache(self) -> Dict[str, Any]:
        """Clear the cache"""
        try:
            cache_size = len(self.cache)
            self.cache.clear()
            
            logger.info(f"🗑️ Cache cleared: {cache_size} items removed")
            
            return jsonify({
                "success": True,
                "message": f"Cache cleared: {cache_size} items removed",
                "timestamp": time.time()
            })
            
        except Exception as e:
            logger.error(f"💥 Error clearing cache: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500
