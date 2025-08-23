---
title: class.RateLimitDetector
kind: class
module: __main__
line_range: [4344, 4447]
discovered_in_chunk: 3
---

# RateLimitDetector Class

## Entity Classification & Context
- **Kind:** Class
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Intelligent rate limiting detection and automatic timing adjustment

## Complete Signature & Definition
```python
class RateLimitDetector:
    """Intelligent rate limiting detection and automatic timing adjustment"""
    
    def __init__(self):
        self.rate_limit_indicators = [
            # Rate limiting detection patterns
        ]
        
        self.timing_profiles = {
            # Predefined timing profiles for different scenarios
        }
```

## Purpose & Behavior
Intelligent rate limiting detection and mitigation system providing:
- **Rate Limit Detection:** Multi-source rate limiting identification
- **Confidence Scoring:** Probabilistic assessment of rate limiting presence
- **Timing Profile Recommendation:** Automatic timing adjustment based on detection confidence
- **Parameter Adjustment:** Dynamic tool parameter modification for rate limit avoidance

## Dependencies & Usage
- **Depends on:**
  - typing.Dict, Any for type annotations
  - re module for parameter adjustment
  - HTTP response data and headers
- **Used by:**
  - Tool parameter optimization systems
  - Automated testing frameworks
  - Rate limit avoidance mechanisms

## Implementation Details

### Core Attributes
- **rate_limit_indicators:** Comprehensive rate limiting detection patterns
- **timing_profiles:** Predefined timing configurations for different scenarios

### Key Methods

#### Rate Limit Detection
1. **detect_rate_limiting(response_text: str, status_code: int, headers: Dict[str, str] = None) -> Dict[str, Any]:** Main rate limit detection
2. **_recommend_timing_profile(confidence: float) -> str:** Timing profile recommendation based on confidence
3. **adjust_timing(current_params: Dict[str, Any], profile: str) -> Dict[str, Any]:** Parameter adjustment for rate limit avoidance

### Rate Limiting Detection System

#### Detection Indicators (9 Patterns)
- **"rate limit":** Direct rate limiting message
- **"too many requests":** Common rate limiting response
- **"429":** HTTP 429 status code reference
- **"throttle":** Throttling indication
- **"slow down":** Rate limiting advisory
- **"retry after":** Retry-After header indication
- **"quota exceeded":** API quota limit reached
- **"api limit":** API rate limit indication
- **"request limit":** Request rate limit indication

#### Detection Sources (3 Sources)

##### HTTP Status Code Analysis
- **429 Status:** Primary rate limiting indicator (0.8 confidence boost)
- **Status Code Weight:** High confidence for explicit rate limiting status

##### Response Text Analysis
- **Pattern Matching:** Searches response text for rate limiting indicators
- **Confidence Accumulation:** Each indicator adds 0.2 confidence
- **Case Insensitive:** Handles various text formatting

##### Header Analysis
- **Rate Limit Headers:** "x-ratelimit", "retry-after", "x-rate-limit"
- **Header Detection:** Searches header names for rate limiting indicators
- **Confidence Boost:** Each header adds 0.3 confidence

### Timing Profiles (4 Profiles)

#### Aggressive Profile
- **Delay:** 0.1 seconds
- **Threads:** 50 concurrent
- **Timeout:** 5 seconds
- **Use Case:** Fast scanning when no rate limiting detected

#### Normal Profile
- **Delay:** 0.5 seconds
- **Threads:** 20 concurrent
- **Timeout:** 10 seconds
- **Use Case:** Standard scanning with moderate rate limiting risk

#### Conservative Profile
- **Delay:** 1.0 seconds
- **Threads:** 10 concurrent
- **Timeout:** 15 seconds
- **Use Case:** Cautious scanning with likely rate limiting

#### Stealth Profile
- **Delay:** 2.0 seconds
- **Threads:** 5 concurrent
- **Timeout:** 30 seconds
- **Use Case:** Maximum stealth with confirmed rate limiting

### Detection Output Structure
```python
{
    "detected": bool,                    # Rate limiting detected
    "confidence": float,                 # Detection confidence (0.0-1.0)
    "indicators": List[str],             # Found indicators
    "recommended_profile": str           # Recommended timing profile
}
```

### Confidence-based Profile Recommendation

#### Profile Selection Logic
- **High Confidence (≥0.8):** Stealth profile for confirmed rate limiting
- **Medium-High Confidence (≥0.5):** Conservative profile for likely rate limiting
- **Medium Confidence (≥0.2):** Normal profile for possible rate limiting
- **Low Confidence (<0.2):** Aggressive profile for unlikely rate limiting

#### Confidence Calculation
- **Maximum Confidence:** Capped at 1.0 to prevent overflow
- **Additive Scoring:** Multiple indicators increase confidence
- **Weighted Indicators:** Different sources have different confidence weights

### Parameter Adjustment System

#### Timing Parameter Adjustment
- **Threads:** Adjusts concurrent thread count based on profile
- **Delay:** Sets inter-request delay based on profile
- **Timeout:** Adjusts request timeout based on profile

#### Tool-specific Adjustments
- **Argument Cleaning:** Removes existing timing arguments using regex
- **Argument Addition:** Adds new timing arguments based on profile
- **Parameter Preservation:** Maintains other parameters while adjusting timing

#### Regex-based Parameter Cleaning
```python
# Remove existing timing arguments
args = re.sub(r'-t\s+\d+', '', args)           # Thread count
args = re.sub(r'--threads\s+\d+', '', args)    # Thread parameter
args = re.sub(r'--delay\s+[\d.]+', '', args)   # Delay parameter
```

#### Parameter Addition Logic
```python
# Add new timing arguments
args += f" -t {timing['threads']}"              # Thread count
if timing["delay"] > 0:
    args += f" --delay {timing['delay']}"       # Delay if needed
```

### Rate Limiting Mitigation Strategies

#### Proactive Detection
- **Early Warning:** Detect rate limiting before complete blocking
- **Gradual Adjustment:** Progressively reduce request rate
- **Adaptive Behavior:** Learn from rate limiting patterns

#### Reactive Adjustment
- **Immediate Response:** Adjust parameters upon detection
- **Profile Switching:** Change timing profile based on confidence
- **Parameter Optimization:** Fine-tune timing for specific targets

#### Stealth Considerations
- **Low Profile:** Reduce detection probability
- **Natural Patterns:** Mimic human browsing patterns
- **Distributed Timing:** Spread requests over time

### Integration with Security Tools

#### Common Tool Parameters
- **Gobuster:** Thread count (-t), delay (--delay)
- **Dirb:** Thread count, delay parameters
- **Nuclei:** Rate limiting options
- **Custom Tools:** Generic parameter adjustment

#### Parameter Mapping
- **Thread Control:** Adjust concurrent request limits
- **Delay Control:** Set inter-request delays
- **Timeout Control:** Adjust request timeouts

## Testing & Validation
- Rate limiting detection accuracy testing
- Confidence scoring precision validation
- Timing profile effectiveness assessment
- Parameter adjustment functionality verification

## Code Reproduction
Complete class implementation with 3 methods for intelligent rate limiting detection and automatic timing adjustment, including multi-source detection, confidence-based profile recommendation, and dynamic parameter adjustment. Essential for automated security testing and rate limit avoidance.
