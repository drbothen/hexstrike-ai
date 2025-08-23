---
title: POST /api/vuln-intel/threat-feeds
group: api
handler: threat_intelligence_feeds
module: __main__
line_range: [13821, 13954]
discovered_in_chunk: 14
---

# POST /api/vuln-intel/threat-feeds

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Aggregate and correlate threat intelligence from multiple sources

## Complete Signature & Definition
```python
@app.route("/api/vuln-intel/threat-feeds", methods=["POST"])
def threat_intelligence_feeds():
    """Aggregate and correlate threat intelligence from multiple sources"""
```

## Purpose & Behavior
Threat intelligence correlation endpoint providing:
- **Multi-Source Aggregation:** Correlate threat intelligence from multiple sources
- **Indicator Analysis:** Analyze CVE, IP, and hash indicators
- **Threat Scoring:** Calculate overall threat scores based on indicators
- **Actionable Recommendations:** Provide security recommendations based on analysis

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/vuln-intel/threat-feeds
- **Content-Type:** application/json

### Request Body
```json
{
    "indicators": ["CVE-2024-1234", "192.168.1.100", "hash123"],  // Required: List of indicators to analyze
    "timeframe": "string",              // Optional: Analysis timeframe (default: "30d")
    "sources": "string"                 // Optional: Threat intelligence sources (default: "all")
}
```

### Parameters
- **indicators:** List of threat indicators (CVEs, IPs, hashes) to analyze (required)
- **timeframe:** Timeframe for threat intelligence analysis (optional, default: "30d")
- **sources:** Threat intelligence sources to use (optional, default: "all")

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "threat_intelligence": {
        "indicators_analyzed": ["CVE-2024-1234", "192.168.1.100"],
        "timeframe": "30d",
        "sources": "all",
        "correlations": [
            {
                "indicator": "CVE-2024-1234",
                "type": "cve",
                "analysis": {
                    "exploitability_level": "HIGH",
                    "exploitability_score": 85
                },
                "threat_level": "HIGH"
            }
        ],
        "threat_score": 75.5,
        "recommendations": [
            "Immediate threat response required",
            "Block identified indicators",
            "Enhance monitoring for related IOCs"
        ]
    },
    "timestamp": "2024-01-01T12:00:00Z"
}
```

### Error Responses

#### Missing Indicators (400 Bad Request)
```json
{
    "success": false,
    "error": "Indicators parameter is required"
}
```

#### Server Error (500 Internal Server Error)
```json
{
    "success": false,
    "error": "Server error: {error_message}"
}
```

## Code Reproduction
```python
@app.route("/api/vuln-intel/threat-feeds", methods=["POST"])
def threat_intelligence_feeds():
    """Aggregate and correlate threat intelligence from multiple sources"""
    try:
        params = request.json
        indicators = params.get("indicators", [])
        timeframe = params.get("timeframe", "30d")
        sources = params.get("sources", "all")
        
        if isinstance(indicators, str):
            indicators = [i.strip() for i in indicators.split(",")]
        
        if not indicators:
            logger.warning("🧠 Threat intelligence called without indicators")
            return jsonify({
                "success": False,
                "error": "Indicators parameter is required"
            }), 400
        
        logger.info(f"🧠 Correlating threat intelligence for {len(indicators)} indicators")
        
        correlation_results = {
            "indicators_analyzed": indicators,
            "timeframe": timeframe,
            "sources": sources,
            "correlations": [],
            "threat_score": 0,
            "recommendations": []
        }
        
        # Analyze each indicator
        cve_indicators = [i for i in indicators if i.startswith("CVE-")]
        ip_indicators = [i for i in indicators if i.replace(".", "").isdigit()]
        hash_indicators = [i for i in indicators if len(i) in [32, 40, 64] and all(c in "0123456789abcdef" for c in i.lower())]
        
        # Process CVE indicators
        for cve_id in cve_indicators:
            try:
                cve_analysis = cve_intelligence.analyze_cve_exploitability(cve_id)
                if cve_analysis.get("success"):
                    correlation_results["correlations"].append({
                        "indicator": cve_id,
                        "type": "cve",
                        "analysis": cve_analysis,
                        "threat_level": cve_analysis.get("exploitability_level", "UNKNOWN")
                    })
                    
                    # Add to threat score
                    exploit_score = cve_analysis.get("exploitability_score", 0)
                    correlation_results["threat_score"] += min(exploit_score, 100)
                    
                # Search for existing exploits
                exploits = cve_intelligence.search_existing_exploits(cve_id)
                if exploits.get("success") and exploits.get("total_exploits", 0) > 0:
                    correlation_results["correlations"].append({
                        "indicator": cve_id,
                        "type": "exploit_availability",
                        "exploits_found": exploits.get("total_exploits", 0),
                        "threat_level": "HIGH"
                    })
                    correlation_results["threat_score"] += 25
                    
            except Exception as e:
                logger.warning(f"Error analyzing CVE {cve_id}: {str(e)}")
        
        # Process IP indicators (basic reputation check simulation)
        for ip in ip_indicators:
            # Simulate threat intelligence lookup
            correlation_results["correlations"].append({
                "indicator": ip,
                "type": "ip_reputation",
                "analysis": {
                    "reputation": "unknown",
                    "geolocation": "unknown",
                    "associated_threats": []
                },
                "threat_level": "MEDIUM"  # Default for unknown IPs
            })
        
        # Process hash indicators
        for hash_val in hash_indicators:
            correlation_results["correlations"].append({
                "indicator": hash_val,
                "type": "file_hash",
                "analysis": {
                    "hash_type": f"hash{len(hash_val)}",
                    "malware_family": "unknown",
                    "detection_rate": "unknown"
                },
                "threat_level": "MEDIUM"
            })
        
        # Calculate overall threat score and generate recommendations
        total_indicators = len(indicators)
        if total_indicators > 0:
            correlation_results["threat_score"] = min(correlation_results["threat_score"] / total_indicators, 100)
            
            if correlation_results["threat_score"] >= 75:
                correlation_results["recommendations"] = [
                    "Immediate threat response required",
                    "Block identified indicators",
                    "Enhance monitoring for related IOCs",
                    "Implement emergency patches for identified CVEs"
                ]
            elif correlation_results["threat_score"] >= 50:
                correlation_results["recommendations"] = [
                    "Elevated threat level detected",
                    "Increase monitoring for identified indicators",
                    "Plan patching for identified vulnerabilities",
                    "Review security controls"
                ]
            else:
                correlation_results["recommendations"] = [
                    "Low to medium threat level",
                    "Continue standard monitoring",
                    "Plan routine patching",
                    "Consider additional threat intelligence sources"
                ]
        
        result = {
            "success": True,
            "threat_intelligence": correlation_results,
            "timestamp": datetime.now().isoformat()
        }
        
        logger.info(f"🎯 Threat intelligence correlation completed | Threat Score: {correlation_results['threat_score']:.1f}")
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"💥 Error in threat intelligence: {str(e)}")
        return jsonify({
            "success": False,
            "error": f"Server error: {str(e)}"
        }), 500
```
