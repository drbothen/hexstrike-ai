"""
Performance dashboard service for real-time monitoring.

This module changes when dashboard requirements or visualization needs change.
"""

from typing import Dict, Any, List
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class PerformanceDashboard:
    """Real-time performance monitoring dashboard"""
    
    def __init__(self):
        self.active_operations = {}
        self.completed_operations = []
        self.system_alerts = []
        self.performance_metrics = {}
        self.dashboard_config = self._initialize_dashboard_config()
    
    def _initialize_dashboard_config(self) -> Dict[str, Any]:
        """Initialize dashboard configuration"""
        return {
            "refresh_interval": 5,
            "max_completed_operations": 100,
            "max_system_alerts": 50,
            "alert_thresholds": {
                "cpu_high": 80.0,
                "memory_high": 85.0,
                "disk_high": 90.0,
                "response_time_high": 5.0
            },
            "colors": {
                "success": "\033[92m",
                "warning": "\033[93m",
                "error": "\033[91m",
                "info": "\033[94m",
                "reset": "\033[0m"
            }
        }
    
    def register_operation(self, operation_id: str, operation_type: str, 
                          details: Dict[str, Any] = None) -> None:
        """Register a new operation for monitoring"""
        if details is None:
            details = {}
        
        self.active_operations[operation_id] = {
            "id": operation_id,
            "type": operation_type,
            "start_time": datetime.now(),
            "status": "running",
            "progress": 0.0,
            "details": details,
            "metrics": {
                "cpu_usage": 0.0,
                "memory_usage": 0.0,
                "network_io": 0.0
            }
        }
        
        logger.info(f"Registered operation: {operation_id} ({operation_type})")
    
    def update_operation(self, operation_id: str, status: str = None, 
                        progress: float = None, metrics: Dict[str, Any] = None) -> None:
        """Update operation status and metrics"""
        if operation_id not in self.active_operations:
            logger.warning(f"Operation {operation_id} not found for update")
            return
        
        operation = self.active_operations[operation_id]
        
        if status:
            operation["status"] = status
        
        if progress is not None:
            operation["progress"] = min(100.0, max(0.0, progress))
        
        if metrics:
            operation["metrics"].update(metrics)
        
        operation["last_update"] = datetime.now()
        
        if status in ["completed", "failed", "cancelled"]:
            self._complete_operation(operation_id)
    
    def _complete_operation(self, operation_id: str) -> None:
        """Move operation from active to completed"""
        if operation_id in self.active_operations:
            operation = self.active_operations.pop(operation_id)
            operation["end_time"] = datetime.now()
            operation["duration"] = (operation["end_time"] - operation["start_time"]).total_seconds()
            
            self.completed_operations.append(operation)
            
            if len(self.completed_operations) > self.dashboard_config["max_completed_operations"]:
                self.completed_operations = self.completed_operations[-self.dashboard_config["max_completed_operations"]:]
            
            logger.info(f"Completed operation: {operation_id} ({operation['status']})")
    
    def add_system_alert(self, alert_type: str, message: str, 
                        severity: str = "info", details: Dict[str, Any] = None) -> None:
        """Add system alert to dashboard"""
        if details is None:
            details = {}
        
        alert = {
            "timestamp": datetime.now(),
            "type": alert_type,
            "message": message,
            "severity": severity,
            "details": details,
            "acknowledged": False
        }
        
        self.system_alerts.append(alert)
        
        if len(self.system_alerts) > self.dashboard_config["max_system_alerts"]:
            self.system_alerts = self.system_alerts[-self.dashboard_config["max_system_alerts"]:]
        
        logger.info(f"System alert: {severity.upper()} - {message}")
    
    def update_system_metrics(self, metrics: Dict[str, Any]) -> None:
        """Update system-wide performance metrics"""
        self.performance_metrics.update({
            "timestamp": datetime.now(),
            **metrics
        })
        
        self._check_alert_thresholds(metrics)
    
    def _check_alert_thresholds(self, metrics: Dict[str, Any]) -> None:
        """Check metrics against alert thresholds"""
        thresholds = self.dashboard_config["alert_thresholds"]
        
        if "cpu_percent" in metrics and metrics["cpu_percent"] > thresholds["cpu_high"]:
            self.add_system_alert(
                "high_cpu_usage",
                f"CPU usage is {metrics['cpu_percent']:.1f}%",
                "warning",
                {"cpu_percent": metrics["cpu_percent"]}
            )
        
        if "memory_percent" in metrics and metrics["memory_percent"] > thresholds["memory_high"]:
            self.add_system_alert(
                "high_memory_usage",
                f"Memory usage is {metrics['memory_percent']:.1f}%",
                "warning",
                {"memory_percent": metrics["memory_percent"]}
            )
        
        if "disk_percent" in metrics and metrics["disk_percent"] > thresholds["disk_high"]:
            self.add_system_alert(
                "high_disk_usage",
                f"Disk usage is {metrics['disk_percent']:.1f}%",
                "error",
                {"disk_percent": metrics["disk_percent"]}
            )
    
    def get_dashboard_data(self) -> Dict[str, Any]:
        """Get complete dashboard data"""
        return {
            "timestamp": datetime.now().isoformat(),
            "active_operations": list(self.active_operations.values()),
            "recent_completed": self.completed_operations[-10:],
            "recent_alerts": [alert for alert in self.system_alerts[-10:] if not alert["acknowledged"]],
            "system_metrics": self.performance_metrics,
            "summary": {
                "active_count": len(self.active_operations),
                "completed_count": len(self.completed_operations),
                "alert_count": len([a for a in self.system_alerts if not a["acknowledged"]]),
                "total_operations": len(self.active_operations) + len(self.completed_operations)
            }
        }
    
    def get_operation_summary(self) -> Dict[str, Any]:
        """Get summary of operations by type and status"""
        summary = {
            "by_type": {},
            "by_status": {},
            "performance": {
                "average_duration": 0.0,
                "success_rate": 0.0,
                "total_operations": 0
            }
        }
        
        all_operations = list(self.active_operations.values()) + self.completed_operations
        
        for op in all_operations:
            op_type = op["type"]
            op_status = op["status"]
            
            summary["by_type"][op_type] = summary["by_type"].get(op_type, 0) + 1
            summary["by_status"][op_status] = summary["by_status"].get(op_status, 0) + 1
        
        completed_ops = [op for op in self.completed_operations if "duration" in op]
        if completed_ops:
            total_duration = sum(op["duration"] for op in completed_ops)
            summary["performance"]["average_duration"] = total_duration / len(completed_ops)
            
            successful_ops = len([op for op in completed_ops if op["status"] == "completed"])
            summary["performance"]["success_rate"] = successful_ops / len(completed_ops)
        
        summary["performance"]["total_operations"] = len(all_operations)
        
        return summary
    
    def render_dashboard(self) -> str:
        """Render dashboard as formatted text"""
        colors = self.dashboard_config["colors"]
        dashboard_data = self.get_dashboard_data()
        
        output = []
        output.append(f"{colors['info']}{'='*80}{colors['reset']}")
        output.append(f"{colors['info']}HexStrike AI Performance Dashboard{colors['reset']}")
        output.append(f"{colors['info']}{'='*80}{colors['reset']}")
        output.append(f"Last Updated: {dashboard_data['timestamp']}")
        output.append("")
        
        output.append(f"{colors['info']}System Metrics:{colors['reset']}")
        if dashboard_data["system_metrics"]:
            metrics = dashboard_data["system_metrics"]
            output.append(f"  CPU: {metrics.get('cpu_percent', 0):.1f}%")
            output.append(f"  Memory: {metrics.get('memory_percent', 0):.1f}%")
            output.append(f"  Disk: {metrics.get('disk_percent', 0):.1f}%")
        else:
            output.append("  No metrics available")
        output.append("")
        
        output.append(f"{colors['info']}Active Operations ({len(dashboard_data['active_operations'])}):{colors['reset']}")
        for op in dashboard_data["active_operations"]:
            status_color = colors["success"] if op["status"] == "completed" else colors["warning"]
            output.append(f"  {status_color}{op['id']}{colors['reset']} - {op['type']} ({op['progress']:.1f}%)")
        
        if not dashboard_data["active_operations"]:
            output.append("  No active operations")
        output.append("")
        
        output.append(f"{colors['info']}Recent Alerts ({len(dashboard_data['recent_alerts'])}):{colors['reset']}")
        for alert in dashboard_data["recent_alerts"]:
            severity_color = colors.get(alert["severity"], colors["info"])
            output.append(f"  {severity_color}{alert['severity'].upper()}{colors['reset']}: {alert['message']}")
        
        if not dashboard_data["recent_alerts"]:
            output.append("  No recent alerts")
        
        output.append(f"{colors['info']}{'='*80}{colors['reset']}")
        
        return "\n".join(output)
    
    def acknowledge_alert(self, alert_index: int) -> bool:
        """Acknowledge a system alert"""
        if 0 <= alert_index < len(self.system_alerts):
            self.system_alerts[alert_index]["acknowledged"] = True
            self.system_alerts[alert_index]["acknowledged_at"] = datetime.now()
            return True
        return False
    
    def clear_acknowledged_alerts(self) -> int:
        """Clear all acknowledged alerts"""
        initial_count = len(self.system_alerts)
        self.system_alerts = [alert for alert in self.system_alerts if not alert["acknowledged"]]
        cleared_count = initial_count - len(self.system_alerts)
        logger.info(f"Cleared {cleared_count} acknowledged alerts")
        return cleared_count
