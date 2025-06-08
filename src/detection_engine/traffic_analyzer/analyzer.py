# Copyright 2025 Jae Sup Hwang
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Traffic analyzer for detecting anomalies in MCP traffic patterns.
"""
import math
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set, Union
import numpy as np
from sklearn.ensemble import IsolationForest

from core.utils.logging import get_logger
from detection_engine.instruction_analysis.models import AnalysisResult, RiskLevel
from detection_engine.traffic_analyzer.models import (
    AnomalyType,
    MessageType,
    MessageDirection,
    MessageData,
    MessageSummaryData,
    BaselineData,
    AlertData,
    TrafficAnalysisResult,
)

# Configure logger
logger = get_logger(__name__)


class TrafficAnalyzer:
    """
    Traffic analyzer for detecting anomalies in MCP traffic patterns.
    """
    
    def __init__(self):
        """
        Initialize the traffic analyzer.
        """
        self.baselines: Dict[str, BaselineData] = {}
        self.anomaly_detectors: Dict[str, Any] = {}
        self.loaded = False
        
        # Default thresholds
        self.volume_threshold = 2.0  # 200% of baseline
        self.timing_threshold = 3.0  # 3 standard deviations
        self.sequence_threshold = 0.7  # 0.7 similarity score
        
        # Features to monitor
        self.monitored_features = [
            "message_rate",
            "message_size",
            "instruction_length",
            "message_interval",
            "message_type_distribution",
            "capability_usage",
        ]
    
    async def load_baselines(self, baselines: List[BaselineData]) -> None:
        """
        Load baseline data into the analyzer.
        
        Args:
            baselines: List of baseline data to load.
        """
        self.baselines = {}
        
        for baseline in baselines:
            if baseline.is_active:
                # Create baseline key (either client_id-server_id or server_id or client_id)
                if baseline.client_id and baseline.server_id:
                    key = f"{baseline.client_id}-{baseline.server_id}"
                elif baseline.server_id:
                    key = f"server-{baseline.server_id}"
                elif baseline.client_id:
                    key = f"client-{baseline.client_id}"
                else:
                    key = "global"
                
                self.baselines[key] = baseline
        
        self.loaded = bool(self.baselines)
        logger.info(f"Loaded {len(self.baselines)} traffic baselines")
    
    def _get_baseline(self, client_id: Optional[str] = None, server_id: Optional[str] = None) -> Optional[BaselineData]:
        """
        Get the most specific baseline for a client-server pair.
        
        Args:
            client_id: Client identifier.
            server_id: Server identifier.
            
        Returns:
            The most specific baseline, or None if no baseline exists.
        """
        # Check for specific client-server baseline
        if client_id and server_id:
            specific_key = f"{client_id}-{server_id}"
            if specific_key in self.baselines:
                return self.baselines[specific_key]
        
        # Check for server-specific baseline
        if server_id:
            server_key = f"server-{server_id}"
            if server_key in self.baselines:
                return self.baselines[server_key]
        
        # Check for client-specific baseline
        if client_id:
            client_key = f"client-{client_id}"
            if client_key in self.baselines:
                return self.baselines[client_key]
        
        # Fall back to global baseline
        if "global" in self.baselines:
            return self.baselines["global"]
        
        return None
    
    def _calculate_message_summary(self, messages: List[MessageData], 
                                  window_start: datetime, window_end: datetime) -> MessageSummaryData:
        """
        Calculate summary metrics for a set of messages.
        
        Args:
            messages: List of messages to analyze.
            window_start: Start of the time window.
            window_end: End of the time window.
            
        Returns:
            MessageSummaryData with calculated metrics.
        """
        if not messages:
            raise ValueError("Cannot calculate summary for empty message list")
        
        # Basic identifiers
        client_id = messages[0].client_id
        server_id = messages[0].server_id
        session_id = messages[0].session_id
        
        # Time window string (format: YYYY-MM-DD-HH)
        time_window = window_start.strftime("%Y-%m-%d-%H")
        
        # Message counts
        total_messages = len(messages)
        message_type_counts: Dict[str, int] = {}
        
        for msg_type in MessageType:
            message_type_counts[msg_type] = 0
        
        # Size metrics
        total_size = 0
        
        # Content metrics
        instructions: Set[str] = set()
        capabilities_used: Set[str] = set()
        capability_frequency: Dict[str, int] = {}
        
        # Temporal metrics
        message_timestamps = []
        
        # Process each message
        for message in messages:
            # Count by type
            message_type_counts[message.message_type] = message_type_counts.get(message.message_type, 0) + 1
            
            # Size metrics
            total_size += message.size_bytes
            
            # Record timestamp
            message_timestamps.append(message.timestamp)
            
            # Extract instruction content
            if message.message_type == MessageType.INSTRUCTION:
                if "text" in message.content:
                    instructions.add(message.content["text"])
                
                # Extract capabilities if present
                if "capabilities" in message.content:
                    caps = message.content["capabilities"]
                    if isinstance(caps, list):
                        for cap in caps:
                            if isinstance(cap, str):
                                capabilities_used.add(cap)
                                capability_frequency[cap] = capability_frequency.get(cap, 0) + 1
        
        # Calculate size metrics
        avg_message_size = total_size / total_messages if total_messages > 0 else 0
        
        # Calculate timing metrics
        avg_message_interval = None
        if len(message_timestamps) > 1:
            # Sort timestamps
            message_timestamps.sort()
            
            # Calculate intervals
            intervals = [(message_timestamps[i] - message_timestamps[i-1]).total_seconds() 
                         for i in range(1, len(message_timestamps))]
            
            avg_message_interval = sum(intervals) / len(intervals) if intervals else None
        
        # Instruction metrics
        unique_instructions = len(instructions)
        instruction_similarity = None  # Would require text similarity calculation
        
        # Capability metrics
        unique_capabilities_used = len(capabilities_used)
        
        return MessageSummaryData(
            client_id=client_id,
            server_id=server_id,
            session_id=session_id,
            time_window=time_window,
            total_messages=total_messages,
            message_type_counts=message_type_counts,
            avg_message_size=avg_message_size,
            total_message_size=float(total_size),
            avg_message_interval=avg_message_interval,
            unique_instructions=unique_instructions,
            instruction_similarity=instruction_similarity,
            unique_capabilities_used=unique_capabilities_used,
            capability_frequency=capability_frequency,
        )
    
    def _detect_volume_anomalies(self, summary: MessageSummaryData, 
                                baseline: BaselineData) -> List[Tuple[AnomalyType, float, float, float]]:
        """
        Detect volume-based anomalies in traffic.
        
        Args:
            summary: Message summary data.
            baseline: Baseline data for comparison.
            
        Returns:
            List of tuples (anomaly_type, observed, baseline, deviation) for detected anomalies.
        """
        anomalies = []
        
        # Message rate anomaly
        # Convert total_messages to messages per minute
        time_parts = summary.time_window.split("-")
        if len(time_parts) == 4:  # Hourly window
            minutes_in_window = 60
        else:  # Daily window
            minutes_in_window = 24 * 60
        
        message_rate = summary.total_messages / minutes_in_window
        if message_rate > baseline.avg_message_rate * self.volume_threshold:
            deviation = (message_rate / baseline.avg_message_rate) - 1.0
            anomalies.append((
                AnomalyType.VOLUME_SPIKE,
                message_rate,
                baseline.avg_message_rate,
                deviation * 100  # Convert to percentage
            ))
        
        # Message size anomaly
        if summary.avg_message_size > baseline.avg_message_size * self.volume_threshold:
            deviation = (summary.avg_message_size / baseline.avg_message_size) - 1.0
            anomalies.append((
                AnomalyType.UNUSUAL_PATTERN,
                summary.avg_message_size,
                baseline.avg_message_size,
                deviation * 100
            ))
        
        return anomalies
    
    def _detect_timing_anomalies(self, summary: MessageSummaryData, 
                               baseline: BaselineData) -> List[Tuple[AnomalyType, float, float, float]]:
        """
        Detect timing-based anomalies in traffic.
        
        Args:
            summary: Message summary data.
            baseline: Baseline data for comparison.
            
        Returns:
            List of tuples (anomaly_type, observed, baseline, deviation) for detected anomalies.
        """
        anomalies = []
        
        # Check for time-based patterns
        if baseline.hourly_patterns and summary.time_window.endswith(summary.time_window[-2:]):
            hour = summary.time_window[-2:]
            if hour in baseline.hourly_patterns:
                expected_rate = baseline.hourly_patterns[hour].get("avg_message_rate", baseline.avg_message_rate)
                
                # Calculate observed rate
                time_parts = summary.time_window.split("-")
                if len(time_parts) == 4:  # Hourly window
                    minutes_in_window = 60
                else:  # Daily window
                    minutes_in_window = 24 * 60
                
                observed_rate = summary.total_messages / minutes_in_window
                
                # Check for significant deviation
                if observed_rate > expected_rate * self.volume_threshold:
                    deviation = (observed_rate / expected_rate) - 1.0
                    anomalies.append((
                        AnomalyType.IRREGULAR_TIMING,
                        observed_rate,
                        expected_rate,
                        deviation * 100
                    ))
        
        return anomalies
    
    def _detect_distribution_anomalies(self, summary: MessageSummaryData, 
                                     baseline: BaselineData) -> List[Tuple[AnomalyType, float, float, float]]:
        """
        Detect anomalies in message type distribution.
        
        Args:
            summary: Message summary data.
            baseline: Baseline data for comparison.
            
        Returns:
            List of tuples (anomaly_type, observed, baseline, deviation) for detected anomalies.
        """
        anomalies = []
        
        # Calculate message type distribution
        total = sum(summary.message_type_counts.values())
        if total == 0:
            return anomalies
        
        observed_distribution = {
            msg_type: count / total 
            for msg_type, count in summary.message_type_counts.items()
        }
        
        # Compare with baseline distribution
        for msg_type, baseline_pct in baseline.message_type_distribution.items():
            observed_pct = observed_distribution.get(msg_type, 0)
            
            # Check for significant deviation
            if observed_pct > baseline_pct * self.volume_threshold:
                deviation = (observed_pct / baseline_pct) - 1.0 if baseline_pct > 0 else float('inf')
                anomalies.append((
                    AnomalyType.UNUSUAL_PATTERN,
                    observed_pct * 100,  # Convert to percentage
                    baseline_pct * 100,  # Convert to percentage
                    deviation * 100
                ))
        
        return anomalies
    
    def _calculate_risk_level(self, anomaly_type: AnomalyType, deviation_percent: float) -> RiskLevel:
        """
        Calculate risk level based on anomaly type and deviation.
        
        Args:
            anomaly_type: Type of anomaly.
            deviation_percent: Percentage deviation from baseline.
            
        Returns:
            Calculated risk level.
        """
        # Base thresholds for different risk levels
        thresholds = {
            AnomalyType.VOLUME_SPIKE: {
                RiskLevel.LOW: 50,      # 50% above baseline
                RiskLevel.MEDIUM: 100,  # 100% above baseline
                RiskLevel.HIGH: 200,    # 200% above baseline
                RiskLevel.CRITICAL: 500 # 500% above baseline
            },
            AnomalyType.UNUSUAL_PATTERN: {
                RiskLevel.LOW: 50,
                RiskLevel.MEDIUM: 100,
                RiskLevel.HIGH: 200,
                RiskLevel.CRITICAL: 300
            },
            AnomalyType.IRREGULAR_TIMING: {
                RiskLevel.LOW: 50,
                RiskLevel.MEDIUM: 100,
                RiskLevel.HIGH: 200,
                RiskLevel.CRITICAL: 300
            },
            AnomalyType.PROTOCOL_VIOLATION: {
                RiskLevel.LOW: 0,       # Any violation starts at medium
                RiskLevel.MEDIUM: 0,
                RiskLevel.HIGH: 50,
                RiskLevel.CRITICAL: 100
            },
            AnomalyType.SUSPICIOUS_CONTENT: {
                RiskLevel.LOW: 0,       # Any suspicious content starts at medium
                RiskLevel.MEDIUM: 0,
                RiskLevel.HIGH: 50,
                RiskLevel.CRITICAL: 100
            },
            AnomalyType.UNAUTHORIZED_CAPABILITY: {
                RiskLevel.LOW: 0,       # Any unauthorized capability starts at high
                RiskLevel.MEDIUM: 0,
                RiskLevel.HIGH: 0,
                RiskLevel.CRITICAL: 50
            }
        }
        
        # Default thresholds if anomaly type not specified
        default_thresholds = {
            RiskLevel.LOW: 50,
            RiskLevel.MEDIUM: 100,
            RiskLevel.HIGH: 200,
            RiskLevel.CRITICAL: 300
        }
        
        # Get thresholds for this anomaly type
        type_thresholds = thresholds.get(anomaly_type, default_thresholds)
        
        # Determine risk level based on deviation
        if deviation_percent >= type_thresholds.get(RiskLevel.CRITICAL, float('inf')):
            return RiskLevel.CRITICAL
        elif deviation_percent >= type_thresholds.get(RiskLevel.HIGH, float('inf')):
            return RiskLevel.HIGH
        elif deviation_percent >= type_thresholds.get(RiskLevel.MEDIUM, float('inf')):
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def _calculate_confidence(self, deviation_percent: float, baseline_sample_count: int) -> float:
        """
        Calculate confidence score based on deviation and baseline quality.
        
        Args:
            deviation_percent: Percentage deviation from baseline.
            baseline_sample_count: Number of samples used in baseline.
            
        Returns:
            Confidence score (0-1).
        """
        # Higher deviation = higher confidence
        deviation_factor = min(1.0, deviation_percent / 100)
        
        # Higher sample count = higher confidence
        sample_factor = min(1.0, baseline_sample_count / 1000)
        
        # Combine factors with higher weight on deviation
        confidence = (deviation_factor * 0.7) + (sample_factor * 0.3)
        
        return min(1.0, max(0.1, confidence))
    
    async def analyze_traffic(self, messages: List[MessageData], 
                             client_id: Optional[str] = None, 
                             server_id: Optional[str] = None) -> TrafficAnalysisResult:
        """
        Analyze traffic for anomalies.
        
        Args:
            messages: List of messages to analyze.
            client_id: Optional client identifier.
            server_id: Optional server identifier.
            
        Returns:
            TrafficAnalysisResult with analysis findings.
        """
        if not messages:
            return TrafficAnalysisResult(
                is_anomalous=False,
                confidence=0.0,
                metrics={},
                baseline_deviation={},
                time_window={"start": datetime.utcnow(), "end": datetime.utcnow()},
                message_count=0
            )
        
        # Extract client and server IDs from messages if not provided
        if not client_id and messages[0].client_id:
            client_id = messages[0].client_id
        if not server_id and messages[0].server_id:
            server_id = messages[0].server_id
        
        # Get appropriate baseline
        baseline = self._get_baseline(client_id, server_id)
        
        if not baseline:
            logger.warning(f"No baseline found for client={client_id}, server={server_id}")
            return TrafficAnalysisResult(
                is_anomalous=False,
                confidence=0.0,
                metrics={"warning": "No baseline available for comparison"},
                baseline_deviation={},
                time_window={
                    "start": min(m.timestamp for m in messages),
                    "end": max(m.timestamp for m in messages)
                },
                message_count=len(messages)
            )
        
        # Determine time window
        window_start = min(m.timestamp for m in messages)
        window_end = max(m.timestamp for m in messages)
        
        # Calculate summary metrics
        summary = self._calculate_message_summary(messages, window_start, window_end)
        
        # Detect different types of anomalies
        volume_anomalies = self._detect_volume_anomalies(summary, baseline)
        timing_anomalies = self._detect_timing_anomalies(summary, baseline)
        distribution_anomalies = self._detect_distribution_anomalies(summary, baseline)
        
        # Combine all anomalies
        all_anomalies = volume_anomalies + timing_anomalies + distribution_anomalies
        
        # Generate alerts for detected anomalies
        alerts = []
        anomaly_types = set()
        highest_risk_level = None
        max_confidence = 0.0
        
        for anomaly_type, observed, baseline_value, deviation in all_anomalies:
            # Calculate risk level
            risk_level = self._calculate_risk_level(anomaly_type, deviation)
            
            # Calculate confidence
            confidence = self._calculate_confidence(deviation, baseline.sample_count)
            
            # Track highest risk and confidence
            if highest_risk_level is None or risk_level.value > highest_risk_level.value:
                highest_risk_level = risk_level
            max_confidence = max(max_confidence, confidence)
            
            # Track anomaly type
            anomaly_types.add(anomaly_type)
            
            # Create alert
            alert = AlertData(
                client_id=client_id,
                server_id=server_id,
                session_id=summary.session_id,
                anomaly_type=anomaly_type,
                risk_level=risk_level,
                confidence=confidence,
                observed_value=observed,
                baseline_value=baseline_value,
                deviation_percent=deviation,
                time_window_start=window_start,
                time_window_end=window_end,
                message_count=summary.total_messages,
                has_sample_messages=False,  # Don't include sample messages in alerts for privacy
            )
            alerts.append(alert)
        
        # Calculate baseline deviation metrics
        baseline_deviation = {}
        
        # Message rate deviation
        time_parts = summary.time_window.split("-")
        if len(time_parts) == 4:  # Hourly window
            minutes_in_window = 60
        else:  # Daily window
            minutes_in_window = 24 * 60
        
        message_rate = summary.total_messages / minutes_in_window
        baseline_deviation["message_rate"] = ((message_rate / baseline.avg_message_rate) - 1.0) * 100 if baseline.avg_message_rate > 0 else 0
        
        # Message size deviation
        baseline_deviation["message_size"] = ((summary.avg_message_size / baseline.avg_message_size) - 1.0) * 100 if baseline.avg_message_size > 0 else 0
        
        # Prepare metrics for response
        metrics = {
            "message_rate": message_rate,
            "avg_message_size": summary.avg_message_size,
            "total_messages": summary.total_messages,
            "message_type_distribution": {
                k: v / summary.total_messages for k, v in summary.message_type_counts.items() if v > 0
            },
            "avg_message_interval": summary.avg_message_interval,
            "unique_instructions": summary.unique_instructions,
            "capability_usage": summary.capability_frequency,
        }
        
        return TrafficAnalysisResult(
            is_anomalous=len(alerts) > 0,
            anomaly_types=list(anomaly_types),
            risk_level=highest_risk_level,
            confidence=max_confidence,
            alerts=alerts,
            metrics=metrics,
            baseline_deviation=baseline_deviation,
            time_window={"start": window_start, "end": window_end},
            message_count=len(messages)
        )
    
    async def analyze(self, messages: List[Dict[str, Any]], 
                     client_id: Optional[str] = None, 
                     server_id: Optional[str] = None) -> AnalysisResult:
        """
        Analyze messages using traffic analysis.
        
        Args:
            messages: The messages to analyze.
            client_id: Optional client identifier.
            server_id: Optional server identifier.
            
        Returns:
            AnalysisResult with traffic analysis results.
        """
        # Convert dict messages to MessageData
        message_data = []
        for msg in messages:
            try:
                # Convert dictionary to MessageData
                message_data.append(MessageData(
                    message_id=msg.get("id", str(len(message_data))),
                    client_id=msg.get("client_id", client_id),
                    server_id=msg.get("server_id", server_id),
                    session_id=msg.get("session_id"),
                    timestamp=msg.get("timestamp", datetime.utcnow()),
                    direction=msg.get("direction", MessageDirection.CLIENT_TO_SERVER),
                    message_type=msg.get("type", MessageType.OTHER),
                    size_bytes=msg.get("size_bytes", len(str(msg))),
                    content=msg.get("content", {}),
                ))
            except Exception as e:
                logger.error(f"Error converting message to MessageData: {e}")
        
        # Analyze traffic
        result = await self.analyze_traffic(message_data, client_id, server_id)
        
        # Map to a standard AnalysisResult
        threat_type = None
        if result.is_anomalous and result.anomaly_types:
            # Map AnomalyType to ThreatType
            anomaly_type_str = result.anomaly_types[0].value
            if "suspicious" in anomaly_type_str:
                from detection_engine.instruction_analysis.models import ThreatType
                threat_type = ThreatType.UNKNOWN
        
        return AnalysisResult(
            component="traffic_analysis",
            result={
                "is_anomalous": result.is_anomalous,
                "anomaly_types": [t.value for t in result.anomaly_types] if result.anomaly_types else [],
                "metrics": result.metrics,
                "alerts": [a.dict() for a in result.alerts],
            },
            is_threat=result.is_anomalous,
            confidence=result.confidence,
            threat_type=threat_type,
            risk_level=result.risk_level,
            details={
                "baseline_deviation": result.baseline_deviation,
                "message_count": result.message_count,
                "time_window": {
                    "start": result.time_window["start"].isoformat(),
                    "end": result.time_window["end"].isoformat(),
                },
            }
        )


# Singleton instance for reuse
traffic_analyzer = TrafficAnalyzer() 