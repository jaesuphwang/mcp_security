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
Behavioral analysis module for detecting anomalous instruction sequences.
"""
from collections import deque
from typing import Dict, List, Optional, Any, Deque, Tuple
import numpy as np
from sklearn.ensemble import IsolationForest

from core.utils.logging import get_logger
from detection_engine.instruction_analysis.models import (
    ThreatType,
    RiskLevel,
    AnalysisResult,
)

# Configure logger
logger = get_logger(__name__)


class BehavioralAnalyzer:
    """
    Behavioral analysis for detecting anomalous instruction sequences.
    """
    
    def __init__(self, sequence_length: int = 10, anomaly_threshold: float = -0.5):
        """
        Initialize the behavioral analyzer.
        
        Args:
            sequence_length: Number of instructions to keep in sequence history.
            anomaly_threshold: Threshold for anomaly detection (-1 to 0, lower is more anomalous).
        """
        self.sequence_length = sequence_length
        self.anomaly_threshold = anomaly_threshold
        self.sequence_history: Dict[str, Deque[Dict[str, Any]]] = {}
        self.models: Dict[str, Any] = {}
        self.feature_names: List[str] = [
            "instruction_length",
            "token_count",
            "command_count",
            "url_count",
            "file_access_count",
            "network_access_count",
            "script_inclusion_count",
            "time_since_last_instruction",
        ]
    
    def _extract_features(self, instruction: str, context: Optional[Dict[str, Any]] = None) -> List[float]:
        """
        Extract behavioral features from an instruction.
        
        Args:
            instruction: The instruction text.
            context: Additional context information.
            
        Returns:
            List of extracted features.
        """
        features = []
        
        # Basic features
        features.append(len(instruction))
        features.append(len(instruction.split()))
        
        # Command-related features
        command_count = instruction.count("exec(") + instruction.count("shell.run") + instruction.count("system(")
        features.append(command_count)
        
        # URL-related features
        url_count = instruction.count("http://") + instruction.count("https://")
        features.append(url_count)
        
        # File access features
        file_access_count = (
            instruction.count("file.read") + 
            instruction.count("file.write") + 
            instruction.count("open(") +
            instruction.count("readFile") +
            instruction.count("writeFile")
        )
        features.append(file_access_count)
        
        # Network access features
        network_access_count = (
            instruction.count("fetch(") + 
            instruction.count("http.get") + 
            instruction.count("http.post") +
            instruction.count("net.connect") +
            instruction.count("socket.")
        )
        features.append(network_access_count)
        
        # Script inclusion features
        script_inclusion_count = (
            instruction.count("import ") + 
            instruction.count("require(") + 
            instruction.count("eval(") +
            instruction.count("<script") +
            instruction.count("Function(")
        )
        features.append(script_inclusion_count)
        
        # Temporal features
        time_since_last = 0.0
        if context and "timestamp" in context:
            if "last_timestamp" in context:
                time_since_last = context["timestamp"] - context["last_timestamp"]
            
        features.append(time_since_last)
        
        return features
    
    def update_sequence(self, session_id: str, instruction: str, 
                        context: Optional[Dict[str, Any]] = None) -> None:
        """
        Update the sequence history for a session.
        
        Args:
            session_id: Session identifier.
            instruction: The instruction text.
            context: Additional context information.
        """
        # Initialize sequence history for new sessions
        if session_id not in self.sequence_history:
            self.sequence_history[session_id] = deque(maxlen=self.sequence_length)
        
        # Extract features
        features = self._extract_features(instruction, context)
        
        # Add to history
        instruction_data = {
            "instruction": instruction,
            "features": features,
            "context": context or {},
        }
        
        self.sequence_history[session_id].append(instruction_data)
    
    def _get_sequence_features(self, session_id: str) -> Optional[List[List[float]]]:
        """
        Get sequence features for a session.
        
        Args:
            session_id: Session identifier.
            
        Returns:
            List of feature vectors or None if not enough history.
        """
        if session_id not in self.sequence_history:
            return None
        
        sequence = self.sequence_history[session_id]
        if len(sequence) < 2:  # Need at least 2 instructions for sequence analysis
            return None
        
        return [item["features"] for item in sequence]
    
    def train_model(self, session_id: str) -> bool:
        """
        Train an anomaly detection model for a session.
        
        Args:
            session_id: Session identifier.
            
        Returns:
            True if model was trained successfully, False otherwise.
        """
        features = self._get_sequence_features(session_id)
        if not features:
            return False
        
        try:
            # Create and train model
            model = IsolationForest(
                contamination=0.1,
                random_state=42,
                n_estimators=100,
            )
            model.fit(features)
            
            # Store model
            self.models[session_id] = model
            logger.info(f"Trained behavioral model for session {session_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error training behavioral model for session {session_id}: {e}")
            return False
    
    def detect_anomalies(self, session_id: str) -> Tuple[bool, float, Optional[Dict[str, Any]]]:
        """
        Detect anomalies in a session's instruction sequence.
        
        Args:
            session_id: Session identifier.
            
        Returns:
            Tuple containing:
                - Boolean indicating if anomaly was detected
                - Anomaly score (-1 to 0, lower is more anomalous)
                - Additional details or None if detection failed
        """
        if session_id not in self.sequence_history:
            return False, 0.0, None
        
        features = self._get_sequence_features(session_id)
        if not features:
            return False, 0.0, None
        
        # Use existing model or train new one
        if session_id not in self.models:
            if not self.train_model(session_id):
                return False, 0.0, None
        
        try:
            model = self.models[session_id]
            
            # Get anomaly scores
            scores = model.decision_function(features)
            
            # The last score corresponds to the most recent instruction
            latest_score = scores[-1]
            
            # Determine if it's an anomaly
            is_anomaly = latest_score < self.anomaly_threshold
            
            # Feature importance (using absolute differences from mean)
            latest_features = features[-1]
            if len(features) > 1:
                previous_means = np.mean(features[:-1], axis=0)
                feature_diffs = np.abs(latest_features - previous_means)
                
                # Create importance dictionary
                feature_importance = {}
                for i, name in enumerate(self.feature_names):
                    if i < len(feature_diffs):
                        feature_importance[name] = float(feature_diffs[i])
            else:
                feature_importance = {name: 0.0 for name in self.feature_names}
            
            details = {
                "score": float(latest_score),
                "feature_importance": feature_importance,
                "threshold": self.anomaly_threshold,
            }
            
            return is_anomaly, float(latest_score), details
            
        except Exception as e:
            logger.error(f"Error detecting anomalies for session {session_id}: {e}")
            return False, 0.0, None
    
    async def analyze(self, instruction: str, session_id: str, 
                     context: Optional[Dict[str, Any]] = None) -> AnalysisResult:
        """
        Analyze an instruction using behavioral analysis.
        
        Args:
            instruction: The instruction text to analyze.
            session_id: Session identifier.
            context: Additional context information.
            
        Returns:
            AnalysisResult with behavioral analysis results.
        """
        # Update sequence history
        self.update_sequence(session_id, instruction, context)
        
        # Detect anomalies
        is_anomaly, anomaly_score, details = self.detect_anomalies(session_id)
        
        # Map anomaly score to confidence (0 to 1)
        # Score is between -1 and 0, where -1 is most anomalous
        if is_anomaly:
            # Convert score from (-1,0) to (0,1) confidence
            confidence = min(1.0, max(0.0, (self.anomaly_threshold - anomaly_score) / abs(self.anomaly_threshold - (-1.0))))
            
            # Determine risk level based on confidence
            if confidence > 0.8:
                risk_level = RiskLevel.HIGH
            elif confidence > 0.5:
                risk_level = RiskLevel.MEDIUM
            else:
                risk_level = RiskLevel.LOW
                
            # For behavioral analysis, we can't easily determine threat type,
            # so we'll use UNKNOWN
            threat_type = ThreatType.UNKNOWN
        else:
            confidence = 0.0
            risk_level = None
            threat_type = None
        
        # Prepare analysis result
        result = {
            "is_anomaly": is_anomaly,
            "anomaly_score": anomaly_score,
        }
        
        if details:
            result["details"] = details
        
        return AnalysisResult(
            component="behavioral_analysis",
            result=result,
            is_threat=is_anomaly,
            confidence=confidence,
            threat_type=threat_type,
            risk_level=risk_level,
            details={
                "session_id": session_id,
                "sequence_length": len(self.sequence_history.get(session_id, [])),
                "has_model": session_id in self.models,
            }
        )


# Singleton instance for reuse
behavioral_analyzer = BehavioralAnalyzer() 