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
Unified detection engine that combines all detection components.
"""
from typing import Dict, List, Optional, Any, Union, Tuple
from uuid import uuid4

from core.utils.logging import get_logger
from detection_engine.instruction_analysis.models import (
    ThreatType,
    RiskLevel,
    AnalysisRequest,
    AnalysisResponse,
    AnalysisResult,
    DetectionEvent,
    EventCreate,
)
from detection_engine.instruction_analysis.pattern_matching import pattern_matcher
from detection_engine.instruction_analysis.behavioral_analysis import behavioral_analyzer
from detection_engine.llm_classifier.classifier import llm_classifier
from detection_engine.traffic_analyzer.analyzer import traffic_analyzer

# Configure logger
logger = get_logger(__name__)


class DetectionEngine:
    """
    Unified detection engine that combines all detection components.
    """
    
    def __init__(self):
        """
        Initialize the detection engine.
        """
        self.components = {
            "pattern_matching": pattern_matcher,
            "behavioral_analysis": behavioral_analyzer,
            "llm_classification": llm_classifier,
            "traffic_analysis": traffic_analyzer,
        }
        
        # Component weights for confidence aggregation
        self.component_weights = {
            "pattern_matching": 0.35,
            "behavioral_analysis": 0.25,
            "llm_classification": 0.30,
            "traffic_analysis": 0.10,
        }
        
        # Minimum confidence threshold for considering a threat
        self.min_confidence_threshold = 0.3
        
        # Threshold for determining risk level
        self.risk_level_thresholds = {
            RiskLevel.LOW: 0.3,
            RiskLevel.MEDIUM: 0.6,
            RiskLevel.HIGH: 0.8,
            RiskLevel.CRITICAL: 0.95,
        }
    
    async def initialize(self):
        """
        Initialize the detection engine components.
        """
        logger.info("Initializing detection engine components")
        
        # Initialize each component if they have an initialize method
        for component_name, component in self.components.items():
            if hasattr(component, 'initialize') and callable(getattr(component, 'initialize')):
                try:
                    logger.info(f"Initializing {component_name} component")
                    await component.initialize()
                except Exception as e:
                    logger.error(f"Error initializing {component_name} component: {e}")
        
        logger.info("Detection engine initialization completed")
    
    async def analyze_instruction(self, 
                                request: AnalysisRequest) -> AnalysisResponse:
        """
        Analyze an instruction using all detection components.
        
        Args:
            request: The analysis request containing the instruction and context.
            
        Returns:
            AnalysisResponse with analysis results.
        """
        instruction_id = request.instruction_id
        logger.info(f"Analyzing instruction with ID {instruction_id}")
        
        # Generate a unique event ID
        event_id = str(uuid4())
        
        # Execute each component analysis in parallel
        analysis_results = await self._execute_component_analysis(
            instruction=request.instruction_content,
            instruction_id=instruction_id,
            session_id=request.session_id,
            client_id=request.client_id,
            server_id=request.server_id,
            context=request.context,
        )
        
        # Aggregate results
        is_threat, threat_type, risk_level, confidence, analysis_details = self._aggregate_results(analysis_results)
        
        # Create an event if a threat was detected
        if is_threat:
            event = self._create_detection_event(
                instruction_id=instruction_id,
                session_id=request.session_id,
                client_id=request.client_id,
                server_id=request.server_id,
                threat_type=threat_type,
                risk_level=risk_level,
                confidence=confidence,
                instruction_content=request.instruction_content,
                analysis_result=analysis_details,
            )
            # In a real implementation, we would store the event in the database
            # await self._store_detection_event(event)
            
            logger.warning(f"Threat detected in instruction {instruction_id}: {threat_type.value}, {risk_level.value}")
        else:
            logger.info(f"No threat detected in instruction {instruction_id}")
        
        # Return response
        return AnalysisResponse(
            instruction_id=instruction_id,
            is_threat=is_threat,
            threat_type=threat_type,
            risk_level=risk_level,
            confidence=confidence,
            analysis_results=analysis_results,
            event_id=event_id if is_threat else None
        )
    
    async def _execute_component_analysis(self,
                                       instruction: str,
                                       instruction_id: str,
                                       session_id: Optional[str] = None,
                                       client_id: Optional[str] = None,
                                       server_id: Optional[str] = None,
                                       context: Optional[Dict[str, Any]] = None) -> List[AnalysisResult]:
        """
        Execute analysis for each component.
        
        Args:
            instruction: The instruction text to analyze.
            instruction_id: Identifier for the instruction.
            session_id: Optional session identifier.
            client_id: Optional client identifier.
            server_id: Optional server identifier.
            context: Additional context information.
            
        Returns:
            List of AnalysisResult from each component.
        """
        results = []
        
        # Pattern matching analysis
        try:
            pattern_result = await pattern_matcher.analyze(instruction)
            results.append(pattern_result)
        except Exception as e:
            logger.error(f"Error in pattern matching analysis: {e}")
            # Add a placeholder result
            results.append(AnalysisResult(
                component="pattern_matching",
                result={"error": str(e)},
                is_threat=False,
                confidence=0.0,
                threat_type=None,
                risk_level=None,
                details={"error": str(e)}
            ))
        
        # Behavioral analysis
        try:
            behavioral_result = await behavioral_analyzer.analyze(
                instruction=instruction,
                session_id=session_id or instruction_id,
                context=context
            )
            results.append(behavioral_result)
        except Exception as e:
            logger.error(f"Error in behavioral analysis: {e}")
            results.append(AnalysisResult(
                component="behavioral_analysis",
                result={"error": str(e)},
                is_threat=False,
                confidence=0.0,
                threat_type=None,
                risk_level=None,
                details={"error": str(e)}
            ))
        
        # LLM classification
        try:
            llm_result = await llm_classifier.analyze(
                instruction=instruction,
                context=context
            )
            results.append(llm_result)
        except Exception as e:
            logger.error(f"Error in LLM classification: {e}")
            results.append(AnalysisResult(
                component="llm_classification",
                result={"error": str(e)},
                is_threat=False,
                confidence=0.0,
                threat_type=None,
                risk_level=None,
                details={"error": str(e)}
            ))
        
        # Traffic analysis (if provided sufficient context)
        if context and "messages" in context and isinstance(context["messages"], list):
            try:
                traffic_result = await traffic_analyzer.analyze(
                    messages=context["messages"],
                    client_id=client_id,
                    server_id=server_id
                )
                results.append(traffic_result)
            except Exception as e:
                logger.error(f"Error in traffic analysis: {e}")
                results.append(AnalysisResult(
                    component="traffic_analysis",
                    result={"error": str(e)},
                    is_threat=False,
                    confidence=0.0,
                    threat_type=None,
                    risk_level=None,
                    details={"error": str(e)}
                ))
        
        return results
    
    def _aggregate_results(self, 
                         results: List[AnalysisResult]) -> Tuple[bool, Optional[ThreatType], Optional[RiskLevel], float, Dict[str, Any]]:
        """
        Aggregate results from all components.
        
        Args:
            results: List of AnalysisResult from each component.
            
        Returns:
            Tuple containing:
                - Boolean indicating if a threat was detected
                - Optional ThreatType (None if no threat)
                - Optional RiskLevel (None if no threat)
                - Overall confidence score
                - Analysis details dictionary
        """
        # Count the number of components that detected a threat
        threats_detected = sum(1 for r in results if r.is_threat)
        
        # Skip aggregation if no threats detected
        if threats_detected == 0:
            return False, None, None, 0.0, {"components": {r.component: r.result for r in results}}
        
        # Calculate weighted confidence
        total_weight = 0.0
        weighted_confidence = 0.0
        
        for result in results:
            component = result.component
            weight = self.component_weights.get(component, 0.1)
            
            if result.is_threat:
                weighted_confidence += result.confidence * weight
            
            total_weight += weight
        
        # Normalize confidence
        if total_weight > 0:
            overall_confidence = weighted_confidence / total_weight
        else:
            overall_confidence = 0.0
        
        # Determine threat detection based on confidence threshold
        is_threat = overall_confidence >= self.min_confidence_threshold
        
        # If no threat detected, return early
        if not is_threat:
            return False, None, None, overall_confidence, {"components": {r.component: r.result for r in results}}
        
        # Determine overall threat type (use the most confident detection)
        threat_results = [r for r in results if r.is_threat and r.threat_type is not None]
        if threat_results:
            # Sort by confidence and take the highest
            threat_result = max(threat_results, key=lambda r: r.confidence)
            threat_type = threat_result.threat_type
        else:
            threat_type = ThreatType.UNKNOWN
        
        # Determine risk level based on confidence
        if overall_confidence >= self.risk_level_thresholds[RiskLevel.CRITICAL]:
            risk_level = RiskLevel.CRITICAL
        elif overall_confidence >= self.risk_level_thresholds[RiskLevel.HIGH]:
            risk_level = RiskLevel.HIGH
        elif overall_confidence >= self.risk_level_thresholds[RiskLevel.MEDIUM]:
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.LOW
        
        # Also consider the highest risk level reported by any component
        for result in results:
            if result.is_threat and result.risk_level is not None:
                if result.risk_level.value > risk_level.value:
                    # Increase risk level if any component reports higher risk
                    risk_level = result.risk_level
        
        # Prepare analysis details
        analysis_details = {
            "components": {r.component: r.result for r in results},
            "confidence": {
                "overall": overall_confidence,
                "components": {r.component: r.confidence for r in results}
            },
            "threat_type": {
                "value": threat_type.value,
                "components": {r.component: r.threat_type.value if r.is_threat and r.threat_type else None for r in results}
            },
            "risk_level": {
                "value": risk_level.value,
                "components": {r.component: r.risk_level.value if r.is_threat and r.risk_level else None for r in results}
            }
        }
        
        return is_threat, threat_type, risk_level, overall_confidence, analysis_details
    
    def _create_detection_event(self,
                              instruction_id: str,
                              session_id: Optional[str],
                              client_id: Optional[str],
                              server_id: Optional[str],
                              threat_type: ThreatType,
                              risk_level: RiskLevel,
                              confidence: float,
                              instruction_content: str,
                              analysis_result: Dict[str, Any]) -> EventCreate:
        """
        Create a detection event.
        
        Args:
            instruction_id: Identifier for the instruction.
            session_id: Optional session identifier.
            client_id: Optional client identifier.
            server_id: Optional server identifier.
            threat_type: Type of threat detected.
            risk_level: Risk level of the threat.
            confidence: Confidence score for the detection.
            instruction_content: Content of the instruction.
            analysis_result: Detailed analysis results.
            
        Returns:
            EventCreate object for storing in the database.
        """
        # Determine the detection source
        if "components" in analysis_result and analysis_result["components"]:
            # Find the component with the highest confidence
            component_confidences = analysis_result["confidence"]["components"]
            detection_source = max(component_confidences.items(), key=lambda x: x[1])[0]
            
            # Convert to DetectionSource enum
            from detection_engine.instruction_analysis.models import DetectionSource
            if detection_source == "pattern_matching":
                source = DetectionSource.PATTERN_MATCHING
            elif detection_source == "behavioral_analysis":
                source = DetectionSource.BEHAVIORAL_ANALYSIS
            elif detection_source == "llm_classification":
                source = DetectionSource.LLM_CLASSIFICATION
            elif detection_source == "traffic_analysis":
                source = DetectionSource.TRAFFIC_ANALYSIS
            else:
                source = DetectionSource.MANUAL
        else:
            source = DetectionSource.MANUAL
        
        # Create the event
        return EventCreate(
            instruction_id=instruction_id,
            session_id=session_id,
            client_id=client_id,
            server_id=server_id,
            threat_type=threat_type,
            risk_level=risk_level,
            confidence=confidence,
            detection_source=source,
            triggered_by=None,  # Would be populated for pattern matches
            instruction_content=instruction_content,
            analysis_result=analysis_result,
        )
    
    async def _store_detection_event(self, event: EventCreate) -> str:
        """
        Store a detection event in the database.
        
        Args:
            event: The event to store.
            
        Returns:
            The ID of the stored event.
        """
        # In a real implementation, this would store the event in a database
        # For now, we just log it
        logger.info(f"Detection event created: {event.dict()}")
        return str(uuid4())


# Singleton instance for reuse
detection_engine = DetectionEngine() 