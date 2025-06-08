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
Pattern matching engine for detecting known attack patterns in MCP instructions.
"""
import re
from typing import Dict, List, Optional, Any, Tuple
import yara

from core.utils.logging import get_logger
from detection_engine.instruction_analysis.models import (
    DetectionPattern,
    MongoPattern,
    ThreatType,
    RiskLevel,
    AnalysisResult,
)

# Configure logger
logger = get_logger(__name__)


class PatternMatcher:
    """
    Pattern matching engine for detecting known attack patterns in MCP instructions.
    """
    
    def __init__(self):
        """
        Initialize the pattern matcher.
        """
        self.patterns: List[Dict[str, Any]] = []
        self.regex_patterns: Dict[str, re.Pattern] = {}
        self.yara_rules: Optional[yara.Rules] = None
        self.loaded = False
    
    async def load_patterns(self, patterns: List[Dict[str, Any]]) -> None:
        """
        Load patterns into the matcher.
        
        Args:
            patterns: List of pattern dictionaries to load.
        """
        self.patterns = [p for p in patterns if p.get("enabled", True)]
        
        # Compile regex patterns
        self.regex_patterns = {}
        for pattern in self.patterns:
            if pattern.get("is_regex", True):
                try:
                    self.regex_patterns[pattern["id"]] = re.compile(
                        pattern["pattern"], 
                        re.MULTILINE | re.DOTALL
                    )
                except re.error as e:
                    logger.error(f"Error compiling regex pattern {pattern['name']}: {e}")
        
        # Compile YARA rules if there are any
        yara_patterns = [p for p in self.patterns if not p.get("is_regex", True)]
        if yara_patterns:
            try:
                yara_source = self._build_yara_rules(yara_patterns)
                self.yara_rules = yara.compile(source=yara_source)
            except yara.Error as e:
                logger.error(f"Error compiling YARA rules: {e}")
                self.yara_rules = None
        
        self.loaded = True
        logger.info(f"Loaded {len(self.patterns)} patterns ({len(self.regex_patterns)} regex, {len(yara_patterns)} YARA)")
    
    def _build_yara_rules(self, yara_patterns: List[Dict[str, Any]]) -> str:
        """
        Build YARA rules from pattern dictionaries.
        
        Args:
            yara_patterns: List of YARA pattern dictionaries.
            
        Returns:
            YARA rule source string.
        """
        rules = []
        
        for pattern in yara_patterns:
            rule_name = f"rule_{pattern['id'].replace('-', '_')}"
            metadata = "\n".join([
                f"        name = \"{pattern['name']}\"",
                f"        description = \"{pattern.get('description', '')}\"",
                f"        threat_type = \"{pattern.get('threat_type', 'unknown')}\"",
                f"        risk_level = \"{pattern.get('risk_level', 'medium')}\"",
                f"        confidence = {pattern.get('confidence', 0.8)}",
            ])
            
            rule = f"""
rule {rule_name} {{
    meta:
{metadata}
    strings:
        $pattern = {pattern['pattern']}
    condition:
        $pattern
}}
"""
            rules.append(rule)
        
        return "\n".join(rules)
    
    async def match(self, instruction: str) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Match an instruction against loaded patterns.
        
        Args:
            instruction: The instruction text to analyze.
            
        Returns:
            Tuple containing:
                - Boolean indicating if any patterns matched
                - List of matched pattern details
        """
        if not self.loaded:
            logger.warning("Pattern matcher not loaded, skipping matching")
            return False, []
        
        matches = []
        
        # Apply regex patterns
        for pattern_id, regex in self.regex_patterns.items():
            pattern = next(p for p in self.patterns if p["id"] == pattern_id)
            
            if regex.search(instruction):
                matches.append({
                    "id": pattern_id,
                    "name": pattern["name"],
                    "pattern": pattern["pattern"],
                    "threat_type": pattern.get("threat_type", ThreatType.UNKNOWN),
                    "risk_level": pattern.get("risk_level", RiskLevel.MEDIUM),
                    "confidence": pattern.get("confidence", 0.8),
                })
        
        # Apply YARA rules if available
        if self.yara_rules:
            try:
                yara_matches = self.yara_rules.match(data=instruction)
                for match in yara_matches:
                    pattern_id = match.rule.split("_", 1)[1].replace("_", "-")
                    pattern = next(p for p in self.patterns if p["id"] == pattern_id)
                    
                    matches.append({
                        "id": pattern_id,
                        "name": pattern["name"],
                        "pattern": pattern["pattern"],
                        "threat_type": pattern.get("threat_type", ThreatType.UNKNOWN),
                        "risk_level": pattern.get("risk_level", RiskLevel.MEDIUM),
                        "confidence": pattern.get("confidence", 0.8),
                    })
            except yara.Error as e:
                logger.error(f"Error applying YARA rules: {e}")
        
        return bool(matches), matches

    async def analyze(self, instruction: str) -> AnalysisResult:
        """
        Analyze an instruction using pattern matching.
        
        Args:
            instruction: The instruction text to analyze.
            
        Returns:
            AnalysisResult with pattern matching results.
        """
        matched, matches = await self.match(instruction)
        
        # If we have matches, determine the highest risk/confidence
        threat_type = None
        risk_level = None
        confidence = 0.0
        
        if matched:
            # Find the highest risk match
            highest_risk_match = max(
                matches, 
                key=lambda m: (
                    RiskLevel[m["risk_level"].upper()].value if isinstance(m["risk_level"], str) else 0,
                    m["confidence"]
                )
            )
            
            threat_type = highest_risk_match["threat_type"]
            risk_level = highest_risk_match["risk_level"]
            confidence = highest_risk_match["confidence"]
        
        return AnalysisResult(
            component="pattern_matching",
            result={"matches": matches},
            is_threat=matched,
            confidence=confidence,
            threat_type=threat_type,
            risk_level=risk_level,
            details={
                "match_count": len(matches),
                "patterns_checked": len(self.patterns)
            }
        )


# Singleton instance for reuse
pattern_matcher = PatternMatcher() 