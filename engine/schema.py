import yaml
from dataclasses import dataclass
from typing import List, Dict, Any

@dataclass
class ChainStep:
    name: str
    event_type: str
    conditions: Dict[str, str]

@dataclass
class AttackChain:
    id: str
    name: str
    description: str
    mitre_tags: List[str]
    steps: List[ChainStep]

def parse_chain_yaml(file_path: str) -> AttackChain:
    with open(file_path, 'r') as f:
        data = yaml.safe_load(f)
    
    steps = []
    for step_data in data.get('steps', []):
        steps.append(ChainStep(
            name=step_data['name'],
            event_type=step_data['event_type'],
            conditions=step_data.get('conditions', {})
        ))
    
    return AttackChain(
        id=data['id'],
        name=data['name'],
        description=data['description'],
        mitre_tags=data.get('mitre_tags', []),
        steps=steps
    )
