from typing import List, Dict, Optional
from .models import TelemetryEvent, EventType
from .schema import AttackChain, ChainStep

class CorrelationEngine:
    def __init__(self, chains: List[AttackChain]):
        self.chains = chains
        self.active_tracks: List[Dict] = []
        # We maintain a process tree to check lineage: {pid: ppid}
        self.process_tree: Dict[int, Optional[int]] = {}

    def ingest(self, event: TelemetryEvent) -> List[str]:
        alerts = []
        
        # Update process tree
        if event.event_type == EventType.PROCESS_CREATE and event.ppid is not None:
            self.process_tree[event.pid] = event.ppid

        # 1. Evaluate against active partial chains
        for track in list(self.active_tracks):
            chain = track['chain']
            step_idx = track['current_step_index']
            next_step = chain.steps[step_idx]
            
            if self._match_step(next_step, event, track):
                track['current_step_index'] += 1
                track['matched_pids'].append(event.pid)
                track['matched_events'].append(event)
                
                if track['current_step_index'] == len(chain.steps):
                    alerts.append(self._generate_alert(chain, track['matched_events']))
                    self.active_tracks.remove(track)

        # 2. Check if event starts a new chain
        for chain in self.chains:
            first_step = chain.steps[0]
            if self._match_step(first_step, event, None):
                if len(chain.steps) == 1:
                    alerts.append(self._generate_alert(chain, [event]))
                else:
                    self.active_tracks.append({
                        'chain': chain,
                        'current_step_index': 1,
                        'matched_pids': [event.pid],
                        'matched_events': [event]
                    })
                    
        return alerts

    def _match_step(self, step: ChainStep, event: TelemetryEvent, track: Optional[Dict]) -> bool:
        if event.event_type.value != step.event_type:
            return False
            
        # Check lineage for subsequent steps (must be spawned by a process in the chain)
        if track:
            # Is event.pid a child of any PID previously matched in this chain?
            # Also handle if event.pid is the same as a matched pid (e.g. ETW event enriching kernel event).
            lineage_matched = (event.pid in track['matched_pids'])
            curr_ppid = event.ppid or self.process_tree.get(event.pid)
            while not lineage_matched and curr_ppid:
                if curr_ppid in track['matched_pids']:
                    lineage_matched = True
                    break
                curr_ppid = self.process_tree.get(curr_ppid)
            
            if not lineage_matched:
                return False

        # Evaluate conditions
        for k, v in step.conditions.items():
            if k == "image_path" and v.lower() not in event.image_path.lower():
                return False
            if k == "command_line" and event.command_line and v.lower() not in event.command_line.lower():
                return False
            if k == "registry_key" and "registry_key" in event.details and v.lower() not in event.details["registry_key"].lower():
                return False
                
        return True

    def _generate_alert(self, chain: AttackChain, events: List[TelemetryEvent]) -> str:
        pids = [str(e.pid) for e in events]
        return f"[ALERT] {chain.name} ({chain.id}) detected! MITRE: {', '.join(chain.mitre_tags)}. PID Lineage: {' -> '.join(pids)}"
