import { TimelineEvent, MitreTechnique, MitreTacticGroup } from './types';

// Standard Enterprise MITRE ATT&CK Tactics
export const MITRE_TACTIC_DEFINITIONS: { id: string; name: string; description: string }[] = [
  { id: 'TA0001', name: 'Initial Access', description: 'Techniques used to gain an initial foothold into the victim network.' },
  { id: 'TA0002', name: 'Execution', description: 'Techniques that result in adversary-controlled code running on a local or remote system.' },
  { id: 'TA0003', name: 'Persistence', description: 'Techniques adversaries use to keep access across restarts, changed credentials, and interruptions.' },
  { id: 'TA0004', name: 'Privilege Escalation', description: 'Techniques used to gain higher-level permissions on a system or network.' },
  { id: 'TA0005', name: 'Defense Evasion', description: 'Techniques adversaries use to avoid detection throughout their compromise.' },
  { id: 'TA0006', name: 'Credential Access', description: 'Techniques for stealing credentials like account names and passwords.' },
  { id: 'TA0007', name: 'Discovery', description: 'Techniques an adversary may use to observe the system and internal environment.' },
  { id: 'TA0008', name: 'Lateral Movement', description: 'Techniques adversaries use to enter and control remote systems on a network.' },
  { id: 'TA0009', name: 'Collection', description: 'Techniques used to gather information of interest prior to exfiltration.' },
  { id: 'TA0011', name: 'Command and Control', description: 'Techniques adversaries use to communicate with systems under their control.' },
  { id: 'TA0010', name: 'Exfiltration', description: 'Techniques used to steal data from the targeted network.' },
  { id: 'TA0040', name: 'Impact', description: 'Techniques adversaries use to disrupt availability or compromise integrity by manipulating processes.' },
];

/**
 * Maps an array of chronological timeline events to the MITRE ATT&CK matrix.
 * Groups findings by tactic and correlates detected event IDs.
 */
export function mapEventsToMitre(events: TimelineEvent[]): MitreTacticGroup[] {
  const tacticMap = new Map<string, Map<string, MitreTechnique>>();

  // Initialize all tactics
  for (const t of MITRE_TACTIC_DEFINITIONS) {
    tacticMap.set(t.id, new Map());
  }

  for (const event of events) {
    if (!event.mitreTactic || !event.mitreTechnique || !event.mitreId) continue;

    // Find tactic ID (e.g. TA0040)
    const match = event.mitreTactic.match(/\b(TA\d{4})\b/);
    const tacticId = match ? match[1] : 'TA0002';
    const tacticTechniques = tacticMap.get(tacticId) || new Map<string, MitreTechnique>();

    const techId = event.mitreId;
    if (tacticTechniques.has(techId)) {
      const existing = tacticTechniques.get(techId)!;
      existing.detectedEventsCount++;
      if (!existing.eventIds.includes(event.id)) existing.eventIds.push(event.id);
      if (event.severity === 'CRITICAL') existing.severity = 'CRITICAL';
      else if (event.severity === 'HIGH' && existing.severity !== 'CRITICAL') existing.severity = 'HIGH';
    } else {
      tacticTechniques.set(techId, {
        id: techId,
        name: event.mitreTechnique,
        tactic: event.mitreTactic,
        tacticId,
        description: `Observed via artifact ${event.sourceArtifact}: ${event.summary}`,
        detectedEventsCount: 1,
        eventIds: [event.id],
        severity: event.severity,
        confidence: event.confidence,
      });
    }

    tacticMap.set(tacticId, tacticTechniques);
  }

  // Convert to array of tactic groups
  return MITRE_TACTIC_DEFINITIONS.map((tDef) => ({
    id: tDef.id,
    name: tDef.name,
    techniques: Array.from(tacticMap.get(tDef.id)?.values() || []),
  }));
}
