# MiMo Model Protocol

## Conflict Policy B

The system preserves all extracted facts, relations, and members, then separately marks the strongest currently usable item as `current_best`.

- Raw extracted claims remain stored with evidence.
- `current_best` is a presentation and export decision, not a deletion mechanism.
- A stronger later claim may replace the prior `current_best`, while the older claim remains queryable.
- Synthesis prompts must expose conflicts rather than silently removing them.

## Processing Stages

1. `article_extract`
   - Input: one normalized document plus candidate groups and limited database context.
   - Output: document-level facts, relations, members, events, alias evidence, and table candidates.

2. `group_profile_synthesis`
   - Input: one group's stored facts and evidence summaries.
   - Output: latest encyclopedia-style overview plus `current_best_updates`.

3. `group_structure_synthesis`
   - Input: one group's stored relations, members, and evidence summaries.
   - Output: latest structure overview plus selected relation/member IDs.

4. `apt_group_export_synthesis`
   - Input: approved overviews, approved aliases, current-best facts, and selected events.
   - Output: one row matching `apt_group_export`.

## Automatic Ingestion Mapping

- `basic_profile_updates` -> `group_facts` + `fact_evidence`
- `organization_structure_updates.relations` -> `group_relations` + `structure_evidence`
- `organization_structure_updates.members` -> `group_members` + `structure_evidence`
- `activity_events` -> `activity_events` + `event_groups` + `event_entities` + `event_evidence`
- `alias_evidence` -> `alias_evidence`
- `group_profile_synthesis.current_best_updates` -> update `group_facts.current_best`
- `group_profile_synthesis.latest_overview` -> `threat_groups.latest_overview`
- `group_structure_synthesis.latest_structure_overview` -> `threat_groups.latest_structure_overview`
- `apt_group_export_synthesis.apt_group_export` -> `apt_group_export`

## Provider Swapping

The model provider is selected through `config/llm.yaml`.
Any OpenAI-compatible provider can be substituted by changing `base_url`, `api_key_env`, and `model` only.
