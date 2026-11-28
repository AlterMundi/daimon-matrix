//! A quest journal is a Holodeck view over shared cards.
use super::{BoardAccess, CATALOG, Card, Error, Labels, Status};
use crate::{GitRevision, WorldEvent};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

/// A registered project revision read by the host under the viewer's current scope.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectRevision {
    pub revision: GitRevision,
    pub label: String,
}

pub(super) fn surface_id(project: Uuid) -> String {
    format!("questbook-{project}")
}

/// The host owns `selected` and sends a new projection for a navigation
/// event. Title editing, claim and completion use the card writer.
pub fn mount(
    cards: &[Card],
    selected: Uuid,
    access: &BoardAccess<'_>,
    labels: &Labels<'_>,
    journal: &str,
    missions: &str,
    project_revisions: &[ProjectRevision],
) -> crate::Result<[Value; 3]> {
    crate::authorized(access, false)?;
    if cards.iter().any(|card| card.project != access.project) {
        return Err(Error::Access);
    }
    let card = cards
        .iter()
        .find(|card| card.id == selected)
        .ok_or(Error::Missing)?;
    let surface = surface_id(access.project);
    let objective_label = |event| match event {
        WorldEvent::BridgeState { raised: true } => "Conectá las islas del taller",
        WorldEvent::BridgeState { raised: false } => "Separá las islas del taller",
    };
    let instructions = card
        .objectives
        .iter()
        .map(|item| {
            let mark = if item.receipt.is_some() { "✓" } else { "○" };
            format!("{mark} {}", objective_label(item.objective.event.clone()))
        })
        .collect::<Vec<_>>()
        .join("\n");
    let revisions = project_revisions
        .iter()
        .filter(|link| card.evidence.contains(&link.revision))
        .map(|link| format!("{} · {}", link.label, link.revision.commit))
        .collect::<Vec<_>>();
    let tracking = card
        .objectives
        .iter()
        .filter(|item| {
            card.assignee.as_ref() == Some(access.actor)
                && card.status == Status::InProgress
                && item.receipt.is_none()
        })
        .map(|item| &item.objective)
        .collect::<Vec<_>>();
    let label = |status| match status {
        Status::Open => labels.open,
        Status::InProgress => labels.in_progress,
        Status::Done => labels.done,
    };
    let quests = [Status::Open, Status::InProgress, Status::Done]
        .into_iter()
        .flat_map(|status| cards.iter().filter(move |card| card.status == status))
        .map(|card| json!({"id":card.id,"label":format!("{} · {}",label(card.status),card.title)}))
        .collect::<Vec<_>>();
    let write_event = |name| json!({"event":{"name":name,"context":{"card":{"@path":"/id"},"revision":{"@path":"/revision"}}}});
    Ok([
        json!({"version":"1.0","createSurface":{"surfaceId":surface,"catalogId":CATALOG}}),
        json!({"version":"1.0","updateComponents":{"surfaceId":surface,"components":[
            {"id":"root","component":"HudPanel","label":journal,
                "children":["missions","objective","status","assignment","instructions","progress","revisions","edit_title","claim","done"]},
            {"id":"missions","component":"HudChoice","label":missions,"options":{"@path":"/quests"},
                "value":{"@path":"/selection"},"draft":{"@path":"/questDraft"},
                "action":{"event":{"name":"select_quest","context":{"card":{"@path":"/questDraft"}}}}},
            {"id":"objective","component":"HudText","label":{"@path":"/title"},"style":"title"},
            {"id":"status","component":"HudText","label":{"@path":"/status"}},
            {"id":"assignment","component":"HudText","label":{"@path":"/assignment"}},
            {"id":"instructions","component":"HudText","label":{"@path":"/instructions"},"lines":2,"visible":{"@path":"/hasObjectives"}},
            {"id":"progress","component":"HudText","label":{"@path":"/progress"},"visible":{"@path":"/hasObjectives"}},
            {"id":"revisions","component":"HudText","label":{"@path":"/revisions"},"lines":8,
                "visible":{"@path":"/hasRevisions"}},
            {"id":"edit_title","component":"HudButton","label":"Editar título",
                "visible":{"@path":"/canEditTitle"},"action":write_event("edit_title")},
            {"id":"claim","component":"HudButton","label":labels.claim,
                "disabled":{"@path":"/claimDisabled"},"action":write_event("claim")},
            {"id":"done","component":"HudButton","label":labels.mark_done,
                "disabled":{"@path":"/doneDisabled"},"action":write_event("done")}
        ]}}),
        json!({"version":"1.0","updateDataModel":{"surfaceId":surface,"value":{
            "quests":quests,"selection":selected,
            "id":card.id,"revision":card.revision,"title":card.title,"status":label(card.status),
            "assignment":if card.assignee.is_some() { labels.assigned } else { labels.unassigned },
            "hasObjectives":!card.objectives.is_empty(),"instructions":instructions,"tracking":tracking,
            "hasRevisions":!revisions.is_empty(),"revisions":revisions.join("\n"),
            "next":(cards.len() == 32).then(|| cards.last().map(|item| item.id)).flatten(),
            "progress":format!("{}/{}",card.objectives.iter().filter(|item|item.receipt.is_some()).count(),card.objectives.len()),
            "canEditTitle":access.can_write,
            "claimDisabled":!access.can_write || card.status != Status::Open || card.assignee.is_some(),
            "doneDisabled":!access.can_write || card.status != Status::InProgress || card.objectives.iter().any(|item|item.receipt.is_none()),
        }}}),
    ])
}
