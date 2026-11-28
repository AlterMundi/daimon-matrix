//! The spatial projection uses Holodeck's existing Proyección catalog.
//! A mounted surface is read-only except for the typed actions it exposes.
use super::{Action, BoardAccess, Card, Command, Error, Status};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

pub mod questbook;

const CATALOG: &str = "https://altermundi.github.io/proyeccion/catalogs/spatial-hud/1.0";

pub struct Labels<'a> {
    pub claim: &'a str,
    pub mark_done: &'a str,
    pub open: &'a str,
    pub in_progress: &'a str,
    pub done: &'a str,
    pub unassigned: &'a str,
    pub assigned: &'a str,
}

/// Stable ID for a card across model updates in the same projection.
fn surface_id(card: Uuid) -> String {
    format!("project-card-{card}")
}

pub fn mount(
    card: &Card,
    access: &BoardAccess<'_>,
    labels: &Labels<'_>,
) -> super::Result<[Value; 3]> {
    super::authorized(access, false)?;
    if access.project != card.project {
        return Err(Error::Access);
    }
    let surface = surface_id(card.id);
    let button = |id: &str, label: &str, disabled: &str| {
        json!({
            "id":id,"component":"HudButton","label":label,"disabled":{"@path":disabled},
            "action":{"event":{"name":id,"context":{"card":{"@path":"/id"},"revision":{"@path":"/revision"}}}}
        })
    };
    Ok([
        json!({"version":"1.0","createSurface":{"surfaceId":surface,"catalogId":CATALOG}}),
        json!({"version":"1.0","updateComponents":{"surfaceId":surface,"components":[
            {"id":"root","component":"HudPanel","label":{"@path":"/title"},"children":["status","assignment","claim","done"]},
            {"id":"assignment","component":"HudText","label":{"@path":"/assignment"}},
            {"id":"status","component":"HudText","label":{"@path":"/status"}},
            button("claim",labels.claim,"/claimDisabled"),
            button("done",labels.mark_done,"/doneDisabled")
        ]}}),
        update(card, access, labels)?,
    ])
}

/// Refresh only shared model fields. The host retains selection and local drafts.
pub fn update(card: &Card, access: &BoardAccess<'_>, labels: &Labels<'_>) -> super::Result<Value> {
    super::authorized(access, false)?;
    if access.project != card.project {
        return Err(Error::Access);
    }
    Ok(json!({"version":"1.0","updateDataModel":{
        "surfaceId":surface_id(card.id),"value":{
            "id":card.id, "revision":card.revision, "title":card.title,
            "status": match card.status { Status::Open => labels.open, Status::InProgress => labels.in_progress, Status::Done => labels.done },
            "assignment": if card.assignee.is_some() { labels.assigned } else { labels.unassigned },
            "claimDisabled":!access.can_write || card.status != Status::Open || card.assignee.is_some(),
            "doneDisabled":!access.can_write || card.status != Status::InProgress || card.objectives.iter().any(|item|item.receipt.is_none()),
        }
    }}))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Event {
    pub surface_id: String,
    pub name: String,
    pub context: Context,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Context {
    pub card: Uuid,
    pub revision: i64,
    #[serde(default)]
    pub title: Option<String>,
}

/// `mounted_card` comes from the host's retained surface selection.
pub fn command(
    event: Event,
    project: Uuid,
    mounted_card: Uuid,
    operation: Uuid,
) -> super::Result<Command> {
    if (event.surface_id != surface_id(mounted_card)
        && event.surface_id != questbook::surface_id(project))
        || event.context.card != mounted_card
    {
        return Err(Error::Access);
    }
    let action = match (event.name.as_str(), event.context.title) {
        ("claim", None) => Action::Claim,
        ("done", None) => Action::Complete,
        ("edit_title", Some(title)) if event.surface_id == questbook::surface_id(project) => {
            Action::EditTitle { title }
        }
        _ => return Err(Error::Invalid),
    };
    Ok(Command {
        operation,
        card: mounted_card,
        expected_revision: event.context.revision,
        action,
    })
}
