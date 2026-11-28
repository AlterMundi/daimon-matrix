//! Shared project cards. An authenticated host resolves identity and project
//! access and calls this writer for both its tools and its human projection.
use std::{path::Path, time::Duration};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub mod a2ui;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorKind {
    Human,
    Daimon,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Actor {
    pub kind: ActorKind,
    pub subject: String,
}

impl Actor {
    fn valid(&self) -> bool {
        !self.subject.trim().is_empty()
            && self.subject.len() <= 256
            && !self.subject.chars().any(char::is_control)
    }
}

/// The owner adapter supplies this grant after resolving the authenticated
/// project audience. It is deliberately absent from the wire action schema.
pub struct BoardAccess<'a> {
    pub project: Uuid,
    pub actor: &'a Actor,
    pub can_write: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Open,
    InProgress,
    Done,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitRevision {
    pub repository: Uuid,
    pub commit: String,
}

impl GitRevision {
    fn valid(&self) -> bool {
        !self.repository.is_nil()
            && matches!(self.commit.len(), 40 | 64)
            && self
                .commit
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorldEvent {
    BridgeState { raised: bool },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldObjective {
    pub id: Uuid,
    pub place: String,
    pub event: WorldEvent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldReceipt {
    pub place: String,
    pub run: Uuid,
    pub edition: String,
    pub command: String,
    pub actor: String,
    pub sequence: u64,
    pub occurred_at_ms: u64,
    pub event: WorldEvent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorldProgress {
    pub objective: WorldObjective,
    pub receipt: Option<WorldReceipt>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    Create {
        title: String,
    },
    CreateIssue {
        title: String,
        description: String,
    },
    EditTitle {
        title: String,
    },
    Assign {
        assignee: Option<Actor>,
    },
    Claim,
    Complete,
    SetStatus {
        status: Status,
    },
    LinkRevision {
        revision: GitRevision,
    },
    RequireWorld {
        objective: WorldObjective,
    },
    RecordWorld {
        objective: Uuid,
        receipt: WorldReceipt,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Command {
    pub operation: Uuid,
    pub card: Uuid,
    pub expected_revision: i64,
    pub action: Action,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Card {
    pub id: Uuid,
    pub project: Uuid,
    pub revision: i64,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issue_description: Option<String>,
    pub status: Status,
    pub assignee: Option<Actor>,
    pub evidence: Vec<GitRevision>,
    pub revised_by: Actor,
    #[serde(default)]
    pub objectives: Vec<WorldProgress>,
    #[serde(default)]
    pub active_since_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub committed_at_ms: u64,
    pub command: Command,
    pub card: Card,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Outcome {
    Applied {
        event: Event,
    },
    Retained {
        event: Event,
    },
    Conflict {
        current_revision: i64,
        reason: Conflict,
    },
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Conflict {
    StaleRevision,
    OperationChanged,
    AlreadyAssigned,
    AlreadyCompleted,
    NotInProgress,
    ObjectivesPending,
    ObjectiveAlreadyRecorded,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("project access is unavailable")]
    Access,
    #[error("invalid card action")]
    Invalid,
    #[error("card is unavailable")]
    Missing,
    #[error("card already exists")]
    Exists,
    #[error(transparent)]
    Store(#[from] rusqlite::Error),
    #[error(transparent)]
    Encoding(#[from] serde_json::Error),
}

type Result<T> = std::result::Result<T, Error>;

fn authorized(access: &BoardAccess<'_>, write: bool) -> Result<()> {
    if access.project.is_nil() || !access.actor.valid() || (write && !access.can_write) {
        return Err(Error::Access);
    }
    Ok(())
}

pub struct Cards(Connection);

impl Cards {
    pub fn open(path: &Path) -> Result<Self> {
        let db = Connection::open(path)?;
        db.busy_timeout(Duration::from_secs(5))?;
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS card_events(
                project TEXT NOT NULL, card TEXT NOT NULL, revision INTEGER NOT NULL,
                operation TEXT NOT NULL, doc TEXT NOT NULL,
                PRIMARY KEY(project,card,revision), UNIQUE(project,operation)
            );",
        )?;
        Ok(Self(db))
    }

    pub fn read(&self, access: &BoardAccess<'_>, card: Uuid) -> Result<Option<Card>> {
        authorized(access, false)?;
        current(&self.0, access.project, card)
    }

    /// Stable card-ID pagination. Event history has its own per-card cursor.
    pub fn list(&self, access: &BoardAccess<'_>, after: Option<Uuid>) -> Result<Vec<Card>> {
        authorized(access, false)?;
        let mut query = self.0.prepare(
            "SELECT e.doc FROM card_events e
             WHERE e.project=?1 AND (?2 IS NULL OR e.card>?2)
               AND e.revision=(SELECT MAX(revision) FROM card_events
                              WHERE project=e.project AND card=e.card)
             ORDER BY e.card LIMIT 32",
        )?;
        events(
            &mut query,
            params![access.project.to_string(), after.map(|id| id.to_string())],
        )?
        .into_iter()
        .map(|event| Ok(event.card))
        .collect()
    }

    /// Export attributed events from the canonical writer without replaying them.
    pub fn history(&self, access: &BoardAccess<'_>, card: Uuid, after: i64) -> Result<Vec<Event>> {
        authorized(access, false)?;
        let mut query = self.0.prepare(
            "SELECT doc FROM card_events WHERE project=?1 AND card=?2 AND revision>?3
             ORDER BY revision LIMIT 32",
        )?;
        events(
            &mut query,
            params![access.project.to_string(), card.to_string(), after],
        )
    }

    /// Read the caller's original committed event without resubmitting a command.
    pub fn receipt(&self, access: &BoardAccess<'_>, operation: Uuid) -> Result<Option<Event>> {
        authorized(access, false)?;
        if operation.is_nil() {
            return Err(Error::Invalid);
        }
        Ok(operation_event(&self.0, access.project, operation)?
            .filter(|event| event.card.revised_by == *access.actor))
    }

    pub fn apply(&mut self, access: &BoardAccess<'_>, command: Command) -> Result<Outcome> {
        if matches!(command.action, Action::RecordWorld { .. }) {
            return Err(Error::Access);
        }
        self.commit(access, command)
    }

    /// Only the owner adapter calls this after reading the authoritative room
    /// receipt with the current project actor. Tool and surface actions use apply.
    pub fn record_world(&mut self, access: &BoardAccess<'_>, command: Command) -> Result<Outcome> {
        if !matches!(command.action, Action::RecordWorld { .. }) {
            return Err(Error::Invalid);
        }
        self.commit(access, command)
    }

    fn commit(&mut self, access: &BoardAccess<'_>, command: Command) -> Result<Outcome> {
        authorized(access, true)?;
        if command.operation.is_nil() || command.card.is_nil() || command.expected_revision < 0 {
            return Err(Error::Invalid);
        }
        let tx = self
            .0
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let card = current(&tx, access.project, command.card)?;
        let current_revision = card.as_ref().map_or(0, |card| card.revision);
        let conflict = |reason| Outcome::Conflict {
            current_revision,
            reason,
        };
        if let Some(event) = operation_event(&tx, access.project, command.operation)? {
            if event.card.revised_by == *access.actor && event.command == command {
                return Ok(Outcome::Retained { event });
            }
            return Ok(conflict(Conflict::OperationChanged));
        }
        if current_revision != command.expected_revision {
            return Ok(conflict(Conflict::StaleRevision));
        }
        let creation = match &command.action {
            Action::Create { title } => Some((title, None)),
            Action::CreateIssue { title, description } => Some((title, Some(description))),
            _ => None,
        };
        let mut card = match (creation, card) {
            (Some((title, description)), None) => {
                if title.trim().is_empty()
                    || title.len() > 240
                    || description
                        .is_some_and(|value| value.trim().is_empty() || value.len() > 4096)
                {
                    return Err(Error::Invalid);
                }
                Card {
                    id: command.card,
                    project: access.project,
                    revision: 0,
                    title: title.clone(),
                    issue_description: description.cloned(),
                    status: Status::Open,
                    assignee: None,
                    evidence: vec![],
                    revised_by: access.actor.clone(),
                    objectives: vec![],
                    active_since_ms: None,
                }
            }
            (Some(_), Some(_)) => return Err(Error::Exists),
            (None, None) => return Err(Error::Missing),
            (None, Some(card)) => card,
        };
        let time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Error::Invalid)?;
        let committed_at_ms = u64::try_from(time.as_millis()).map_err(|_| Error::Invalid)?;
        match &command.action {
            Action::Create { .. } | Action::CreateIssue { .. } => {}
            Action::EditTitle { title } => {
                if title.trim().is_empty() || title.len() > 240 {
                    return Err(Error::Invalid);
                }
                card.title.clone_from(title);
            }
            Action::Assign { assignee } => {
                if assignee.as_ref().is_some_and(|actor| !actor.valid()) {
                    return Err(Error::Invalid);
                }
                card.assignee.clone_from(assignee);
            }
            Action::Claim => {
                if card.status == Status::Done {
                    return Ok(conflict(Conflict::AlreadyCompleted));
                }
                if card.status != Status::Open || card.assignee.is_some() {
                    return Ok(conflict(Conflict::AlreadyAssigned));
                }
                card.assignee = Some(access.actor.clone());
                card.status = Status::InProgress;
                card.active_since_ms = Some(committed_at_ms);
            }
            Action::Complete => {
                if card.status != Status::InProgress {
                    return Ok(conflict(Conflict::NotInProgress));
                }
                if card
                    .objectives
                    .iter()
                    .any(|objective| objective.receipt.is_none())
                {
                    return Ok(conflict(Conflict::ObjectivesPending));
                }
                card.status = Status::Done;
            }
            Action::SetStatus { status } => {
                if *status == Status::Done
                    && card
                        .objectives
                        .iter()
                        .any(|objective| objective.receipt.is_none())
                {
                    return Ok(conflict(Conflict::ObjectivesPending));
                }
                if *status == Status::InProgress && card.status != Status::InProgress {
                    card.active_since_ms = Some(committed_at_ms);
                }
                card.status = *status;
            }
            Action::RequireWorld { objective } => {
                if card.status != Status::Open
                    || objective.id.is_nil()
                    || !identifier(&objective.place, 80)
                    || card
                        .objectives
                        .iter()
                        .any(|entry| entry.objective.id == objective.id)
                {
                    return Err(Error::Invalid);
                }
                card.objectives.push(WorldProgress {
                    objective: objective.clone(),
                    receipt: None,
                });
            }
            Action::RecordWorld { objective, receipt } => {
                if card.status != Status::InProgress {
                    return Ok(conflict(Conflict::NotInProgress));
                }
                let started = card.active_since_ms.ok_or(Error::Invalid)?;
                if receipt.actor != access.actor.subject
                    || receipt.run.is_nil()
                    || !identifier(&receipt.command, 80)
                    || !identifier(&receipt.edition, 160)
                    || receipt.sequence == 0
                    || receipt.occurred_at_ms < started
                {
                    return Err(Error::Invalid);
                }
                if card
                    .objectives
                    .iter()
                    .filter_map(|entry| entry.receipt.as_ref())
                    .any(|old| {
                        old.place == receipt.place
                            && old.run == receipt.run
                            && old.command == receipt.command
                    })
                {
                    return Ok(conflict(Conflict::ObjectiveAlreadyRecorded));
                }
                let target = card
                    .objectives
                    .iter_mut()
                    .find(|entry| entry.objective.id == *objective)
                    .filter(|entry| {
                        entry.objective.place == receipt.place
                            && entry.objective.event == receipt.event
                    })
                    .ok_or(Error::Invalid)?;
                if target.receipt.is_some() {
                    return Ok(conflict(Conflict::ObjectiveAlreadyRecorded));
                }
                target.receipt = Some(receipt.clone());
            }
            Action::LinkRevision { revision } => {
                if !revision.valid() {
                    return Err(Error::Invalid);
                }
                if let Some(head) = card
                    .evidence
                    .iter_mut()
                    .find(|head| head.repository == revision.repository)
                {
                    head.clone_from(revision);
                } else {
                    card.evidence.push(revision.clone());
                }
            }
        }
        card.revision = current_revision.checked_add(1).ok_or(Error::Invalid)?;
        card.revised_by = access.actor.clone();
        let event = Event {
            committed_at_ms,
            command,
            card,
        };
        tx.execute(
            "INSERT INTO card_events(project,card,revision,operation,doc) VALUES (?1,?2,?3,?4,?5)",
            params![
                event.card.project.to_string(),
                event.card.id.to_string(),
                event.card.revision,
                event.command.operation.to_string(),
                serde_json::to_string(&event)?
            ],
        )?;
        tx.commit()?;
        Ok(Outcome::Applied { event })
    }
}

fn identifier(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_@.".contains(&b))
}

fn operation_event(db: &Connection, project: Uuid, operation: Uuid) -> Result<Option<Event>> {
    let document: Option<String> = db
        .query_row(
            "SELECT doc FROM card_events WHERE project=?1 AND operation=?2",
            params![project.to_string(), operation.to_string()],
            |row| row.get(0),
        )
        .optional()?;
    Ok(document.as_deref().map(serde_json::from_str).transpose()?)
}

fn current(db: &Connection, project: Uuid, card: Uuid) -> Result<Option<Card>> {
    let raw: Option<String> = db.query_row(
        "SELECT doc FROM card_events WHERE project=?1 AND card=?2 ORDER BY revision DESC LIMIT 1",
        params![project.to_string(), card.to_string()], |row| row.get(0),
    ).optional()?;
    raw.map(|raw| Ok(serde_json::from_str::<Event>(&raw)?.card))
        .transpose()
}

fn events(
    query: &mut rusqlite::Statement<'_>,
    params: impl rusqlite::Params,
) -> Result<Vec<Event>> {
    let mut rows = query.query(params)?;
    let mut events = Vec::new();
    while let Some(row) = rows.next()? {
        events.push(serde_json::from_str(&row.get::<_, String>(0)?)?);
    }
    Ok(events)
}
