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
pub enum Action {
    Create { title: String },
    EditTitle { title: String },
    Assign { assignee: Option<Actor> },
    Claim,
    SetStatus { status: Status },
    LinkRevision { revision: GitRevision },
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
    pub status: Status,
    pub assignee: Option<Actor>,
    pub evidence: Vec<GitRevision>,
    pub revised_by: Actor,
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

    pub fn apply(&mut self, access: &BoardAccess<'_>, command: Command) -> Result<Outcome> {
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
        let original: Option<String> = tx
            .query_row(
                "SELECT doc FROM card_events WHERE project=?1 AND operation=?2",
                params![access.project.to_string(), command.operation.to_string()],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(original) = original {
            let event: Event = serde_json::from_str(&original)?;
            if event.card.revised_by == *access.actor && event.command == command {
                return Ok(Outcome::Retained { event });
            }
            return Ok(conflict(Conflict::OperationChanged));
        }
        if current_revision != command.expected_revision {
            return Ok(conflict(Conflict::StaleRevision));
        }
        let mut card = match (&command.action, card) {
            (Action::Create { title }, None) if !title.trim().is_empty() && title.len() <= 240 => {
                Card {
                    id: command.card,
                    project: access.project,
                    revision: 0,
                    title: title.clone(),
                    status: Status::Open,
                    assignee: None,
                    evidence: vec![],
                    revised_by: access.actor.clone(),
                }
            }
            (Action::Create { .. }, None) => return Err(Error::Invalid),
            (Action::Create { .. }, Some(_)) => return Err(Error::Exists),
            (_, None) => return Err(Error::Missing),
            (_, Some(card)) => card,
        };
        match &command.action {
            Action::Create { .. } => {}
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
                if card
                    .assignee
                    .as_ref()
                    .is_some_and(|assignee| assignee != access.actor)
                {
                    return Ok(conflict(Conflict::AlreadyAssigned));
                }
                card.assignee = Some(access.actor.clone());
            }
            Action::SetStatus { status } => card.status = *status,
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
        let time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Error::Invalid)?;
        let committed_at_ms = u64::try_from(time.as_millis()).map_err(|_| Error::Invalid)?;
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
