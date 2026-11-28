//! Owner-side process adapter for a host that already authenticates project access.
use std::{io::Read, path::Path};

use daimon_cards::{Actor, BoardAccess, Cards, Command, Error, a2ui};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    project: Uuid,
    actor: Actor,
    can_write: bool,
    input: Operation,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum Operation {
    List {
        after: Option<Uuid>,
    },
    Read {
        card: Uuid,
    },
    Receipt {
        operation: Uuid,
    },
    History {
        card: Uuid,
        after: i64,
    },
    Apply {
        command: Command,
    },
    RecordWorld {
        command: Command,
    },
    MountCard {
        card: Uuid,
        labels: ProjectionLabels,
    },
    MountQuestbook {
        selected: Option<Uuid>,
        after: Option<Uuid>,
        labels: ProjectionLabels,
        journal: String,
        missions: String,
    },
    ApplySurface {
        operation: Uuid,
        mounted_card: Uuid,
        event: a2ui::Event,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectionLabels {
    claim: String,
    mark_done: String,
    open: String,
    in_progress: String,
    done: String,
    assigned: String,
    unassigned: String,
}

impl ProjectionLabels {
    fn labels(&self) -> a2ui::Labels<'_> {
        a2ui::Labels {
            claim: &self.claim,
            mark_done: &self.mark_done,
            open: &self.open,
            in_progress: &self.in_progress,
            done: &self.done,
            assigned: &self.assigned,
            unassigned: &self.unassigned,
        }
    }
}

fn execute(cards: &mut Cards, request: Request) -> Result<Value, Error> {
    let access = BoardAccess {
        project: request.project,
        actor: &request.actor,
        can_write: request.can_write,
    };
    Ok(match request.input {
        Operation::List { after } => json!(cards.list(&access, after)?),
        Operation::Read { card } => json!(cards.read(&access, card)?),
        Operation::Receipt { operation } => json!(cards.receipt(&access, operation)?),
        Operation::History { card, after } => json!(cards.history(&access, card, after)?),
        Operation::Apply { command } => json!(cards.apply(&access, command)?),
        Operation::RecordWorld { command } => json!(cards.record_world(&access, command)?),
        Operation::MountCard { card, labels } => {
            let card = cards.read(&access, card)?.ok_or(Error::Missing)?;
            json!(a2ui::mount(&card, &access, &labels.labels())?)
        }
        Operation::MountQuestbook {
            selected,
            after,
            labels,
            journal,
            missions,
        } => {
            let cards = cards.list(&access, after)?;
            let selected = selected.or_else(|| cards.first().map(|card| card.id));
            let Some(selected) = selected else {
                return Ok(Value::Null);
            };
            json!(a2ui::questbook::mount(
                &cards,
                selected,
                &access,
                &labels.labels(),
                &journal,
                &missions
            )?)
        }
        Operation::ApplySurface {
            operation,
            mounted_card,
            event,
        } => {
            let command = a2ui::command(event, access.project, mounted_card, operation)?;
            json!(cards.apply(&access, command)?)
        }
    })
}

fn run(store: &Path) -> Result<Value, Box<dyn std::error::Error>> {
    const MAX_REQUEST: u64 = 16 * 1024;
    let mut data = Vec::new();
    std::io::stdin()
        .take(MAX_REQUEST + 1)
        .read_to_end(&mut data)?;
    if data.len() as u64 > MAX_REQUEST {
        return Err(Error::Invalid.into());
    }
    let request: Request = serde_json::from_slice(&data)?;
    let mut cards = Cards::open(store)?;
    let reply = match execute(&mut cards, request) {
        Ok(result) => json!({"ok":true,"result":result}),
        Err(Error::Access) => json!({"ok":false,"code":"access"}),
        Err(Error::Invalid) => json!({"ok":false,"code":"invalid"}),
        Err(Error::Exists) => json!({"ok":false,"code":"exists"}),
        Err(Error::Missing) => json!({"ok":false,"code":"missing"}),
        Err(error) => return Err(error.into()),
    };
    Ok(reply)
}

fn main() -> std::process::ExitCode {
    let mut args = std::env::args_os().skip(1);
    let Some(store) = args.next().filter(|_| args.next().is_none()) else {
        eprintln!("Usage: daimon-cards STORE < REQUEST.json");
        return std::process::ExitCode::FAILURE;
    };
    match run(Path::new(&store)) {
        Ok(reply) => {
            println!("{reply}");
            std::process::ExitCode::SUCCESS
        }
        Err(_) => {
            // Caller retains the original operation ID and can inspect the
            // authoritative writer before retrying a write.
            eprintln!("Card operation could not be confirmed");
            std::process::ExitCode::FAILURE
        }
    }
}
