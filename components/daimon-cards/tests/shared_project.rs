use std::{
    path::Path,
    process::{Command as Process, Stdio},
    sync::Barrier,
};

use daimon_cards::{
    Action, Actor, ActorKind, BoardAccess, Cards, Command, Conflict, Error, GitRevision, Outcome,
    Status, a2ui,
};
use serde_json::{Value, json};
use uuid::Uuid;

fn git(path: &Path, args: &[&str]) -> String {
    let output = Process::new("git")
        .current_dir(path)
        .args(args)
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output);
    String::from_utf8(output.stdout).unwrap().trim().into()
}

fn id(value: u128) -> Uuid {
    Uuid::from_u128(value)
}

fn action(operation: u128, card: Uuid, expected_revision: i64, action: Action) -> Command {
    Command {
        operation: id(operation),
        card,
        expected_revision,
        action,
    }
}

fn owner_call(db: &Path, access: &BoardAccess<'_>, input: Value) -> Value {
    let mut process = Process::new(env!("CARGO_BIN_EXE_daimon-cards"))
        .arg(db)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    serde_json::to_writer(
        process.stdin.take().unwrap(),
        &json!({
            "project":access.project,"actor":access.actor,"can_write":access.can_write,"input":input
        }),
    )
    .unwrap();
    let output = process.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "The owner adapter did not return a receipt"
    );
    let reply: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(reply["ok"], true, "{reply}");
    reply["result"].clone()
}

#[test]
fn a2ui_and_tools_share_the_card_writer_and_a_forge_independent_revision() {
    let fixture = tempfile::tempdir().unwrap();
    let room = fixture.path().join("room");
    let remote = fixture.path().join("story.git");
    let review = fixture.path().join("review");
    std::fs::create_dir(&room).unwrap();
    std::fs::create_dir(&remote).unwrap();
    git(&remote, &["init", "--bare", "--initial-branch=main"]);
    git(&room, &["init", "--initial-branch=main"]);
    std::fs::write(
        room.join("playtest.md"),
        "Walk to the beacon and light it.\n",
    )
    .unwrap();
    git(&room, &["add", "playtest.md"]);
    git(
        &room,
        &[
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-m",
            "First playtest",
        ],
    );
    git(&room, &["push", remote.to_str().unwrap(), "main"]);
    git(
        fixture.path(),
        &["clone", remote.to_str().unwrap(), review.to_str().unwrap()],
    );
    let revision = GitRevision {
        repository: id(51),
        commit: git(&review, &["rev-parse", "HEAD"]),
    };
    assert_eq!(revision.commit, git(&room, &["rev-parse", "HEAD"]));

    let human = Actor {
        kind: ActorKind::Human,
        subject: "paired-host-human".into(),
    };
    let daimon = Actor {
        kind: ActorKind::Daimon,
        subject: "signed-daimon".into(),
    };
    let project = id(10);
    let card = id(20);
    let human_access = BoardAccess {
        project,
        actor: &human,
        can_write: true,
    };
    let daimon_access = BoardAccess {
        project,
        actor: &daimon,
        can_write: true,
    };
    let labels = a2ui::Labels {
        claim: "Accept quest",
        mark_done: "Mark done",
        open: "Open",
        in_progress: "In progress",
        done: "Done",
        unassigned: "Unassigned",
        assigned: "Assigned",
    };
    let db = fixture.path().join("cards.sqlite");

    let description = "Walk to the beacon in the published scene and record the result.";
    let create = json!({
        "type":"apply","command":{
            "operation":id(1),"card":card,"expected_revision":0,
            "action":{"type":"create_issue","title":"Review the first playtest","description":description}
        }
    });
    let created = owner_call(&db, &human_access, create.clone());
    assert_eq!(created["status"], "applied");
    let retried = owner_call(&db, &human_access, create);
    assert_eq!(retried["status"], "retained");
    assert_eq!(retried["event"], created["event"]);

    let mut store = Cards::open(&db).unwrap();
    let edited = store
        .apply(
            &human_access,
            action(
                2,
                card,
                1,
                Action::EditTitle {
                    title: "Run the beacon playtest".into(),
                },
            ),
        )
        .unwrap();
    let Outcome::Applied { event: edited } = edited else {
        panic!("card edit was not applied")
    };
    let surface = owner_call(
        &db,
        &human_access,
        json!({
            "type":"mount_questbook","selected":card,"journal":"Questbook","missions":"Missions","labels":{
                "claim":labels.claim,"mark_done":labels.mark_done,"open":labels.open,
                "in_progress":labels.in_progress,"done":labels.done,
                "assigned":labels.assigned,"unassigned":labels.unassigned,
            }
        }),
    );
    let surface_id = surface[0]["createSurface"]["surfaceId"].clone();
    assert_eq!(surface[2]["updateDataModel"]["value"]["revision"], 2);
    assert_eq!(
        surface[2]["updateDataModel"]["value"]["issueDescription"],
        description
    );
    assert_eq!(surface[2]["updateDataModel"]["value"]["doneDisabled"], true);
    let premature = store
        .apply(&human_access, action(90, card, 2, Action::Complete))
        .unwrap();
    assert!(matches!(
        premature,
        Outcome::Conflict {
            current_revision: 2,
            reason: Conflict::NotInProgress,
        }
    ));
    assert_eq!(
        surface[2]["updateDataModel"]["value"]["title"],
        edited.card.title
    );
    let activated_event = |name: &str, revision: i64| {
        json!({"surfaceId":surface_id,"name":name,
        "context":{"card":card,"revision":revision}})
    };
    let human_event: Value = if let Some(projection) = std::env::var_os("DAIMON_CARDS_PROYECCION") {
        let mut browser = Process::new("node")
            .arg("tests/projection_probe.mjs")
            .arg(projection)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        serde_json::to_writer(browser.stdin.take().unwrap(), &surface).unwrap();
        let output = browser.wait_with_output().unwrap();
        assert!(output.status.success(), "The spatial renderer probe failed");
        let stdout = String::from_utf8(output.stdout).unwrap();
        let event = stdout
            .lines()
            .find_map(|line| line.strip_prefix("DAIMON_CARDS_EVENT "))
            .expect("the renderer emitted no card action");
        serde_json::from_str(event).unwrap()
    } else {
        activated_event("claim", 2)
    };
    let human_claim = a2ui::command(
        serde_json::from_value(human_event.clone()).unwrap(),
        project,
        card,
        id(3),
    )
    .unwrap();
    let daimon_claim: Command = serde_json::from_value(json!({"operation":id(4),"card":card,
        "expected_revision":2,"action":{"type":"claim"}}))
    .unwrap();
    let barrier = Barrier::new(2);
    let race = |access: &BoardAccess<'_>, input: Value| -> Outcome {
        barrier.wait();
        serde_json::from_value(owner_call(&db, access, input)).unwrap()
    };
    let (human_result, daimon_result) = std::thread::scope(|threads| {
        let left = threads.spawn(|| race(&human_access, json!({
            "type":"apply_surface","operation":id(3),"mounted_card":card,"event":human_event,
        })));
        let right = threads.spawn(|| {
            race(
                &daimon_access,
                json!({
                    "type":"apply","command":daimon_claim,
                }),
            )
        });
        (left.join().unwrap(), right.join().unwrap())
    });
    let (accepted, winner, winning_command) = match (human_result, daimon_result) {
        (
            Outcome::Applied { event },
            Outcome::Conflict {
                current_revision: 3,
                reason: Conflict::StaleRevision,
            },
        ) => (event, &human_access, human_claim),
        (
            Outcome::Conflict {
                current_revision: 3,
                reason: Conflict::StaleRevision,
            },
            Outcome::Applied { event },
        ) => (event, &daimon_access, daimon_claim),
        unexpected => panic!("expected exactly one claim to commit: {unexpected:?}"),
    };
    assert_eq!(accepted.card.assignee.as_ref(), Some(winner.actor));
    assert_eq!(accepted.card.status, Status::InProgress);
    assert_eq!(
        store.read(&daimon_access, card).unwrap(),
        Some(accepted.card.clone())
    );
    let refresh = a2ui::update(&accepted.card, &human_access, &labels).unwrap();
    assert_eq!(surface_id, format!("questbook-{project}"));
    assert_eq!(
        refresh["updateDataModel"]["value"]["status"],
        labels.in_progress
    );
    assert_eq!(refresh["updateDataModel"]["value"]["claimDisabled"], true);
    assert!(refresh["updateDataModel"]["value"].get("draft").is_none());

    store
        .apply(
            &daimon_access,
            action(
                5,
                card,
                3,
                Action::LinkRevision {
                    revision: revision.clone(),
                },
            ),
        )
        .unwrap();
    let finished = owner_call(
        &db,
        &human_access,
        json!({
            "type":"apply_surface","operation":id(6),"mounted_card":card,
            "event":activated_event("done",4),
        }),
    );
    assert_eq!(finished["event"]["card"]["status"], "done");
    drop(store);

    let mut reopened = Cards::open(&db).unwrap();
    let stored = reopened.read(&human_access, card).unwrap().unwrap();
    assert_eq!(stored.revision, 5);
    assert_eq!(stored.issue_description.as_deref(), Some(description));
    assert_eq!(stored.status, Status::Done);
    assert_eq!(stored.evidence, vec![revision.clone()]);
    assert_eq!(reopened.list(&daimon_access, None).unwrap(), vec![stored]);
    assert_eq!(reopened.history(&human_access, card, 0).unwrap().len(), 5);
    assert_eq!(
        reopened.apply(winner, winning_command.clone()).unwrap(),
        Outcome::Retained { event: accepted }
    );
    let other = if winner.actor == &human {
        &daimon_access
    } else {
        &human_access
    };
    assert!(matches!(
        reopened.apply(other, winning_command.clone()).unwrap(),
        Outcome::Conflict {
            current_revision: 5,
            reason: Conflict::OperationChanged
        }
    ));
    let read_only = BoardAccess {
        can_write: false,
        ..*winner
    };
    assert!(matches!(
        reopened.apply(&read_only, winning_command),
        Err(Error::Access)
    ));
    let foreign = BoardAccess {
        project: id(99),
        ..*winner
    };
    assert!(reopened.read(&foreign, card).unwrap().is_none());
    assert!(reopened.list(&foreign, None).unwrap().is_empty());

    let mismatched = serde_json::from_value(json!({"surfaceId":surface_id,"name":"done",
        "context":{"card":id(80),"revision":5}}))
    .unwrap();
    assert!(matches!(
        a2ui::command(mismatched, project, card, id(81)),
        Err(Error::Access)
    ));

    let another = id(91);
    reopened
        .apply(
            &human_access,
            action(
                92,
                another,
                0,
                Action::Create {
                    title: "Find the map".into(),
                },
            ),
        )
        .unwrap();
    let cards = reopened.list(&daimon_access, None).unwrap();
    let project_revisions = [a2ui::questbook::ProjectRevision {
        revision: revision.clone(),
        label: "Playtest".into(),
    }];
    let journal = a2ui::questbook::mount(
        &cards,
        card,
        &human_access,
        &labels,
        "Questbook",
        "Missions",
        &project_revisions,
    )
    .unwrap();
    let state = &journal[2]["updateDataModel"]["value"];
    assert_eq!(state["selection"], json!(card));
    assert_eq!(
        state["revisions"],
        format!("Playtest · {}", revision.commit)
    );
    assert_eq!(state["quests"][0]["label"], "Open · Find the map");
    assert_eq!(
        state["quests"][1]["label"],
        "Done · Run the beacon playtest"
    );
    let changed = a2ui::questbook::mount(
        &cards,
        another,
        &human_access,
        &labels,
        "Questbook",
        "Missions",
        &project_revisions,
    )
    .unwrap();
    assert_eq!(journal[0], changed[0]);
    assert_eq!(
        changed[2]["updateDataModel"]["value"]["hasRevisions"],
        false
    );
    assert_eq!(
        changed[2]["updateDataModel"]["value"]["selection"],
        json!(another)
    );
    assert_eq!(
        reopened.history(&human_access, another, 0).unwrap().len(),
        1
    );
}

#[test]
fn world_objectives_require_confirmed_receipts_before_completion() {
    use daimon_cards::{WorldEvent, WorldObjective, WorldReceipt};

    let temp = tempfile::tempdir().unwrap();
    let mut store = Cards::open(&temp.path().join("board.sqlite")).unwrap();
    let actor = Actor {
        kind: ActorKind::Daimon,
        subject: "fixture-daimon".into(),
    };
    let access = BoardAccess {
        project: id(1),
        actor: &actor,
        can_write: true,
    };
    let card = id(2);
    let objective = WorldObjective {
        id: id(3),
        place: "island-workshop".into(),
        event: WorldEvent::BridgeState { raised: true },
    };
    store
        .apply(
            &access,
            action(
                40,
                card,
                0,
                Action::Create {
                    title: "Operate the bridge".into(),
                },
            ),
        )
        .unwrap();
    store
        .apply(
            &access,
            action(
                41,
                card,
                1,
                Action::RequireWorld {
                    objective: objective.clone(),
                },
            ),
        )
        .unwrap();
    let active = store
        .apply(&access, action(42, card, 2, Action::Claim))
        .unwrap();
    let Outcome::Applied { event } = active else {
        panic!("Quest not accepted")
    };
    let receipt = WorldReceipt {
        place: objective.place.clone(),
        run: id(4),
        edition: "island-workshop@draft-1".into(),
        command: "original-bridge-action".into(),
        actor: actor.subject.clone(),
        sequence: 17,
        occurred_at_ms: event.card.active_since_ms.unwrap(),
        event: objective.event,
    };
    assert!(matches!(
        store
            .apply(
                &access,
                action(
                    43,
                    card,
                    3,
                    Action::SetStatus {
                        status: Status::Done
                    }
                )
            )
            .unwrap(),
        Outcome::Conflict {
            current_revision: 3,
            reason: Conflict::ObjectivesPending
        }
    ));
    let command = action(
        44,
        card,
        3,
        Action::RecordWorld {
            objective: objective.id,
            receipt: receipt.clone(),
        },
    );
    assert!(matches!(
        store.apply(&access, command.clone()),
        Err(Error::Access)
    ));
    let mut mismatch = receipt.clone();
    mismatch.actor = "different-fixture".into();
    assert!(matches!(
        store.record_world(
            &access,
            action(
                45,
                card,
                3,
                Action::RecordWorld {
                    objective: objective.id,
                    receipt: mismatch
                }
            )
        ),
        Err(Error::Invalid)
    ));
    let credited = store.record_world(&access, command.clone()).unwrap();
    let Outcome::Applied { event } = credited else {
        panic!("Room evidence not applied")
    };
    assert_eq!(event.card.objectives[0].receipt.as_ref(), Some(&receipt));
    let closed = store
        .apply(&access, action(46, card, 4, Action::Complete))
        .unwrap();
    assert!(matches!(closed, Outcome::Applied { event } if event.card.status == Status::Done));
    assert_eq!(
        store.record_world(&access, command).unwrap(),
        Outcome::Retained { event }
    );
}
