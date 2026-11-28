use std::{
    path::Path,
    process::{Command as Process, Stdio},
    sync::Barrier,
};

use daimon_cards::{
    Action, Actor, ActorKind, BoardAccess, Cards, Command, Conflict, Error, GitRevision, Outcome,
    Status, a2ui,
};
use serde_json::json;
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
        claim: "Take card",
        mark_done: "Mark done",
        open: "Open",
        in_progress: "In progress",
        done: "Done",
        unassigned: "Unassigned",
        assigned: "Assigned",
    };
    let db = fixture.path().join("cards.sqlite");

    let mut store = Cards::open(&db).unwrap();
    let created = store
        .apply(
            &human_access,
            action(
                1,
                card,
                0,
                Action::Create {
                    title: "Review the first playtest".into(),
                },
            ),
        )
        .unwrap();
    assert!(matches!(created, Outcome::Applied { .. }));
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
    let surface = a2ui::mount(&edited.card, &human_access, &labels).unwrap();
    let surface_id = surface[0]["createSurface"]["surfaceId"].clone();
    assert_eq!(surface[2]["updateDataModel"]["value"]["revision"], 2);
    let activate = |name: &str, revision: i64, operation: u128| {
        let event = serde_json::from_value(json!({"surfaceId":surface_id,"name":name,
            "context":{"card":card,"revision":revision}}))
        .unwrap();
        a2ui::command(event, card, id(operation)).unwrap()
    };
    let human_claim = if let Some(projection) = std::env::var_os("DAIMON_CARDS_PROYECCION") {
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
        a2ui::command(serde_json::from_str(event).unwrap(), card, id(3)).unwrap()
    } else {
        activate("claim", 2, 3)
    };
    let daimon_claim: Command = serde_json::from_value(json!({"operation":id(4),"card":card,
        "expected_revision":2,"action":{"type":"claim"}}))
    .unwrap();
    let barrier = Barrier::new(2);
    let claim = |access: &BoardAccess<'_>, command: Command| {
        let mut contender = Cards::open(&db).unwrap();
        barrier.wait();
        contender.apply(access, command).unwrap()
    };
    let (human_result, daimon_result) = std::thread::scope(|threads| {
        let left = threads.spawn(|| claim(&human_access, human_claim.clone()));
        let right = threads.spawn(|| claim(&daimon_access, daimon_claim.clone()));
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
    assert_eq!(
        store.read(&daimon_access, card).unwrap(),
        Some(accepted.card.clone())
    );
    let refresh = a2ui::update(&accepted.card, &human_access, &labels).unwrap();
    assert_eq!(refresh["updateDataModel"]["surfaceId"], surface_id);
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
    store.apply(&human_access, activate("done", 4, 6)).unwrap();
    drop(store);

    let mut reopened = Cards::open(&db).unwrap();
    let stored = reopened.read(&human_access, card).unwrap().unwrap();
    assert_eq!(stored.revision, 5);
    assert_eq!(stored.status, Status::Done);
    assert_eq!(stored.evidence, vec![revision]);
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
        a2ui::command(mismatched, card, id(81)),
        Err(Error::Access)
    ));
}
