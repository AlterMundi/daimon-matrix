# Daimon technical project contract

When a person proposes creating something, the daimon should tend to make it a
project the person can use, revisit and continue with another embodiment. This
applies to code, games, stories, designs and other creative work. The human can
start by describing or playing with the idea in their usual surface. The daimon
handles the project setup as part of making the thing.

## Preserve the work in Git

Use a Git repository for work that is expected to continue. Link the repository
from the conversation doing the work. Use an existing repo when the proposal
extends a project. For a new project, initialize Git where the work will live
and commit the first useful revision. Local Git works with any participant.
When the project is shared, use a remote reachable by its participants and an
accessible view for people who do not use Git. Keep large project sources in
their supported durable storage and commit stable references where needed.

### Repository and revision binding

Use the topic's existing Gateway workspace binding to find its permanent
folder. A project checkout is an explicit selection within or alongside that
folder. An existing Git root is reused with its own history. For new work,
initialize only the selected project directory and commit the first useful
files. Stage only changes belonging to that iteration. An existing repository,
index, or uncommitted change remains part of the operator's working state.

A topic can link to multiple projects, a project can have multiple repositories,
and the same project can appear in more than one topic. Keep logical topic,
project, repository, and checkout identities distinct. Adding a repository or
advancing its revision must preserve the other links in the topic.

Each durable link records the project and repository identities, the authorized
repository locator, and the full Git commit object ID. A local checkout is a
per-workspace resolution of that locator. List and resolve links through their
current audiences. Page the catalog and select what a cold start needs without
limiting which projects or repositories can remain linked. A branch name helps navigation. The commit
identifies the revision under review. An inaccessible locator, unborn
repository or missing commit leaves the reference unresolved. A local
repository is a valid project. When collaboration spans hosts, use a cloneable
remote reachable by the authorized participants.

The first test uses a readable non-code project, a local Git remote, and two
independent workspace directories. Both sides resolve the same project commit
after one workspace moves. Returning to the first workspace leaves its local
changes intact. Repeated observation produces the same revision without a new
commit, network write or model call.

For a new checkout, obtain the current permanent workspace claim through
Gateway and run
`python tools/prepare_project_git.py WORKSPACE CLAIM CHECKOUT REPOSITORY_UUID`.
Choose a new child directory and keep the repository UUID to repeat the
operation. The helper initializes an empty local repository and returns its
locator. For a shared filesystem, add `--shared-root DIRECTORY` to select an
existing authorized setgid, group-writable directory. The helper initializes
or reuses the bare repository for that UUID and clones it into the selected
workspace. All collaborators using this route need access to the same
absolute mount. The helper inherits the mount's group, checks the workspace
marker and refuses a different repository at the selected path. It never
stages project files. Use ordinary Git to commit the first useful files and,
if shared, push the first revision. On a filesystem where Git requires
explicit trust for a collaborator-owned bare repository, use its exact
authorized path with `git -c safe.directory=/path/to/repository.git` for the
Git operation. Existing SSH and HTTP repositories can use ordinary Git
directly. The helper does not create service access or edit an existing
checkout's Git configuration.

Use `python tools/verify_project_git.py REPO COMMIT`
on the already authorized checkout. The probe only verifies the exact local
Git object. Gateway remains responsible for the topic binding, access to
the referenced source and publishing a checkpoint revision.

The project records its purpose, how to open or run it, and the next action
when that would let someone else continue. Use shared cards when there is
work to coordinate. Record decisions and meaningful changes where future
collaborators can retrieve them from the project and conversation. Reuse the
topic checkpoint and existing receipts to recover after a harness change.

## Make project state usable from tools and surfaces

Represent project data with stable IDs and enough structure for a daimon to
read the relevant state and take useful actions programmatically. A document
may expose sections and edits. A game may expose scenes, objects, rules and
supported actions. Keep the state and validation with the application that
owns the project. Associate edits with the actual actor and revision.

Project an appropriate interface for the person through A2UI. The surface's
component tree, selection and drafts have their own view state. Controls use
the same project operations as programmatic tools, so changing surfaces keeps
the target and the work consistent. Routine rendering, data reads and actions
can go directly through the project operations. Use model turns for design,
interpretation and novel work. Start with the smallest useful state and
surface, and extend them as the project develops.

## Enter a topic as a room

In Holodeck, represent a Matrix topic as a room where people and daimons can
return to the work. Bind the room to the existing logical topic. Entering it
situates the current conversation and work in that topic with the visitor's
current access. Room decoration and position belong to Holodeck. Topic history,
checkpoints and project links retain their existing authorities and identities.
Holodeck's topic explorer is available from the ordinary entrance, including
when a daimon has no house. It lists the visitor's current accessible topics.
Choosing one opens its default virtual room. Derive that room from the existing
topic, its authorized project links and the maintained default layout and
workflow. Show conversation and the current state of the work, with project
doors, worktables and the questbook as the available work calls for them. An
empty topic is usable for conversation and gains project surfaces as links and
shared work are recorded. Reads and ordinary updates use those existing
records without a setup step or an extra model turn.

A house, a custom layout or a handcrafted topic space is optional. Apply such
customizations to the presentation of the same logical topic and work. A
visitor can still find the topic through the explorer and use the default
presentation when a custom room has not been configured.

### Conversation and visible work in the room

Entering a topic room keeps our general conversation as the default. The
same CompAII avatar can accompany the person into the room. Freeze the current
topic identity and relevant place or selection with each intervention at
intake. The general conversation receives the original once with that
attributed context. The room independently shows the daimon's work in that
topic, including current activity, available results and pending questions
the visitor may see and answer. These are projections of retained sources.
Represent the same being at work in different conversations, with activity
and attention grounded in observed state.

Offer an explicit way to talk directly to the topic while staying in the
room. The canonical Conversation view then shows that topic's history and
routes input to it. Indicate the active recipient in the composer and in the
room. The general conversation avatar can step aside, disappear or visibly
yield the floor. The visual choice can vary with the layout. Keep a clear
way back to general Conversation while staying situated.

Moving between rooms can change the current context. A submitted original
keeps its captured audience, destination and source references. Preserve
drafts and in-flight receipts across the transition. Leaving direct mode or
the room can offer a return to our general conversation with an optional
handoff. A person can say what they want to bring back or select an attributed
update. If automatic handoffs are explicitly configured, use the same
attributed return path and preserve its audience. Movement itself has no
send, approval or model effect.

Arrange the room around what participants do with its linked projects. A door
can lead to a game's world, a walkable design or another substantial project
experience. A worktable can open a project at its selected revision or bring
several linked projects together for comparison or composition. A questbook
shows shared missions and opens work at the relevant project or place. These
are options the host can combine. The same project can appear in different
rooms through its existing link and writer. A table may keep its own selection
or drafts. A committed edit still targets the actual project and its revision.

Resolve each link against the visitor's access before showing or opening it.
Admission to a room does not grant access to every linked project. Reuse the
same typed project actions in the room, in a project space and in non-spatial
clients. Changing the room layout or switching harnesses preserves the topic
and its work.

## Let the person create through the medium

For a playable game or place, prefer Holodeck as the primary projection when
it supports the experience. A child proposing a game can sketch the rules in
conversation, enter a playable prototype and point to what should change.
The daimon can act on the same scene and selection using project tools. A2UI
can project choices, a playtest panel or a scene inspector in that context.
The repo preserves the rules, source and references needed to resume with
another body. The child's ordinary experience is to invent and play the game.

The [portability roadmap](portability-roadmap.md) defines how to qualify shared
cards, topic checkpoints and cold recovery using a real project. Start with
these defaults for new work and prove the shared workflow in the pilot before
changing existing project writers or moving existing workspaces.
