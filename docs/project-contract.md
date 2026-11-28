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

For the isolated pilot, run `python tools/verify_project_git.py REPO COMMIT`
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
A topic can start with an empty room and gain surfaces as its work develops.

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
