# Decisions

Why the script is built the way it is. The code keeps its comments short — what a line
does and why — and the longer story behind a choice is told here, once.

| # | Decision |
|---|---|
| [0001](0001-ssh-port-switch.md) | Moving SSH to a new port: a test sshd, the socket kept, a timed way back |
| [0002](0002-one-file-built-from-src.md) | Edited in `src/`, shipped as one file |
| [0003](0003-one-list-for-setup-and-check.md) | One list for what the setup writes and what `--check` expects |
| [0004](0004-lessons-from-live-runs.md) | What live servers and VM runs showed, and where the code answers it |

A new record gets the next number. A decision that is replaced is not deleted: its record
says what replaced it and why.
