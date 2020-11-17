---
title: Contribution Guidelines
weight: 40
---

## Code of Conduct

Please refer to the Kinvolk [Code of Conduct](https://github.com/kinvolk/contribution/blob/master/CODE_OF_CONDUCT.md).

## Setup developer environment

```bash
git clone git@github.com:kinvolk/seccompagent.git
cd seccompagent
```

## Build the code

```bash
make
```

## Build with container image

```bash
make container-image
```

## Authoring PRs

For the general guidelines on making PRs/commits easier to review, please check out
Kinvolk's
[contribution guidelines on git](https://github.com/kinvolk/contribution/tree/master/topics/git.md).

## Updating dependencies

In order to update dependencies managed with Go modules, run `make vendor`,
which will ensure that all steps needed for an update are taken (tidy and vendoring).

## Testing and linting requirements

```bash
make test
```
