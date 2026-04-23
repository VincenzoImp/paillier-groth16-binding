# Demo

This lab intentionally avoids a wide application UI.

The demo surface should stay thin and research-oriented:

- voter flow
- operator flow
- aggregate publication
- share submission
- transcript extraction
- attack reproduction through scripts

For the current implementation phase, the main demo path is script-driven and
contract-test-driven rather than app-driven.

The recommended demo order is:

1. run `yarn quick:attack`
2. run `yarn attack:demo`
3. run `yarn transcript:demo`
