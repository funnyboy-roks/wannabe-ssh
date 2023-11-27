# Wannabe-SSH

[name may change at some point, tbd]

An application that allows one to run pre-defined commands on their
computer from a web browser by authenticating with GitHub.  All commands
are defined by the computer on which they will be run through the config
file.

## Parts

There are 3 parts of this project: the daemon, the server, and the web
client

### Daemon (`wannabe-daemon`)

This runs on the computer that will be responsible for executing the
commands.  It tells the server what commands it can execute and executes
them when the server instructs it over a websocket connection.

### Server (`wannabe-server`)

This runs on a server somewhere (I use a VPS) and is responsible for
managing connections.  It has a few endpoints that allow auth by the web
client and connecting with the daemons using websockets.

### Web Client

This is a _very_ simple website that just shows a bunch of buttons for
each command which can be run.


## TODO

There are many TODOs for this project, that I have probably missed some.

- [ ] Security! -- super important since it will literally run shell
  commands on the computer
- [ ] More config options
    - Daemon: Customise notification settings, actions that are not
      shell commands(?), customise logging (stdout/stderr and more)
    - Server: port, auth provider(???)
- [ ] Actually daemonise the daemon
    - [`daemonize`](https://docs.rs/daemonize/latest/daemonize/) seems
      good
- [ ] GitHub CI
- [ ] Tests
