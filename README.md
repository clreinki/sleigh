[![Deploy to DO](https://www.deploytodo.com/do-btn-blue-ghost.svg)](https://cloud.digitalocean.com/apps/new?repo=https://github.com/clreinki/sleigh/tree/main&refcode=fd652045edeb)


## Overview
Sleigh is a Django-based management server for managing the [Santa](https://northpole.dev/) configurations across your environment.  It combines a highly performant server-client communication platform with a simple to use web interface for easy management and reporting.

This project and the latest release is available on [Github](https://github.com/clreinki/sleigh).

## Features
* **Fully integrated web server:** Sleigh replaces your existing Santa server (Moroz, Zentral, etc)
* **Flexible deployment options:** Can be hosted locally using Dokku (preferred) or via various cloud-providers like Digital Ocean or Heroku
* **High performance caching:** Extensive use of in-memory caching allows sub-10ms response times and easily supports 10k+ clients using minimal hardware
* **Multiple client configurations:** Manage multiple profiles (rulesets) across your environment.  Need different configurations for each department?  You can easily apply a new configuration to a set of clients from the web interface without any changes needed on the client.
* **Changelog Tracking:** Not sure who made a change?  All changes are logged and can quickly be reviewed.
* **Reporting:** See the last time a client checked in along with basic device info so you can ensure Santa is working properly

## Installation and Getting Started
Full documentation can be found at [Sleigh.cloud](https://sleigh.cloud)

## Contributing
Contributions are welcome, especially for front-end improvements (spoiler alert: I'm not a UI developer!)