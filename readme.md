# FBBL

A small TUI (Text User Interface) application for capturing and inspecting network frames (Ethernet, IP, TCP). The app is built with the [Textual](https://textual.textualize.io/) library.

> [!WARNING]
> This application only works on **Linux**. Windows does not support direct access to the network card via raw sockets in the same way.

## Installation
Install the required dependencies:

```bash
pip install -r requirements.txt
```

## Running

The application requires root privileges to work with raw sockets and read from network interfaces. Run it as follows:

```bash
sudo python main.py
```