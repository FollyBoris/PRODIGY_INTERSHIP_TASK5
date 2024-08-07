# Network Packet Analyzer
## Description
This project is an advanced network packet analyzer written in Python. It uses the scapy library for packet capturing and analysis, and tabulate for displaying packet information in a readable table format.

## Features
Captures network packets with specified filters.
Displays packet details in a table format.
Saves captured packets to a file.
Reads and analyzes packets from a saved capture file.

## Installation
Clone the repository:

```bash
git clone https://github.com/FollyBoris/PRODIGY_INTERSHIP_TASK5.git
cd PRODIGY_INTERSHIP_TASK5
```
### Create a virtual environment:


Usage
Ensure the necessary modules are installed:

```bash
pip install scapy tabulate

```

### Run the network packet analyzer with the following options:

```bash
python packet_analyzer.py --count 10 --filter "tcp" --output captured_packets.pcap
```
### To read and analyze packets from a saved capture file:

```bash
python packet_analyzer.py --input captured_packets.pcap
```
