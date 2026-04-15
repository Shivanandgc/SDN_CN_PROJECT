# SDN_CN_PROJECT 🚀

A Software Defined Networking (SDN) project built using **Mininet** and a custom **Ryu Controller** to simulate and manage network traffic dynamically.

---

## 📌 Project Description

This project demonstrates the concept of SDN by separating the **control plane** from the **data plane**.

It uses:

* **Mininet** for network emulation
* **Ryu Controller** for controlling network behavior
* **OpenFlow Protocol** for communication between switches and controller

---

## 🧠 Objective

* Create a virtual network topology
* Implement a custom SDN controller
* Dynamically control packet forwarding
* Understand flow-based networking

---

## 🛠️ Technologies Used

* Python
* Mininet
* Ryu Controller
* Open vSwitch (OVS)
* Linux / Ubuntu

---

## 📂 Project Structure

SDN_CN_PROJECT/
│── controller.py        # Ryu controller logic
│── topology.py          # Mininet topology
│── README.md

---

## ⚙️ Installation & Setup

### 1. Install Mininet

sudo apt update
sudo apt install mininet

### 2. Install Ryu

pip install ryu

### 3. Clone Repository

git clone https://github.com/Shivanandgc/SDN_CN_PROJECT.git
cd SDN_CN_PROJECT

---

## ▶️ How to Run

### Step 1: Start Controller

ryu-manager controller.py

### Step 2: Run Topology

sudo python3 topology.py

### Step 3: Test Network

pingall

---

## 🔍 How It Works

1. Mininet creates a virtual network
2. Switches connect to the controller
3. Unknown packets are sent to controller
4. Controller installs flow rules
5. Future packets are forwarded directly

---

## 📊 Features

* Custom SDN controller
* Dynamic flow rule installation
* Packet forwarding using OpenFlow
* Programmable network behavior

---

## 🧪 Example Commands

pingall              # Test connectivity
iperf h1 h2          # Check bandwidth
dpctl dump-flows     # View flow rules

---

## 🚀 Future Enhancements

* Load balancing
* Firewall implementation
* Traffic monitoring
* Multi-controller support

---


