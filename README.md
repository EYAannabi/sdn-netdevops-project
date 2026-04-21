# SDN NetDevOps Project

This project is a reproducible Software-Defined Networking (SDN) lab built around **Ryu**, **Mininet**, **Docker**, **Ansible**, **Prometheus**, **Grafana**, and **GitHub Actions**.

It demonstrates how to:

- run an SDN controller in a container
- create a Mininet datacenter-style topology
- manage firewall and QoS rules as code
- validate network behavior automatically in CI
- deploy a persistent lab for demonstrations
- expose and visualize metrics with Prometheus and Grafana

## Project Goals

The main goals of the project are:

- automate the deployment of an SDN environment
- separate controller logic, topology, policies, tests, and observability
- validate connectivity and policy enforcement automatically
- keep a persistent lab available after successful CI
- apply a NetDevOps workflow to an SDN use case

## High-Level Architecture

The project is organized around five layers:

1. **Controller**
   Ryu runs inside Docker and loads its apps from [iac/controller_config.yml](/c:/Users/MSI/Desktop/2ATEL/pfa/sdn-netdevops-project/sdn-netdevops-project-main/iac/controller_config.yml).
2. **Topology**
   Mininet creates a small spine-leaf datacenter topology with four switches and four hosts.
3. **Policy as Code**
   Firewall and QoS policies are defined in JSON and applied by [scripts/deploy_policies.py](/c:/Users/MSI/Desktop/2ATEL/pfa/sdn-netdevops-project/sdn-netdevops-project-main/scripts/deploy_policies.py).
4. **Testing**
   [tests/network_tests.py](/c:/Users/MSI/Desktop/2ATEL/pfa/sdn-netdevops-project/sdn-netdevops-project-main/tests/network_tests.py) builds an ephemeral network, applies policies, and validates behavior.
5. **Observability**
   Prometheus, Grafana, `ryu_exporter`, and sFlow-RT collect and display SDN metrics.

## How the Controller Starts

The controller startup flow is:

1. [docker/Dockerfile](/c:/Users/MSI/Desktop/2ATEL/pfa/sdn-netdevops-project/sdn-netdevops-project-main/docker/Dockerfile) builds the Ryu image.
2. The container starts [controller/main_controller.py](/c:/Users/MSI/Desktop/2ATEL/pfa/sdn-netdevops-project/sdn-netdevops-project-main/controller/main_controller.py).
3. [controller/main_controller.py](/c:/Users/MSI/Desktop/2ATEL/pfa/sdn-netdevops-project/sdn-netdevops-project-main/controller/main_controller.py) reads [iac/controller_config.yml](/c:/Users/MSI/Desktop/2ATEL/pfa/sdn-netdevops-project/sdn-netdevops-project-main/iac/controller_config.yml).
4. It launches `ryu-manager` with:
   - the configured Ryu apps
   - the OpenFlow port `6653`
   - the REST API port `8080`

The currently loaded Ryu apps are:

- `controller.apps.datacenter_controller`
- `ryu.app.ofctl_rest`

## Topology Design

The topology is defined in [topology/datacenter_topo.py](/c:/Users/MSI/Desktop/2ATEL/pfa/sdn-netdevops-project/sdn-netdevops-project-main/topology/datacenter_topo.py).

It contains:

- 2 spine switches: `s1`, `s2`
- 2 leaf switches: `s3`, `s4`
- 4 hosts: `h1`, `h2`, `h3`, `h4`

Host addressing:

- `h1` -> `10.0.0.1/24`
- `h2` -> `10.0.0.2/24`
- `h3` -> `10.0.0.3/24`
- `h4` -> `10.0.0.4/24`

The links are redundant:

- `h1`, `h2` connect to `s3`
- `h3`, `h4` connect to `s4`
- each leaf connects to both spines

This design allows the project to test:

- normal connectivity
- traffic blocking rules
- link failover and STP-based recovery

## Policy Deployment

[scripts/deploy_policies.py](/c:/Users/MSI/Desktop/2ATEL/pfa/sdn-netdevops-project/sdn-netdevops-project-main/scripts/deploy_policies.py) is the policy deployment entry point.

It performs three main actions:

1. waits for the Ryu REST API and connected switches
2. reads [controller/policies/firewall.json](/c:/Users/MSI/Desktop/2ATEL/pfa/sdn-netdevops-project/sdn-netdevops-project-main/controller/policies/firewall.json) and applies firewall rules
3. reads [controller/policies/qos.json](/c:/Users/MSI/Desktop/2ATEL/pfa/sdn-netdevops-project/sdn-netdevops-project-main/controller/policies/qos.json) and applies QoS policing

Firewall behavior:

- global `ALLOW` rules are kept as implicit forwarding behavior in the custom controller
- `DENY` rules are translated into explicit OpenFlow drop flows

QoS behavior:

- QoS is currently enforced mainly through OVS ingress policing
- some helper functions for a more advanced Ryu/OVSDB QoS model exist in the code but are not fully used yet

## Automated Testing

[tests/network_tests.py](/c:/Users/MSI/Desktop/2ATEL/pfa/sdn-netdevops-project/sdn-netdevops-project-main/tests/network_tests.py) is the main CI validation script.

Its execution flow is:

1. create an ephemeral Mininet topology
2. connect the topology to the Ryu controller on `127.0.0.1:6653`
3. call [scripts/deploy_policies.py](/c:/Users/MSI/Desktop/2ATEL/pfa/sdn-netdevops-project/sdn-netdevops-project-main/scripts/deploy_policies.py)
4. derive the expected allow/deny plan from the JSON policy files
5. run connectivity tests
6. simulate a link failure
7. verify self-healing and rerouting

What is currently tested:

- allowed traffic reaches its destination
- denied traffic is blocked
- the network recovers after a link failure

QoS note:

- QoS rules are detected in CI
- strict QoS validation is currently skipped in the CI flow

## Persistent Lab Validation

[tests/validate_lab.py](/c:/Users/MSI/Desktop/2ATEL/pfa/sdn-netdevops-project/sdn-netdevops-project-main/tests/validate_lab.py) validates the persistent lab after deployment.

It checks that:

- the Ryu REST API is reachable
- the persistent topology process is running
- OVS bridges exist

## CI/CD Workflow

The project uses two GitHub Actions workflows:

- [`.github/workflows/ci.yml`](/c:/Users/MSI/Desktop/2ATEL/pfa/sdn-netdevops-project/sdn-netdevops-project-main/.github/workflows/ci.yml)
- [`.github/workflows/cd.yml`](/c:/Users/MSI/Desktop/2ATEL/pfa/sdn-netdevops-project/sdn-netdevops-project-main/.github/workflows/cd.yml)

### CI

The CI workflow runs on:

- pushes to `main`
- pull requests targeting `main`

It does the following:

1. checks out the repository
2. builds the controller Docker image
3. runs [ansible/deploy_ci.yml](/c:/Users/MSI/Desktop/2ATEL/pfa/sdn-netdevops-project/sdn-netdevops-project-main/ansible/deploy_ci.yml)

[ansible/deploy_ci.yml](/c:/Users/MSI/Desktop/2ATEL/pfa/sdn-netdevops-project/sdn-netdevops-project-main/ansible/deploy_ci.yml) launches:

- the `controller` role
- the `topology` role in `ci` mode

This produces a short-lived validation environment.

### CD

The CD workflow runs only after a successful CI run.

It does the following:

1. checks out the repository
2. rebuilds the controller image
3. runs [ansible/deploy_lab.yml](/c:/Users/MSI/Desktop/2ATEL/pfa/sdn-netdevops-project/sdn-netdevops-project-main/ansible/deploy_lab.yml)
4. runs [tests/validate_lab.py](/c:/Users/MSI/Desktop/2ATEL/pfa/sdn-netdevops-project/sdn-netdevops-project-main/tests/validate_lab.py)

[ansible/deploy_lab.yml](/c:/Users/MSI/Desktop/2ATEL/pfa/sdn-netdevops-project/sdn-netdevops-project-main/ansible/deploy_lab.yml) launches:

- the `controller` role
- the `topology` role in `lab` mode
- the `monitoring` role
- the `firewall` role

This produces a persistent lab environment.

## Ansible Roles

The Ansible roles are split by responsibility:

- [ansible/roles/controller/tasks/main.yml](/c:/Users/MSI/Desktop/2ATEL/pfa/sdn-netdevops-project/sdn-netdevops-project-main/ansible/roles/controller/tasks/main.yml)
  builds and starts the Ryu controller container
- [ansible/roles/topology/tasks/ci.yml](/c:/Users/MSI/Desktop/2ATEL/pfa/sdn-netdevops-project/sdn-netdevops-project-main/ansible/roles/topology/tasks/ci.yml)
  runs the automated network tests
- [ansible/roles/topology/tasks/lab.yml](/c:/Users/MSI/Desktop/2ATEL/pfa/sdn-netdevops-project/sdn-netdevops-project-main/ansible/roles/topology/tasks/lab.yml)
  starts the persistent Mininet topology inside `tmux`
- [ansible/roles/monitoring/tasks/main.yml](/c:/Users/MSI/Desktop/2ATEL/pfa/sdn-netdevops-project/sdn-netdevops-project-main/ansible/roles/monitoring/tasks/main.yml)
  starts Prometheus, Grafana, sFlow-RT, and the exporter stack
- [ansible/roles/firewall/tasks/main.yml](/c:/Users/MSI/Desktop/2ATEL/pfa/sdn-netdevops-project/sdn-netdevops-project-main/ansible/roles/firewall/tasks/main.yml)
  applies SDN policies from the JSON source of truth

## Monitoring Stack

[docker-compose.yml](/c:/Users/MSI/Desktop/2ATEL/pfa/sdn-netdevops-project/sdn-netdevops-project-main/docker-compose.yml) starts the monitoring services:

- `ryu_exporter`
- `prometheus`
- `grafana`
- `sflow-rt`

Important ports:

- Ryu OpenFlow: `6653`
- Ryu REST API: `8080`
- `ryu_exporter`: `8000`
- Prometheus: `9090`
- Grafana: `3001`
- sFlow-RT: `8008`
- sFlow UDP: `6343/udp`

## Step-by-Step Deployment Guide

This section explains how to deploy the project from scratch on a fresh Ubuntu virtual machine. It covers system preparation, dependency installation, GitHub access, first manual tests, and self-hosted GitHub Actions setup.

Recommended target:

- Ubuntu 22.04 or 24.04 VM
- a user account with `sudo` privileges
- internet access for package installation and GitHub access

### Phase 1. System Preparation and Dependencies

#### 1. Update the system

Start by refreshing package indexes and upgrading installed packages:

```bash
sudo apt update && sudo apt upgrade -y
```

#### 2. Install core tools

These packages are useful for cloning the repository, troubleshooting networking, and building dependencies:

```bash
sudo apt install -y git curl wget net-tools build-essential
```

If you are using VMware or VirtualBox, you can also install guest utilities:

```bash
sudo apt install -y open-vm-tools open-vm-tools-desktop
```

#### 3. Install Docker

The controller and monitoring stack rely on Docker and Docker Compose:

```bash
sudo apt install -y docker.io docker-compose
sudo systemctl enable docker
sudo systemctl start docker
sudo usermod -aG docker $USER
newgrp docker
```

The `newgrp docker` command reloads your group membership in the current shell so you can run Docker without `sudo`.

#### 4. Install SDN infrastructure tools

Mininet and Open vSwitch are required to emulate the topology and apply switching behavior:

```bash
sudo apt install -y mininet openvswitch-switch xterm
sudo systemctl enable openvswitch-switch
sudo systemctl start openvswitch-switch
```

#### 5. Install Ansible and Python dependencies

Ansible is used to orchestrate both CI-style and lab-style deployments. Python dependencies are needed by the controller tooling and monitoring helpers:

```bash
sudo apt install -y ansible python3-pip
pip3 install requests pyyaml prometheus_client
```

### Phase 2. GitHub Integration and Workspace Setup

#### 1. Configure Git identity

Set your Git author information before making changes:

```bash
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"
```

#### 2. Generate and register an SSH key

Create an SSH key so you can clone and push without entering your GitHub password every time:

```bash
ssh-keygen -t ed25519 -C "your.email@example.com"
```

Accept the default path and choose a passphrase if you want extra protection. Then display the public key:

```bash
cat ~/.ssh/id_ed25519.pub
```

Copy the output and add it in GitHub:

1. Go to `GitHub -> Settings -> SSH and GPG keys -> New SSH key`
2. Paste the public key
3. Save it

Test the connection:

```bash
ssh -T git@github.com
```

If prompted, type `yes` to trust GitHub's host key.

#### 3. Clone the repository

Fork the project or clone your own copy, then move into the workspace:

```bash
git clone git@github.com:EYAannabi/sdn-netdevops-project.git
cd sdn-netdevops-project
```

#### 4. Install VS Code

If you want to edit and inspect the project directly inside the VM:

```bash
sudo snap install --classic code
code .
```

### Phase 3. Infrastructure Prerequisites and Manual Validation

Before relying on GitHub Actions, it is a good idea to verify that the base infrastructure works locally.

#### 1. Create the Docker network

The Compose stack expects an external Docker network:

```bash
docker network create sdn_net
```

This only needs to be done once per VM.

#### 2. Build the controller image

Build the Ryu controller image manually:

```bash
docker build -t mon-ryu:v2 -f docker/Dockerfile .
```

#### 3. Clean the environment when needed

If a previous test left Mininet bridges, containers, or stale state behind, clean the lab before retrying:

```bash
sudo mn -c
sudo ovs-vsctl --if-exists del-br s1
sudo ovs-vsctl --if-exists del-br s2
sudo ovs-vsctl --if-exists del-br s3
sudo ovs-vsctl --if-exists del-br s4
docker rm -f sdn-controller grafana prometheus ryu_exporter sflow-rt 2>/dev/null || true
```

#### 4. Run the Ansible playbooks manually

Use these playbooks to confirm the environment is correctly configured before automating it:

```bash
ansible-playbook ansible/deploy_ci.yml -i ansible/inventory.ini
ansible-playbook ansible/deploy_lab.yml -i ansible/inventory.ini
```

If both playbooks complete successfully, the VM is ready for normal project use.

### Phase 4. Configure the CI/CD Pipeline

This project uses a self-hosted GitHub Actions runner because Mininet and Open vSwitch must run directly on the VM.

#### 1. Allow passwordless sudo

The self-hosted runner needs to execute network and Mininet commands non-interactively:

```bash
sudo visudo
```

Add the following line at the end of the file, replacing `ubuntu` with your actual VM username:

```text
ubuntu ALL=(ALL) NOPASSWD:ALL
```

#### 2. Add the self-hosted GitHub runner

In your GitHub repository:

1. Go to `Settings -> Actions -> Runners`
2. Click `New self-hosted runner`
3. Choose `Linux` and `x64`
4. Run the generated download and configuration commands on the VM

Start the runner with:

```bash
./run.sh
```

To keep it persistent across reboots, install it as a service:

```bash
sudo ./svc.sh install
sudo ./svc.sh start
```

#### 3. Trigger the pipeline

Push a commit to launch the workflows:

```bash
git commit --allow-empty -m "Trigger CI/CD pipeline"
git push
```

You can then watch execution in the `Actions` tab of your repository.

### Phase 5. Interact with the Persistent Lab

After a successful lab deployment, you can observe services and validate network behavior manually.

#### 1. Open the monitoring dashboards

Use the VM IP address instead of `localhost` if you are connecting from another machine.

- Grafana: `http://localhost:3001`
- Prometheus: `http://localhost:9090`
- sFlow-RT: `http://localhost:8008`

Grafana is the best place to inspect infrastructure health and traffic behavior at a glance.

#### 2. Attach to the Mininet lab

The persistent lab topology runs inside `tmux`. Attach to it with:

```bash
sudo tmux attach -t mininet_lab
```

From the Mininet prompt, test connectivity:

```bash
pingall
```

#### 3. Test QoS behavior

You can manually generate traffic between hosts to observe rate limiting:

```bash
xterm h1 h3
```

Then run these commands in the opened host terminals:

On `h3`:

```bash
iperf -s -u &
```

On `h1`:

```bash
iperf -c 10.0.0.3 -u -b 6M -t 10
```

Watch the QoS-related dashboards in Grafana while the traffic is running.

To detach from the `tmux` session without stopping the lab, press `Ctrl+B`, then `D`.

### Quick Start Checklist

If you want the shortest path from a fresh VM to a working lab, the practical order is:

1. install Docker, Mininet, Open vSwitch, Ansible, and Python dependencies
2. clone the repository and create the `sdn_net` Docker network
3. build `mon-ryu:v2`
4. run `ansible-playbook ansible/deploy_ci.yml -i ansible/inventory.ini`
5. run `ansible-playbook ansible/deploy_lab.yml -i ansible/inventory.ini`
6. configure a self-hosted GitHub runner if you want the full CI/CD workflow

Once those steps work, the VM is ready to host the project for demos, testing, and automation experiments.

## Repository Structure

```text
sdn-netdevops-project/
|-- .github/workflows/
|   |-- ci.yml
|   `-- cd.yml
|-- ansible/
|   |-- deploy_ci.yml
|   |-- deploy_lab.yml
|   |-- inventory.ini
|   `-- roles/
|       |-- controller/
|       |-- firewall/
|       |-- monitoring/
|       `-- topology/
|-- controller/
|   |-- main_controller.py
|   `-- policies/
|       |-- firewall.json
|       `-- qos.json
|-- docker/
|   |-- Dockerfile
|   `-- Dockerfile.exporter
|-- iac/
|   `-- controller_config.yml
|-- monitoring/
|   `-- prometheus.yml
|-- scripts/
|   |-- deploy_policies.py
|   |-- ryu_exporter.py
|   |-- start_datacenter.py
|   `-- start_demo.py
|-- tests/
|   |-- network_tests.py
|   `-- validate_lab.py
|-- topology/
|   |-- datacenter_topo.py
|   `-- start_lab_topology.py
`-- docker-compose.yml
```

## Typical Execution Paths

### 1. CI Validation Path

```text
GitHub Actions CI
-> ansible/deploy_ci.yml
-> controller role
-> topology role (ci mode)
-> tests/network_tests.py
-> scripts/deploy_policies.py
-> connectivity and failover validation
```

### 2. Persistent Lab Deployment Path

```text
GitHub Actions CD
-> ansible/deploy_lab.yml
-> controller role
-> topology role (lab mode)
-> monitoring role
-> firewall role
-> tests/validate_lab.py
```

### 3. Controller Runtime Path

```text
docker run mon-ryu:v2
-> controller/main_controller.py
-> iac/controller_config.yml
-> ryu-manager
-> OpenFlow + REST services
```

## Local Usage Notes

This project assumes a host capable of running:

- Docker
- Python 3
- Mininet
- Open vSwitch
- Ansible
- `sudo`
- `tmux` for persistent lab mode

The GitHub Actions workflows use a **self-hosted runner** because standard hosted runners do not provide a suitable Mininet and OVS environment by default.

## Known Limitations

- QoS validation is not fully enforced in CI
- some QoS helper functions are present but not fully integrated into the active deployment path
- the project depends on a self-hosted environment with SDN tools already installed

## Summary

This repository is a small but complete NetDevOps SDN platform:

- Docker runs the controller
- Mininet emulates the network
- JSON files define policies
- Python scripts apply and validate behavior
- Ansible orchestrates deployment
- GitHub Actions links CI and CD
- Prometheus and Grafana provide observability

It is a good project for demonstrating SDN automation, policy-driven networking, CI/CD for infrastructure, and observability in a lab environment.
