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

- `ryu.app.simple_switch_stp_13`
- `ryu.app.ofctl_rest`
- `ryu.app.rest_firewall`

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

- global `ALLOW` rules are applied through the Ryu firewall REST module
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
