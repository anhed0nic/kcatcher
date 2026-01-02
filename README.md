<p align="center">
  <img width="657" height="380" alt="kcatcher-logo" src="https://github.com/user-attachments/assets/618e8ff0-6b74-4e12-825b-7613d3b17e15" />
</p>

<p align="center">
  <em>Catch what's lurking in your Kafka clusters.</em>
</p>

## Introduction

Kcatcher is a command-line utility for enumerating and evaluating Kafka cluster configurations. It connects to Apache Kafka clusters and retrieves detailed information about brokers, topics, ACLs, and even samples messages. Perfect for security audits, infrastructure assessments, or just understanding what's running in your Kafka environment.

## Demo

![kcatcher-demo](https://github.com/user-attachments/assets/88db1acc-b3b5-43e1-a40e-678b04b9ec92)

## Installation

### Go

If you have a functional Go environment, you can install with:

```sh
go install github.com/RoseSecurity/kcatcher@latest
```

### Apt

To install packages, you can quickly setup the repository automatically:

```sh
curl -1sLf \
  'https://dl.cloudsmith.io/public/rosesecurity/kcatcher/setup.deb.sh' \
  | sudo -E bash
```

Once the repository is configured, you can install with:

```sh
apt install kcatcher
```

### Source

```sh
git clone git@github.com:RoseSecurity/kcatcher.git
cd kcatcher
make build
```

## Usage

### Basic Enumeration

Connect to a Kafka cluster and retrieve broker and topic metadata:

```sh
kcatcher -b kafka-broker-1,kafka-broker-2
```

### Custom Port

Specify a non-default Kafka port:

```sh
kcatcher -b kafka-broker-1 -p 9093
```

### ACL Enumeration

Retrieve Access Control Lists configured on the cluster:

```sh
kcatcher -b kafka-broker-1 --acls
```

### Message Sampling

Sample recent messages from a specific topic:

```sh
kcatcher -b kafka-broker-1 --sample-topic my-topic --sample-count 5
```

### JSON Output

Output results in JSON format for further processing:

```sh
kcatcher -b kafka-broker-1 --acls -o json
```

### Configuration Enumeration

Retrieve broker and topic configurations:

```sh
kcatcher -b kafka-broker-1 --configs
```

### Security Analysis

Run a comprehensive security analysis on your Kafka cluster:

```sh
kcatcher -b kafka-broker-1 --analyze
```

Combine with ACL and configuration enumeration for a complete assessment:

```sh
kcatcher -b kafka-broker-1 --acls --configs --analyze
```

The security analysis evaluates your cluster against 20 built-in security rules across five categories: Authentication, Authorization, Encryption, Access Control, and Configuration. Results include a security score (0-100), letter grade, and detailed findings with remediation guidance.

### Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-b, --brokers` | List of Kafka brokers to enumerate (required) | - |
| `-p, --port` | Kafka broker port | `9092` |
| `-t, --timeout` | Connection timeout duration | `10s` |
| `-o, --output` | Output format (`text` or `json`) | `text` |
| `--acls` | Enable ACL enumeration | `false` |
| `--configs` | Enable broker and topic configuration retrieval | `false` |
| `--analyze` | Run security analysis on cluster configuration | `false` |
| `--metadata` | Show cluster metadata (auto-enabled unless `--analyze` only) | `true` |
| `--sample-topic` | Topic to sample messages from | - |
| `--sample-count` | Number of messages to sample | `10` |

## Security Rules Reference

The security analysis engine evaluates your Kafka cluster against the following rules:

### Authentication

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| AUTH001 | No Authentication Configured | CRITICAL | Detects when no authentication mechanism is configured |
| AUTH002 | Plaintext Listener Detected | CRITICAL | Identifies listeners using PLAINTEXT protocol |
| AUTH003 | Weak SASL Mechanism | HIGH | Flags weak SASL mechanisms like PLAIN without SSL |

### Authorization

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| AUTHZ001 | No Authorizer Configured | CRITICAL | Detects missing authorizer configuration |
| AUTHZ002 | Allow Everyone Permission | CRITICAL | Identifies overly permissive allow-everyone settings |
| AUTHZ003 | Superusers Exposed | MEDIUM | Flags exposed superuser configurations |

### Encryption

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| ENC001 | No Inter-Broker Encryption | CRITICAL | Detects unencrypted inter-broker communication |
| ENC002 | Weak SSL Protocol | HIGH | Identifies deprecated or weak SSL/TLS protocols |
| ENC003 | No SSL Client Authentication | MEDIUM | Flags missing SSL client authentication |
| ENC004 | No Endpoint Identification | MEDIUM | Detects disabled SSL endpoint identification |

### Access Control (ACLs)

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| ACL001 | Wildcard Principal in ACL | CRITICAL | Identifies ACLs with wildcard (*) principals |
| ACL002 | Wildcard Host in ACL | MEDIUM | Flags ACLs allowing access from any host |
| ACL003 | Overly Permissive ACL | HIGH | Detects ACLs granting excessive permissions |
| ACL004 | Cluster-Wide ACL | MEDIUM | Identifies ACLs applied to entire cluster |
| ACL005 | Wildcard Resource in ACL | HIGH | Flags ACLs with wildcard resource patterns |

### Configuration

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| TOPIC001 | Auto Topic Creation Enabled | HIGH | Detects automatic topic creation being enabled |
| TOPIC002 | Unclean Leader Election | HIGH | Identifies unclean leader election configuration |
| TOPIC003 | Low Min ISR | HIGH | Flags topics with insufficient minimum in-sync replicas |
| TOPIC004 | Short Retention Period | MEDIUM | Detects unusually short message retention periods |
| TOPIC005 | Delete Topic Enabled | MEDIUM | Identifies when topic deletion is enabled |

### Security Score

The analysis produces a security score from 0-100 and a letter grade:

| Grade | Score Range | Description |
|-------|-------------|-------------|
| A | 90-100 | Excellent security posture |
| B | 80-89 | Good security with minor improvements needed |
| C | 70-79 | Moderate security, several improvements recommended |
| D | 60-69 | Poor security, significant changes required |
| F | 0-59 | Critical security issues requiring immediate attention |

## Contributing

For bug reports & feature requests, please use the [issue tracker](https://github.com/RoseSecurity/kcatcher/issues).

PRs are welcome! We follow the typical "fork-and-pull" Git workflow.
 1. **Fork** the repo on GitHub
 2. **Clone** the project to your own machine
 3. **Commit** changes to your own branch
 4. **Push** your work back up to your fork
 5. Submit a **Pull Request** so that we can review your changes

> [!TIP]
> Be sure to merge the latest changes from "upstream" before making a pull request!

### Many Thanks to Our Contributors

<a href="https://github.com/RoseSecurity/kcatcher/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=RoseSecurity/kcatcher&max=24" />
</a>
