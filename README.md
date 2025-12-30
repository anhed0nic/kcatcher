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

### Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-b, --brokers` | List of Kafka brokers to enumerate (required) | - |
| `-p, --port` | Kafka broker port | `9092` |
| `-t, --timeout` | Connection timeout duration | `10s` |
| `-o, --output` | Output format (`text` or `json`) | `text` |
| `--acls` | Enable ACL enumeration | `false` |
| `--sample-topic` | Topic to sample messages from | - |
| `--sample-count` | Number of messages to sample | `10` |

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
