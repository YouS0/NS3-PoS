# Proof-of-Stake (PoS) Blockchain Simulation using ns-3

A discrete-event network simulation implementing a Proof-of-Stake consensus mechanism with validator selection, transaction propagation, and block validation visualization.

## Key Features

- **Validator Selection**: Weighted random selection based on node stakes
- **Transaction Processing**: Batched transactions (20 per block)
- **Network Topology**:
  - 25 nodes divided into 5 groups
  - Backbone nodes with high-speed connections
- **Visualization**: Real-time NetAnim visualization showing:
  - Validator nodes (red)
  - Transaction initiations (green flashes)
  - Block receptions (blue flashes)
- **Performance Metrics**:
  - Data throughput calculation
  - Transaction processing rate
  - CPU/Memory usage tracking

## Prerequisites

- [ns-3.43](https://www.nsnam.org/releases/ns-3-43/)
- NetAnim (built with ns-3)
- CSV datasets:
  - `Node_Status_Dataset.csv`
  - `Transactions_Dataset.csv`

## Installation

1. Clone repository:
   ```bash
   git clone https://github.com/yourusername/pos-ns3-simulation.git

2. Place CSV files in project root:
- pos-ns3-simulation/
  
   **├── Node_Status_Dataset.csv**
  
   **└── Transactions_Dataset.csv**
  3. Compile With NS3
```bash
  cd ns-allinone-3.43/ns-3.43
  ./ns3 configure --enable-examples --enable-modules=netanim
  ./ns3 build
```
## Usage
  Run simulation:
  ```bash
./ns3 run pos
```

## Simulation Parameters (modify in code):
```c
// Main simulation parameters
uint32_t numNodes = 25;            // Total nodes
uint32_t numRounds = 8;            // Consensus rounds
uint32_t transactionsPerRound = 20; // Transactions per block
```
