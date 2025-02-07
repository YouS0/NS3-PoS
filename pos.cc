#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/ipv4-global-routing-helper.h"
#include "ns3/flow-monitor-helper.h"
#include "ns3/flow-monitor.h"
#include "ns3/ipv4-flow-classifier.h"
#include <vector>
#include <fstream>
#include <sstream>
#include <map>
#include <random>
#include <iomanip>
#include <iostream>
#include <sys/resource.h>
#include "ns3/flow-monitor-helper.h"


// Define a logging component for the Proof of Stake Simulation
NS_LOG_COMPONENT_DEFINE("ProofOfStakeSimulation");

using namespace ns3;
using namespace std;

// Maps to store round start times and validator nodes
std::map<uint32_t, double> roundStartTimes;  // Maps round number to start time
std::map<uint32_t, uint32_t> validators;     // Maps round number to validator node ID

// Variables to track total data transmitted and total transactions
uint64_t totalDataTransmitted = 0;  
uint32_t totaltransactions = 0;  

// Structure to store a node's stake information
struct NodeStake {
    uint32_t nodeId;  // Node ID
    uint32_t stake;   // Stake amount
};

// Structure to represent a transaction
struct Transaction {
    string transactionId;  // Unique transaction ID
    uint32_t sender;       // Sender node ID
    uint32_t receiver;     // Receiver node ID
    double amount;         // Transaction amount
    string timestamp;      // Timestamp of transaction
    string signature;      // Digital signature for security
    uint32_t blockId;      // Block ID where the transaction is recorded
};

// Function to print CPU usage statistics
void PrintCPUUsage() {
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
    std::cout << "======================== CPU USAGE ============================" << std::endl;
    std::cout << "User CPU time: " << usage.ru_utime.tv_sec + usage.ru_utime.tv_usec / 1e6 << " sec" << std::endl;
    std::cout << "System CPU time: " << usage.ru_stime.tv_sec + usage.ru_stime.tv_usec / 1e6 << " sec" << std::endl;
}

// Function to print memory usage statistics
void PrintMemoryUsage() {
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
    std::cout << "======================== MEMORY USAGE ============================" << std::endl;
    std::cout << "Memory usage: " << usage.ru_maxrss << " KB" << std::endl;
}

// Function to load node stakes from a CSV file
map<uint32_t, vector<NodeStake>> LoadNodeStakes(const string &fileName) {
    map<uint32_t, vector<NodeStake>> roundStakes;  // Stores stakes by round number
    ifstream file(fileName);
    string line;
    
    getline(file, line); // Skip the header line

    while (getline(file, line)) {
        istringstream ss(line);
        string temp;
        NodeStake ns;
        uint32_t round;

        // Read round number
        getline(ss, temp, ',');
        round = stoi(temp);

        // Read node ID, adjusting for formatting and zero-based indexing
        getline(ss, temp, ',');
        ns.nodeId = stoi(temp.substr(temp.find('-') + 1)) - 1;

        // Read stake value
        getline(ss, temp, ',');
        ns.stake = stoi(temp);

        // Store the node stake in the corresponding round
        roundStakes[round].push_back(ns);
    }
    return roundStakes;
}

// Function to load transactions from a CSV file
vector<Transaction> LoadTransactions(const string &fileName) {
    vector<Transaction> transactions;  // Stores the list of transactions
    ifstream file(fileName);
    string line;
    
    getline(file, line); // Skip the header line

    while (getline(file, line)) {
        istringstream ss(line);
        string temp;
        Transaction tx;

        // Read transaction ID
        getline(ss, tx.transactionId, ',');

        // Read sender ID, adjusting for formatting
        getline(ss, temp, ',');
        tx.sender = stoi(temp.substr(temp.find('-') + 1)) - 1;

        // Read receiver ID, adjusting for formatting
        getline(ss, temp, ',');
        tx.receiver = stoi(temp.substr(temp.find('-') + 1)) - 1;

        // Read transaction amount
        getline(ss, temp, ',');
        tx.amount = stod(temp);

        // Read timestamp
        getline(ss, tx.timestamp, ',');

        // Read digital signature
        getline(ss, tx.signature, ',');

        // Read block ID
        getline(ss, temp, ',');
        tx.blockId = stoi(temp);

        // Add transaction to the list
        transactions.push_back(tx);

        // Log transaction details
        NS_LOG_INFO("Loaded TX: " << tx.transactionId 
                    << " From: Node" << tx.sender 
                    << " To: Node" << tx.receiver 
                    << " Amount: " << tx.amount);
    }
    return transactions;
}


// Function to pad a string with spaces up to a given size
std::string PadData(const std::string& data, size_t size) {
    if (data.size() + 1 >= size) { // +1 for the comma
        return data.substr(0, size - 1) + ","; // Truncate and append a comma if necessary
    }
    std::ostringstream paddedData;
    paddedData << data << ',' 
               << std::setw(size - data.size() - 1) 
               << std::setfill(' ') << ' '; // Pad with spaces after the comma
    return paddedData.str();
}

// Function to select a validator based on stake weight
uint32_t SelectValidator(const vector<NodeStake> &stakes) {
    NS_LOG_INFO("Selecting validator from " << stakes.size() << " candidates");

    random_device rd;    // Random device for seeding
    mt19937 gen(rd());   // Mersenne Twister pseudo-random generator

    vector<double> probabilities; // Stores probability for each candidate
    uint32_t totalStake = 0;

    // Calculate total stake
    for (const auto &stake : stakes) 
        totalStake += stake.stake;

    // Calculate probability of selection based on stake proportion
    for (const auto &stake : stakes) 
        probabilities.push_back(static_cast<double>(stake.stake) / totalStake);

    // Create a discrete probability distribution based on stakes
    discrete_distribution<> dist(probabilities.begin(), probabilities.end());

    // Select a validator using the probability distribution
    uint32_t selected = stakes[dist(gen)].nodeId;
    
    NS_LOG_INFO("Selected validator: Node" << selected);
    return selected;
}

// Class to track block propagation across nodes
class BlockTracker : public Object {
public:
    static TypeId GetTypeId() { // Define TypeId for the BlockTracker class
        static TypeId tid = TypeId("BlockTracker")
            .SetParent<Object>()
            .AddConstructor<BlockTracker>();
        return tid;
    }

    void Init(uint32_t totalNodes) { // Initialize total nodes participating in tracking
        m_totalNodes = totalNodes;
    }

    void ReportBlockReceived(uint32_t round, uint32_t nodeId) { // Report that a node received a block for a specific round
        NS_LOG_INFO("Node " << nodeId << " reported block received for round " << round);
        m_receivedNodes[round].insert(nodeId); // Add the node to the list of those that received the block

        if (AllNodesReceived(round)) { // Check if all nodes received the block
            NS_LOG_INFO("All nodes received block for round " << round);
            if (m_completeCallback.find(round) != m_completeCallback.end()) { // If a completion callback is set
                NS_LOG_INFO("Triggering completion callback for round " << round);
                m_completeCallback[round](); // Execute the callback
            }
        } else {
            NS_LOG_INFO("Nodes received so far for round " << round << ": " 
                        << m_receivedNodes[round].size());
        }
    }

    bool AllNodesReceived(uint32_t round) { // Check if all nodes have received the block for a given round
        return m_receivedNodes[round].size() == m_totalNodes;
    }

    void SetCompletionCallback(uint32_t round, std::function<void()> callback) { // Set a callback function for when all nodes receive the block
        m_completeCallback[round] = callback;
    }

private:
    uint32_t m_totalNodes; // Total number of nodes in the network
    std::map<uint32_t, std::set<uint32_t>> m_receivedNodes; // Map to track which nodes received a block for each round
    std::map<uint32_t, std::function<void()>> m_completeCallback; // Map to store completion callbacks for rounds
};

// Custom server application class that handles transactions and broadcasts blocks
class CustomServerApp : public Application {
public:
    CustomServerApp(uint16_t port) : m_port(port) {} // Constructor that sets the listening port
    vector<Transaction> transactionsBuffer; // Buffer to store transactions before broadcasting a block

    void BroadcastBlock() { // Function to broadcast a block to all nodes
        NS_LOG_INFO("Node" << GetNode()->GetId() << " broadcasting block with " 
                    << transactionsBuffer.size() << " transactions" << "Round" << m_currentRound);

        // Prepare block data with round number and pad to 512 bytes
        ostringstream blockStream;
        blockStream << "Round" << m_currentRound << ": Block with " 
                    << transactionsBuffer.size() << " transactions";
        string blockData = PadData(blockStream.str(), 512); // Ensure block size is 512 bytes

        Ptr<Packet> blockPacket = Create<Packet>((uint8_t*)blockData.c_str(), blockData.size()); // Create a packet containing block data

        // Send block to all other nodes in the network
        for (uint32_t i = 0; i < m_nodes.GetN(); ++i) {
            if (m_nodes.Get(i) == GetNode()) continue; // Skip self

            Ptr<Socket> socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId()); // Create UDP socket
            InetSocketAddress remote = InetSocketAddress(
                m_nodes.Get(i)->GetObject<Ipv4>()->GetAddress(1,0).GetLocal(), 
                m_blockPort
            ); // Get the recipient node's IP address and block port
            socket->Connect(remote); // Establish connection
            socket->Send(blockPacket->Copy()); // Send block data packet

            NS_LOG_INFO("Block sent to Node" << m_nodes.Get(i)->GetId());
        }
        m_blockTracker->ReportBlockReceived(m_currentRound, GetNode()->GetId()); // Report that the block has been broadcasted

        // Track total data transmitted: (nodes - 1) * 512 bytes per block
        totalDataTransmitted += (m_nodes.GetN() - 1) * 512;
        transactionsBuffer.clear(); // Clear transaction buffer after broadcasting
        NS_LOG_INFO("Block broadcast completed.");
    }

    void SetCurrentRound(uint32_t round) { m_currentRound = round; } // Set the current round number
    void SetNodes(NodeContainer nodes) { m_nodes = nodes; } // Set the node container
    void SetBlockPort(uint16_t port) { m_blockPort = port; } // Set the port for block communication
    void SetBlockTracker(Ptr<BlockTracker> tracker) { m_blockTracker = tracker; } // Set the block tracker instance

private:
    uint32_t m_currentRound; // Stores the current round number
    uint16_t m_port; // Port used for communication
    Ptr<BlockTracker> m_blockTracker; // Pointer to block tracker instance
    uint16_t m_blockPort; // Port used for block broadcasting
    NodeContainer m_nodes; // Container for all network nodes
    Ptr<Socket> m_socket; // Socket for network communication
    
    void StartApplication() override { // Function called when the application starts
        m_socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId()); // Create UDP socket
        m_socket->Bind(InetSocketAddress(Ipv4Address::GetAny(), m_port)); // Bind socket to the listening port
        m_socket->SetRecvCallback(MakeCallback(&CustomServerApp::HandleRead, this)); // Set callback for receiving messages
    }

    void StopApplication() override { // Function called when the application stops
        if (m_socket) {
            m_socket->Close(); // Close socket
            m_socket = nullptr;
        }
        m_currentRound = 0; // Reset round number
    }

    void HandleRead(Ptr<Socket> socket) { // Function to process incoming packets
        Ptr<Packet> packet;
        Address from;
        while ((packet = socket->RecvFrom(from))) { // Receive packet from sender
            uint8_t *buffer = new uint8_t[packet->GetSize() + 1]; // Allocate buffer for packet data
            packet->CopyData(buffer, packet->GetSize()); // Copy packet data into buffer
            buffer[packet->GetSize()] = '\0'; // Null-terminate the buffer
            string data((char*)buffer); // Convert buffer to string

            Transaction tx;
            istringstream ss(data);
            string temp;

            try {
                // Parse transaction fields from received data
                getline(ss, tx.transactionId, ',');
                if (!getline(ss, temp, ',')) throw std::invalid_argument("Invalid sender");
                tx.sender = stoi(temp);

                if (!getline(ss, temp, ',')) throw std::invalid_argument("Invalid receiver");
                tx.receiver = stoi(temp);

                if (!getline(ss, temp, ',')) throw std::invalid_argument("Invalid amount");
                tx.amount = stod(temp);

                if (!getline(ss, tx.timestamp, ',')) throw std::invalid_argument("Invalid timestamp");
                if (!getline(ss, tx.signature, ',')) throw std::invalid_argument("Invalid signature");

                if (!getline(ss, temp, ',')) throw std::invalid_argument("Invalid blockId");
                tx.blockId = stoi(temp);

                NS_LOG_INFO("Received TX " << tx.transactionId << " From: Node" << tx.sender 
                            << " To: Node" << tx.receiver << " Amount: " << tx.amount);

                transactionsBuffer.push_back(tx); // Add transaction to buffer

                // Check if the buffer has reached 20 transactions, then broadcast a block
                if (transactionsBuffer.size() >= 20) {
                    BroadcastBlock();
                }
            } catch (const exception& e) { // Handle errors in transaction parsing
                NS_LOG_ERROR("Error processing received packet: " << e.what() << " Data: " << data);
            }
            delete[] buffer; // Free allocated buffer memory
        }
    }   
};

// Custom client application that sends transactions to a remote server
class CustomClientApp : public Application {
public:
    // Constructor to initialize the client with destination address, port, and transaction data
    CustomClientApp(Ipv4Address address, uint16_t port, string data) 
        : m_remoteAddress(address), m_remotePort(port), m_data(data) {}

private:
    Ipv4Address m_remoteAddress; // Destination IP address
    uint16_t m_remotePort;       // Destination port
    string m_data;               // Transaction data to be sent
    Ptr<Socket> m_socket;        // UDP socket for sending data

    // Function called when the application starts
    void StartApplication() override {
        NS_LOG_INFO("Node" << GetNode()->GetId() << " starting transaction to " 
                    << m_remoteAddress << ":" << m_remotePort);
        
        // Create a UDP socket and connect to the remote address
        m_socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
        m_socket->Connect(InetSocketAddress(m_remoteAddress, m_remotePort));

        // Create a packet with the transaction data and send it
        Ptr<Packet> packet = Create<Packet>((uint8_t*)m_data.c_str(), m_data.size());
        m_socket->Send(packet);
        
        NS_LOG_INFO("Transaction sent from Node" << GetNode()->GetId() 
                    << " to Node" << m_remoteAddress);
    }
};

// Block receiver application that listens for incoming blocks
class BlockReceiverApp : public Application {
public:
    // Constructor to initialize with a port and a block tracker object
    BlockReceiverApp(uint16_t port, Ptr<BlockTracker> tracker) 
        : m_port(port), m_tracker(tracker) {}

    // Setter function to set the current round of block processing
    void SetCurrentRound(uint32_t round) {
        m_currentRound = round;
    }

    // Setter function to set the expected validator for the current round
    void SetExpectedValidator(uint32_t validatorId) {
        m_expectedValidator = validatorId;
    }

    void SetBlockTracker(Ptr<BlockTracker> tracker) {
        m_tracker = tracker;
    }

    void SetNodes(NodeContainer nodes) { m_nodes = nodes; }
private:
    uint16_t m_port;             // Port to listen for blocks
    NodeContainer m_nodes;
    Ptr<BlockTracker> m_tracker; // Tracker to monitor received blocks
    uint32_t m_currentRound;     // The current round being processed
    uint32_t m_expectedValidator; // The expected validator for the current round
    Ptr<Socket> m_socket;        // UDP socket for receiving blocks

    // Function called when the application starts
    void StartApplication() override {
        // Create a UDP socket and bind it to the specified port
        m_socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
        m_socket->Bind(InetSocketAddress(Ipv4Address::GetAny(), m_port));

        // Set a callback function to handle incoming block data
        m_socket->SetRecvCallback(MakeCallback(&BlockReceiverApp::HandleBlock, this));
    }

    // Function to handle received block packets
    void HandleBlock(Ptr<Socket> socket) {
        Ptr<Packet> packet;
        Address from;

        // Process each received packet
        while ((packet = socket->RecvFrom(from))) {
            uint8_t buffer[1024]; // Buffer to store packet data
            packet->CopyData(buffer, packet->GetSize());
            buffer[packet->GetSize()] = '\0'; // Null-terminate the string

            string data((char*)buffer); // Convert buffer to string
            NS_LOG_INFO("Node " << GetNode()->GetId() << " received: " << data);

            // Check if the sender is the expected validator
            InetSocketAddress address = InetSocketAddress::ConvertFrom(from);
            Ipv4Address senderAddress = address.GetIpv4();
            uint32_t senderNodeId = GetNodeIdFromAddress(senderAddress);

            if (senderNodeId != m_expectedValidator) {
                NS_LOG_WARN("Node " << GetNode()->GetId() << " received block from unexpected validator: Node" << senderNodeId);
                continue; // Ignore the block if the sender is not the expected validator
            }

            try {
                // Extract the round number from the block data
                uint32_t round = stoi(data.substr(5, data.find(':') - 5));
                NS_LOG_INFO("Node " << GetNode()->GetId() << " parsed round " << round);

                // Report block reception to the block tracker
                m_tracker->ReportBlockReceived(round, GetNode()->GetId());
            } catch (const std::exception &e) {
                // Log an error if parsing fails
                NS_LOG_ERROR("Error parsing block data: " << e.what());
            }
        }
    }

    // Helper function to get the node ID from an IP address
    uint32_t GetNodeIdFromAddress(Ipv4Address address) {
        for (uint32_t i = 0; i < m_nodes.GetN(); ++i) {
            Ptr<Node> node = m_nodes.Get(i);
            Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();
            if (!ipv4) continue;

            // Check all interfaces
            for (uint32_t interface = 0; interface < ipv4->GetNInterfaces(); ++interface) {
                // Check all addresses on the interface
                for (uint32_t addrIdx = 0; addrIdx < ipv4->GetNAddresses(interface); ++addrIdx) {
                    Ipv4InterfaceAddress addr = ipv4->GetAddress(interface, addrIdx);
                    if (addr.GetLocal() == address) {
                        return node->GetId();
                    }
                }
            }
        }
        NS_LOG_WARN("Address " << address << " not found in any node");
        return -1; // Indicate not found
    }   
   

};


// Function to create a formatted transaction string for transmission
std::string CreateTxString(const Transaction& tx) {
    std::ostringstream txStream;

    // Format transaction details as a comma-separated string
    txStream << tx.transactionId << "," 
             << tx.sender << "," 
             << tx.receiver << "," 
             << tx.amount << "," 
             << tx.timestamp << "," 
             << tx.signature << "," 
             << tx.blockId;

    // Pad the transaction string to a fixed size (512 bytes)
    return PadData(txStream.str(), 512);
}


int main(int argc, char* argv[]) {
    // Enable logging for debugging
    LogComponentEnable("ProofOfStakeSimulation", LOG_LEVEL_ALL);

    // Define network and simulation parameters
    uint32_t numNodes = 25;
    uint16_t transactionPort = 9;
    uint16_t blockPort = 10;
    uint32_t numRounds = 8;
    uint32_t transactionsPerRound = 20;

    // Initialize block tracker for blockchain operations
    Ptr<BlockTracker> blockTracker = CreateObject<BlockTracker>();
    blockTracker->Init(numNodes);

    // Create network nodes and install the internet stack
    NodeContainer nodes;
    nodes.Create(numNodes);
    InternetStackHelper internet;
    internet.Install(nodes);

    // Define node groups (5 groups of 5 nodes each)
    vector<vector<uint32_t>> groups = {
        {0,1,2,3,4}, {5,6,7,8,9}, {10,11,12,13,14},
        {15,16,17,18,19}, {20,21,22,23,24}
    };

    // Define backbone nodes for inter-group communication
    vector<uint32_t> backboneNodes = {1,6,11,16,21};

    // Configure intra-group network connections (10Mbps, 2ms latency)
    PointToPointHelper intraGroupHelper;
    intraGroupHelper.SetDeviceAttribute("DataRate", StringValue("10Mbps"));
    intraGroupHelper.SetChannelAttribute("Delay", StringValue("2ms"));

    // Create intra-group links where each node connects to its backbone node
    for (uint32_t groupIdx = 0; groupIdx < 5; ++groupIdx) {
        Ipv4AddressHelper address;
        address.SetBase(("10." + to_string(100 + groupIdx) + ".0.0").c_str(), "255.255.255.252");

        for (auto nodeId : groups[groupIdx]) {
            if (nodeId != backboneNodes[groupIdx]) {
                NetDeviceContainer devices = intraGroupHelper.Install(
                    nodes.Get(nodeId), 
                    nodes.Get(backboneNodes[groupIdx])
                );
                address.Assign(devices);
                address.NewNetwork(); // Assign a new subnet for each connection
            }
        }
    }

    // Configure backbone connections (100Mbps, 5ms latency)
    PointToPointHelper backboneHelper;
    backboneHelper.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
    backboneHelper.SetChannelAttribute("Delay", StringValue("5ms"));
    
    // Assign IP addresses for backbone communication
    Ipv4AddressHelper backboneAddress("10.200.0.0", "255.255.255.252");

    // Connect backbone nodes in a circular topology
    for (size_t i = 0; i < backboneNodes.size(); ++i) {
        uint32_t current = backboneNodes[i];
        uint32_t next = backboneNodes[(i+1) % backboneNodes.size()]; // Circular connection

        NetDeviceContainer devices = backboneHelper.Install(
            nodes.Get(current), 
            nodes.Get(next)
        );
        backboneAddress.Assign(devices);
        backboneAddress.NewNetwork();
    }

    // Enable global routing to allow inter-node communication
    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    // Install block receiving applications on all nodes
    for (uint32_t i = 0; i < nodes.GetN(); ++i) {
        Ptr<BlockReceiverApp> blockReceiver = CreateObject<BlockReceiverApp>(blockPort, blockTracker);
        nodes.Get(i)->AddApplication(blockReceiver);
        blockReceiver->SetStartTime(Simulator::Now()); // Start immediately
    }
    
    // Load stake information and transaction data from external CSV files
    auto roundStakes = LoadNodeStakes("Node_Status_Dataset.csv");
    auto transactions = LoadTransactions("Transactions_Dataset.csv");

    // Define function to start each simulation round
    std::function<void(uint32_t)> startRound = [&](uint32_t round) {
        if (round > numRounds) return; // Stop if the round exceeds the total number of rounds

        NS_LOG_INFO("\n=== STARTING ROUND " << round << " ==="); // Log the start of a round
        double startTime = Simulator::Now().GetSeconds(); // Get the current simulation time
        NS_LOG_INFO("Round " << round << " start time: " << startTime); // Log start time
        roundStartTimes[round] = startTime; // Store the start time of the round

        auto stakes = roundStakes[round]; // Get stakes for the round
        uint32_t validatorId = SelectValidator(stakes); // Select validator based on stakes
        validators[round] = validatorId; // Store selected validator

        Ptr<CustomServerApp> serverApp; // Pointer to server application
        bool appInstalled = false; // Flag to check if app is already installed
        for (uint32_t i = 0; i < nodes.Get(validatorId)->GetNApplications(); ++i) {
            serverApp = DynamicCast<CustomServerApp>(nodes.Get(validatorId)->GetApplication(i)); // Try to find an existing server app
            if (serverApp) {
                appInstalled = true; // Set flag if found
                break; // Exit loop
            }
        }

        if (!appInstalled) { // If server app is not installed, create and install it
            serverApp = CreateObject<CustomServerApp>(transactionPort); // Create server app
            serverApp->SetBlockTracker(blockTracker); // Set block tracker
            serverApp->SetNodes(nodes); // Assign nodes
            serverApp->SetBlockPort(blockPort); // Set block port
            nodes.Get(validatorId)->AddApplication(serverApp); // Add app to node
            serverApp->SetStartTime(Simulator::Now()); // Set start time for the app
        }
        serverApp->SetCurrentRound(round); // Set the current round for the server app

        // Configure block receiver apps on all nodes
        for (uint32_t i = 0; i < nodes.GetN(); ++i) {
            for (uint32_t j = 0; j < nodes.Get(i)->GetNApplications(); ++j) {
                Ptr<BlockReceiverApp> blockReceiver = DynamicCast<BlockReceiverApp>(nodes.Get(i)->GetApplication(j)); // Find block receiver app
                if (blockReceiver) {
                    blockReceiver->SetCurrentRound(round); // Set current round
                    blockReceiver->SetNodes(nodes); // Assign nodes
                    blockReceiver->SetExpectedValidator(validatorId); // Set expected validator
                    blockReceiver->SetBlockTracker(blockTracker); // Set block tracker
                }
            }
        }

        // Process transactions for the round
        for (uint32_t i = 0; i < transactionsPerRound; ++i) {
            uint32_t txIndex = (round - 1) * transactionsPerRound + i; // Calculate transaction index
            if (txIndex >= transactions.size()) break; // Stop if no more transactions

            Transaction tx = transactions[txIndex]; // Get transaction
            Ptr<Node> sender = nodes.Get(tx.sender); // Get sender node

            Ipv4Address validatorAddress = nodes.Get(validatorId)
                                                ->GetObject<Ipv4>()
                                                ->GetAddress(1,0)
                                                .GetLocal(); // Get validator's IP address

            // Create and install client app to send transaction
            Ptr<CustomClientApp> clientApp = CreateObject<CustomClientApp>(
                validatorAddress, 
                transactionPort, 
                CreateTxString(tx)
            );
            sender->AddApplication(clientApp); // Add client app to sender node
            clientApp->SetStartTime(Simulator::Now()); // Set client app start time

            totalDataTransmitted += 512; // Update total data transmitted
            totaltransactions += 1; // Increment total transactions count
        }

        // Set callback for when all nodes confirm the round
        blockTracker->SetCompletionCallback(round, [=]() {
            double finishTime = Simulator::Now().GetSeconds(); // Get finish time
            NS_LOG_INFO("All nodes confirmed round " << round); // Log confirmation
            NS_LOG_INFO("Round " << round << " finish time: " << finishTime); // Log finish time

            double duration = finishTime - roundStartTimes[round]; // Calculate round duration
            NS_LOG_INFO("Round " << round << " duration: " << duration << " seconds"); // Log duration

            if (round < numRounds) { // Schedule next round if not the last round
                Simulator::Schedule(MilliSeconds(10), [=]() {
                    startRound(round + 1); // Start next round after 10ms
                });
            } else { // If last round, display statistics
                std::cout << "Validators for the last 8 rounds:" << std::endl;
                for (size_t i = validators.size() > 8 ? validators.size() - 8 : 0; i < validators.size() - 1; ++i) {
                    std::cout << "Round " << (i + 1) << ": Validator " << validators[i+1] << std::endl; // Print last 8 validators
                }

                double totalTime = finishTime - roundStartTimes[1]; // Calculate total time
                double throughput = (totalDataTransmitted * 8) / totalTime; // Compute raw data throughput
                std::cout << "Total Data Transmitted: " << totalDataTransmitted << " bytes" << std::endl;
                std::cout << "Total Time: " << totalTime << " seconds" << std::endl;
                std::cout << "Raw Data Throughput: " << throughput << " bps" << std::endl;

                double transaction_throughput = totaltransactions / totalTime; // Compute transaction throughput
                std::cout << "Total Transactions Processed: " << totaltransactions << std::endl;
                std::cout << "Total Time: " << totalTime << " seconds" << std::endl;
                std::cout << "Transaction Throughput: " << transaction_throughput << " tps" << std::endl;

                PrintCPUUsage(); // Print CPU usage statistics
                PrintMemoryUsage(); // Print memory usage statistics
            }
        });
    };

        
    // Start the first round of the Proof-of-Stake simulation
    startRound(1);

    // Run the simulation
    Simulator::Run();
    Simulator::Destroy();
    return 0;
}
