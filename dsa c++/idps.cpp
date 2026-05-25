#include <iostream>
#include <vector>
#include <map>
#include <queue>
#include <string>
#include <cmath>
#include <algorithm>
#include <iomanip>
#include <ctime>
#include <thread>
#include <mutex>
#include <chrono>
#include <atomic>

using namespace std;

// ==================== Configuration Constants ====================
const int QUEUE_MAXSIZE = 20000;
const int BATCH_SIZE = 32;
const double PREDICT_INTERVAL = 1.0;
const double FLOW_IDLE_TIMEOUT = 4.0;
const double ACTIVE_TIMEOUT = 1.0;
const double AUTO_BLOCK_THRESHOLD = 0.8;
const bool DROP_OLDEST_ON_FULL = true;

// Global control
atomic<bool> stop_flag(false);
mutex flows_lock;

// ==================== Statistics Helper ====================
struct Stats {
    double mean, std_dev, min_val, max_val;
};

Stats safe_stats(vector<double>& arr) {
    Stats s = {0, 0, 0, 0};
    if (arr.empty()) return s;

    double sum = 0;
    s.min_val = arr[0];
    s.max_val = arr[0];

    for (double val : arr) {
        sum += val;
        if (val < s.min_val) s.min_val = val;
        if (val > s.max_val) s.max_val = val;
    }

    s.mean = sum / arr.size();

    double var_sum = 0;
    for (double val : arr) {
        var_sum += (val - s.mean) * (val - s.mean);
    }
    s.std_dev = sqrt(var_sum / arr.size());

    return s;
}

// ==================== Packet Structure ====================
struct Packet {
    double timestamp;
    int length;
    string src_ip;
    string dst_ip;
    string protocol;
    int src_port;
    int dst_port;
    int ip_hdr_len;
    int tcp_hdr_len;
    string tcp_flags;
    int tcp_window;
    int tcp_seg_len;
};

// ==================== Flow Key ====================
struct FlowKey {
    string ip1, ip2;
    int port1, port2;
    string protocol;

    bool operator<(const FlowKey& other) const {
        if (ip1 != other.ip1) return ip1 < other.ip1;
        if (ip2 != other.ip2) return ip2 < other.ip2;
        if (port1 != other.port1) return port1 < other.port1;
        if (port2 != other.port2) return port2 < other.port2;
        return protocol < other.protocol;
    }

    string to_string() const {
        return "(" + ip1 + ":" + std::to_string(port1) + " <-> " +
               ip2 + ":" + std::to_string(port2) + " " + protocol + ")";
    }
};

FlowKey get_flow_key(Packet& p) {
    FlowKey key;
    key.protocol = p.protocol;

    // Canonical ordering (sorted) for bidirectional flow
    pair<string, int> a = {p.src_ip, p.src_port};
    pair<string, int> b = {p.dst_ip, p.dst_port};

    if (a < b) {
        key.ip1 = p.src_ip;
        key.port1 = p.src_port;
        key.ip2 = p.dst_ip;
        key.port2 = p.dst_port;
    } else {
        key.ip1 = p.dst_ip;
        key.port1 = p.dst_port;
        key.ip2 = p.src_ip;
        key.port2 = p.src_port;
    }

    return key;
}

// ==================== Flow Data ====================
struct FlowData {
    double start_time, end_time;
    int total_fwd_packets, total_bwd_packets;
    int total_fwd_bytes, total_bwd_bytes;

    vector<double> fwd_packet_lengths;
    vector<double> bwd_packet_lengths;
    vector<double> fwd_header_lengths;
    vector<double> bwd_header_lengths;
    vector<double> packet_times;
    vector<double> flow_iat;
    vector<double> fwd_iat;
    vector<double> bwd_iat;

    double last_fwd_time, last_bwd_time;
    double last_packet_time;
    vector<double> active_times;
    vector<double> idle_times;
    double current_active_start;

    int fin_flags_fwd, fin_flags_bwd;
    int syn_flags_fwd, syn_flags_bwd;
    int rst_flags_fwd, rst_flags_bwd;
    int psh_flags_fwd, psh_flags_bwd;
    int ack_flags_fwd, ack_flags_bwd;
    int urg_flags_fwd, urg_flags_bwd;

    int min_packet_len, max_packet_len;
    int act_data_pkt_fwd;

    string src_ip, dst_ip;
    int src_port, dst_port;
    string protocol;

    FlowData() {
        start_time = end_time = 0;
        total_fwd_packets = total_bwd_packets = 0;
        total_fwd_bytes = total_bwd_bytes = 0;
        last_fwd_time = last_bwd_time = -1;
        last_packet_time = -1;
        current_active_start = -1;
        fin_flags_fwd = fin_flags_bwd = 0;
        syn_flags_fwd = syn_flags_bwd = 0;
        rst_flags_fwd = rst_flags_bwd = 0;
        psh_flags_fwd = psh_flags_bwd = 0;
        ack_flags_fwd = ack_flags_bwd = 0;
        urg_flags_fwd = urg_flags_bwd = 0;
        min_packet_len = max_packet_len = -1;
        act_data_pkt_fwd = 0;
        src_port = dst_port = -1;
    }
};

// ==================== Node for Doubly Linked List (DSA) ====================
struct Node {
    FlowKey key;
    FlowData flow;
    double timestamp;
    Node* prev;
    Node* next;

    Node(FlowKey k, FlowData f) : key(k), flow(f), prev(nullptr), next(nullptr) {
        timestamp = chrono::duration<double>(chrono::system_clock::now().time_since_epoch()).count();
    }
};

// ==================== Doubly Linked Flow List (DSA) ====================
class DoublyLinkedFlowList {
public:
    Node* head;
    Node* tail;
    int size;

    DoublyLinkedFlowList() : head(nullptr), tail(nullptr), size(0) {}

    Node* append(FlowKey key, FlowData flow) {
        Node* node = new Node(key, flow);
        if (!tail) {
            head = tail = node;
        } else {
            tail->next = node;
            node->prev = tail;
            tail = node;
        }
        size++;
        return node;
    }

    void move_to_tail(Node* node) {
        if (node == tail) return;

        // Unlink from current position
        if (node->prev) node->prev->next = node->next;
        if (node->next) node->next->prev = node->prev;
        if (node == head) head = node->next;

        // Reset if empty
        if (!head) tail = nullptr;

        // Append to tail
        if (tail) {
            tail->next = node;
            node->prev = tail;
            node->next = nullptr;
            tail = node;
        } else {
            head = tail = node;
            node->prev = node->next = nullptr;
        }
    }

    pair<FlowKey, FlowData> pop_oldest() {
        if (!head) return {{}, {}};

        Node* node = head;
        FlowKey k = node->key;
        FlowData f = node->flow;

        head = node->next;
        if (head) head->prev = nullptr;
        else tail = nullptr;

        size--;
        delete node;
        return {k, f};
    }

    ~DoublyLinkedFlowList() {
        while (head) {
            Node* temp = head;
            head = head->next;
            delete temp;
        }
    }
};

// ==================== Bounded Queue (DSA) ====================
template<typename T>
class BoundedQueue {
private:
    queue<T> q;
    int max_size;
    mutex mtx;

public:
    BoundedQueue(int max_sz) : max_size(max_sz) {}

    bool push(T item) {
        lock_guard<mutex> lock(mtx);
        if (q.size() >= max_size) {
            if (!DROP_OLDEST_ON_FULL) return false;
            q.pop();
        }
        q.push(item);
        return true;
    }

    bool pop(T& item) {
        lock_guard<mutex> lock(mtx);
        if (q.empty()) return false;
        item = q.front();
        q.pop();
        return true;
    }

    int get_size() {
        lock_guard<mutex> lock(mtx);
        return q.size();
    }

    bool empty() {
        lock_guard<mutex> lock(mtx);
        return q.empty();
    }
};

// ==================== Flow Manager (Hash Map + Doubly Linked List) ====================
class FlowManager {
public:
    DoublyLinkedFlowList flow_list;
    map<FlowKey, Node*> flow_nodes;

    void update_flow(Packet& p) {
        FlowKey key = get_flow_key(p);
        double ts = p.timestamp;
        int pkt_len = p.length;
        int payload_len = pkt_len - (p.ip_hdr_len + p.tcp_hdr_len);

        lock_guard<mutex> lock(flows_lock);

        Node* node = flow_nodes[key];

        if (node == nullptr) {
            // Create new flow
            FlowData flow;
            flow.start_time = ts;
            flow.end_time = ts;
            flow.src_ip = p.src_ip;
            flow.dst_ip = p.dst_ip;
            flow.src_port = p.src_port;
            flow.dst_port = p.dst_port;
            flow.protocol = p.protocol;

            node = flow_list.append(key, flow);
            flow_nodes[key] = node;
        } else {
            flow_list.move_to_tail(node);
        }

        FlowData& flow = node->flow;
        flow.end_time = ts;

        // Active/Idle time tracking
        if (flow.last_packet_time >= 0) {
            double gap = ts - flow.last_packet_time;
            if (gap > ACTIVE_TIMEOUT) {
                if (flow.current_active_start >= 0) {
                    double active_dur = flow.last_packet_time - flow.current_active_start;
                    if (active_dur > 0) flow.active_times.push_back(active_dur);
                }
                flow.idle_times.push_back(gap);
                flow.current_active_start = ts;
            }
        } else {
            flow.current_active_start = ts;
        }
        flow.last_packet_time = ts;

        // Packet length stats
        if (flow.min_packet_len < 0 || pkt_len < flow.min_packet_len) {
            flow.min_packet_len = pkt_len;
        }
        if (flow.max_packet_len < 0 || pkt_len > flow.max_packet_len) {
            flow.max_packet_len = pkt_len;
        }

        // Direction determination
        pair<string, int> canonical_a = {key.ip1, key.port1};
        pair<string, int> current = {p.src_ip, p.src_port};
        bool is_forward = (current == canonical_a);

        if (is_forward) {
            flow.total_fwd_packets++;
            flow.total_fwd_bytes += pkt_len;
            flow.fwd_packet_lengths.push_back(pkt_len);
            flow.fwd_header_lengths.push_back(p.ip_hdr_len + p.tcp_hdr_len);

            if (flow.last_fwd_time >= 0) {
                flow.fwd_iat.push_back(ts - flow.last_fwd_time);
            }
            flow.last_fwd_time = ts;

            if (payload_len > 0) flow.act_data_pkt_fwd++;

            // TCP flags
            if (p.protocol == "TCP") {
                if (p.tcp_flags.find('F') != string::npos) flow.fin_flags_fwd++;
                if (p.tcp_flags.find('S') != string::npos) flow.syn_flags_fwd++;
                if (p.tcp_flags.find('R') != string::npos) flow.rst_flags_fwd++;
                if (p.tcp_flags.find('P') != string::npos) flow.psh_flags_fwd++;
                if (p.tcp_flags.find('A') != string::npos) flow.ack_flags_fwd++;
                if (p.tcp_flags.find('U') != string::npos) flow.urg_flags_fwd++;
            }
        } else {
            flow.total_bwd_packets++;
            flow.total_bwd_bytes += pkt_len;
            flow.bwd_packet_lengths.push_back(pkt_len);
            flow.bwd_header_lengths.push_back(p.ip_hdr_len + p.tcp_hdr_len);

            if (flow.last_bwd_time >= 0) {
                flow.bwd_iat.push_back(ts - flow.last_bwd_time);
            }
            flow.last_bwd_time = ts;

            // TCP flags
            if (p.protocol == "TCP") {
                if (p.tcp_flags.find('F') != string::npos) flow.fin_flags_bwd++;
                if (p.tcp_flags.find('S') != string::npos) flow.syn_flags_bwd++;
                if (p.tcp_flags.find('R') != string::npos) flow.rst_flags_bwd++;
                if (p.tcp_flags.find('P') != string::npos) flow.psh_flags_bwd++;
                if (p.tcp_flags.find('A') != string::npos) flow.ack_flags_bwd++;
                if (p.tcp_flags.find('U') != string::npos) flow.urg_flags_bwd++;
            }
        }

        flow.packet_times.push_back(ts);
        if (flow.packet_times.size() > 1) {
            int n = flow.packet_times.size();
            flow.flow_iat.push_back(ts - flow.packet_times[n - 2]);
        }
    }

    vector<pair<FlowKey, FlowData>> get_idle_flows(double current_time) {
        vector<pair<FlowKey, FlowData>> idle_flows;

        lock_guard<mutex> lock(flows_lock);

        while (flow_list.head) {
            Node* node = flow_list.head;
            if (current_time - node->flow.end_time <= FLOW_IDLE_TIMEOUT) {
                break;
            }

            auto result = flow_list.pop_oldest();
            flow_nodes.erase(result.first);
            idle_flows.push_back(result);
        }

        return idle_flows;
    }
};

// ==================== Flow Features ====================
struct FlowFeatures {
    string src_ip, dst_ip;
    int src_port, dst_port;
    int protocol;
    double flow_duration;
    int total_fwd_packets, total_bwd_packets;
    int total_fwd_bytes, total_bwd_bytes;
    double fwd_pkt_len_mean, fwd_pkt_len_std, fwd_pkt_len_min, fwd_pkt_len_max;
    double bwd_pkt_len_mean, bwd_pkt_len_std, bwd_pkt_len_min, bwd_pkt_len_max;
    double flow_bytes_per_sec, flow_packets_per_sec;
    double flow_iat_mean, flow_iat_std, flow_iat_min, flow_iat_max;
    double fwd_iat_mean, bwd_iat_mean;
    int fin_flags, syn_flags, rst_flags, psh_flags, ack_flags, urg_flags;
    int min_pkt_len, max_pkt_len;
    double pkt_len_mean, pkt_len_std;
    double active_mean, idle_mean;
};

FlowFeatures extract_flow_features(FlowKey& key, FlowData& flow) {
    FlowFeatures feat;

    // Finalize active time
    if (flow.current_active_start >= 0 && flow.end_time > 0) {
        double active_dur = flow.end_time - flow.current_active_start;
        if (active_dur > 0) flow.active_times.push_back(active_dur);
    }

    double duration = flow.end_time - flow.start_time;

    Stats fwd_stats = safe_stats(flow.fwd_packet_lengths);
    Stats bwd_stats = safe_stats(flow.bwd_packet_lengths);

    vector<double> combined = flow.fwd_packet_lengths;
    combined.insert(combined.end(), flow.bwd_packet_lengths.begin(), flow.bwd_packet_lengths.end());
    Stats pkt_stats = safe_stats(combined);

    Stats flow_iat_stats = safe_stats(flow.flow_iat);
    Stats fwd_iat_stats = safe_stats(flow.fwd_iat);
    Stats bwd_iat_stats = safe_stats(flow.bwd_iat);
    Stats active_stats = safe_stats(flow.active_times);
    Stats idle_stats = safe_stats(flow.idle_times);

    feat.src_ip = flow.src_ip;
    feat.dst_ip = flow.dst_ip;
    feat.src_port = flow.src_port;
    feat.dst_port = flow.dst_port;
    feat.protocol = (flow.protocol == "TCP") ? 6 : 17;
    feat.flow_duration = duration;
    feat.total_fwd_packets = flow.total_fwd_packets;
    feat.total_bwd_packets = flow.total_bwd_packets;
    feat.total_fwd_bytes = flow.total_fwd_bytes;
    feat.total_bwd_bytes = flow.total_bwd_bytes;

    feat.fwd_pkt_len_mean = fwd_stats.mean;
    feat.fwd_pkt_len_std = fwd_stats.std_dev;
    feat.fwd_pkt_len_min = fwd_stats.min_val;
    feat.fwd_pkt_len_max = fwd_stats.max_val;

    feat.bwd_pkt_len_mean = bwd_stats.mean;
    feat.bwd_pkt_len_std = bwd_stats.std_dev;
    feat.bwd_pkt_len_min = bwd_stats.min_val;
    feat.bwd_pkt_len_max = bwd_stats.max_val;

    feat.flow_bytes_per_sec = (duration > 0) ?
        (flow.total_fwd_bytes + flow.total_bwd_bytes) / duration : 0;
    feat.flow_packets_per_sec = (duration > 0) ?
        (flow.total_fwd_packets + flow.total_bwd_packets) / duration : 0;

    feat.flow_iat_mean = flow_iat_stats.mean;
    feat.flow_iat_std = flow_iat_stats.std_dev;
    feat.flow_iat_min = flow_iat_stats.min_val;
    feat.flow_iat_max = flow_iat_stats.max_val;

    feat.fwd_iat_mean = fwd_iat_stats.mean;
    feat.bwd_iat_mean = bwd_iat_stats.mean;

    feat.fin_flags = flow.fin_flags_fwd + flow.fin_flags_bwd;
    feat.syn_flags = flow.syn_flags_fwd + flow.syn_flags_bwd;
    feat.rst_flags = flow.rst_flags_fwd + flow.rst_flags_bwd;
    feat.psh_flags = flow.psh_flags_fwd + flow.psh_flags_bwd;
    feat.ack_flags = flow.ack_flags_fwd + flow.ack_flags_bwd;
    feat.urg_flags = flow.urg_flags_fwd + flow.urg_flags_bwd;

    feat.min_pkt_len = flow.min_packet_len;
    feat.max_pkt_len = flow.max_packet_len;
    feat.pkt_len_mean = pkt_stats.mean;
    feat.pkt_len_std = pkt_stats.std_dev;

    feat.active_mean = active_stats.mean;
    feat.idle_mean = idle_stats.mean;

    return feat;
}

// ==================== Prediction ====================
struct Prediction {
    string label;
    double confidence;
};

Prediction predict_flow(FlowFeatures& feat) {
    Prediction pred;

    // Heuristic-based detection (simulating ML model)
    int score = 0;

    if (feat.flow_packets_per_sec > 100) score += 3;
    if (feat.syn_flags > 10) score += 2;
    if (feat.flow_duration < 0.1) score += 2;
    if (feat.total_fwd_packets > 100 && feat.total_bwd_packets < 10) score += 2;
    if (feat.fwd_pkt_len_mean < 50) score += 1;

    pred.confidence = min(1.0, score / 10.0);
    pred.label = (pred.confidence >= 0.5) ? "ATTACK" : "BENIGN";

    return pred;
}

// ==================== Auto Prevention ====================
void auto_block_ip(string ip, double confidence) {
    cout << "[AUTO-PREVENTION] IP " << ip << " blocked (confidence: "
         << fixed << setprecision(1) << confidence * 100 << "%)" << endl;
}

// ==================== Worker Threads ====================

// Packet capture simulation
void packet_capture_worker(BoundedQueue<Packet>& packet_q, vector<Packet>& packets) {
    cout << "[CAPTURE] Starting packet capture...\n";
    for (auto& pkt : packets) {
        if (stop_flag) break;
        packet_q.push(pkt);
        this_thread::sleep_for(chrono::milliseconds(1));
    }
    cout << "[CAPTURE] Packet capture complete\n";
}

// Flow processor
void flow_processor_worker(BoundedQueue<Packet>& packet_q,
                          FlowManager& flow_mgr,
                          queue<pair<FlowKey, FlowData>>& out_queue) {
    cout << "[PROCESSOR] Starting flow processor...\n";
    auto last_flush = chrono::steady_clock::now();

    while (!stop_flag) {
        Packet p;
        if (packet_q.pop(p)) {
            flow_mgr.update_flow(p);
        }

        auto now = chrono::steady_clock::now();
        auto elapsed = chrono::duration<double>(now - last_flush).count();

        if (elapsed >= PREDICT_INTERVAL) {
            double current_time = chrono::duration<double>(
                chrono::system_clock::now().time_since_epoch()).count();

            auto idle_flows = flow_mgr.get_idle_flows(current_time);

            for (auto& flow_pair : idle_flows) {
                out_queue.push(flow_pair);
            }

            last_flush = now;
        }

        this_thread::sleep_for(chrono::milliseconds(10));
    }

    cout << "[PROCESSOR] Flow processor complete\n";
}

// Inference worker
void inference_worker(queue<pair<FlowKey, FlowData>>& out_queue, int& alert_count) {
    cout << "[INFERENCE] Starting inference worker...\n";

    while (!stop_flag || !out_queue.empty()) {
        if (out_queue.empty()) {
            this_thread::sleep_for(chrono::milliseconds(100));
            continue;
        }

        auto flow_pair = out_queue.front();
        out_queue.pop();

        FlowKey key = flow_pair.first;
        FlowData flow = flow_pair.second;

        FlowFeatures features = extract_flow_features(key, flow);
        Prediction pred = predict_flow(features);

        auto now = chrono::system_clock::now();
        time_t now_t = chrono::system_clock::to_time_t(now);

        cout << "[" << put_time(localtime(&now_t), "%H:%M:%S") << "] ";
        cout << "Flow " << key.to_string() << " Duration=" << fixed << setprecision(6)
             << features.flow_duration << " Prediction=" << pred.label
             << " Confidence=" << fixed << setprecision(2) << pred.confidence * 100 << "%\n";

        if (pred.label == "ATTACK") {
            alert_count++;

            if (pred.confidence >= AUTO_BLOCK_THRESHOLD) {
                auto_block_ip(features.src_ip, pred.confidence);
            }
        }
    }

    cout << "[INFERENCE] Inference worker complete\n";
}

// ==================== Main ====================
int main() {
    cout << "========================================================================================================================\n";
    cout << "   \t\t\t\t\t\tNetwork IDS\n";
    cout << "========================================================================================================================\n\n";

    // Initialize data structures
    BoundedQueue<Packet> packet_queue(QUEUE_MAXSIZE);
    FlowManager flow_manager;
    queue<pair<FlowKey, FlowData>> out_queue;
    int alert_count = 0;



    // Generate sample packets
    vector<Packet> packets;

    // Normal traffic
    for (int i = 0; i < 5; i++) {
        Packet p;
        p.timestamp = 1.0 + i * 0.1;
        p.length = 100 + i * 10;
        p.src_ip = "192.168.1.10";
        p.dst_ip = "8.8.8.8";
        p.protocol = "TCP";
        p.src_port = 54321 + i;
        p.dst_port = 80;
        p.ip_hdr_len = 20;
        p.tcp_hdr_len = 20;
        p.tcp_flags = (i == 0) ? "S" : "A";
        p.tcp_window = 8192;
        p.tcp_seg_len = p.length - p.tcp_hdr_len;
        packets.push_back(p);
    }

    // Suspicious traffic (SYN flood attack simulation)
    for (int i = 0; i < 150; i++) {
        Packet p;
        p.timestamp = 2.0 + i * 0.001;
        p.length = 40;
        p.src_ip = "10.0.0.100";
        p.dst_ip = "192.168.1.1";
        p.protocol = "TCP";
        p.src_port = 50000 + i;
        p.dst_port = 22;
        p.ip_hdr_len = 20;
        p.tcp_hdr_len = 20;
        p.tcp_flags = "S";
        p.tcp_window = 5840;
        p.tcp_seg_len = 0;
        packets.push_back(p);
    }

    cout << "Generated " << packets.size() << " packets for simulation\n\n";

    // Start worker threads
    cout << "Starting worker threads...\n\n";

    thread capture_thread(packet_capture_worker, ref(packet_queue), ref(packets));
    thread processor_thread(flow_processor_worker, ref(packet_queue), ref(flow_manager), ref(out_queue));
    thread inference_thread(inference_worker, ref(out_queue), ref(alert_count));

    // Wait for capture to complete
    capture_thread.join();

    // Allow processing to complete
    this_thread::sleep_for(chrono::seconds(6));

    // Stop all threads
    stop_flag = true;
    processor_thread.join();
    inference_thread.join();

    // Summary
    cout << "\n=================================================\n";
    cout << "Summary:\n";
    cout << "  - Packets processed: " << packets.size() << "\n";
    cout << "  - Total alerts: " << alert_count << "\n";
    cout << "=================================================\n";

    cout << "\nDSA Components Demonstrated:\n";
    cout << "  1. Doubly Linked List - LRU flow management with move_to_tail\n";
    cout << "  2. Hash Map (std::map) - O(1) flow lookup by FlowKey\n";
    cout << "  3. Bounded Queue - Packet buffering with drop-oldest policy\n";
    cout << "  4. Queue - Output queue for batch processing\n";
    cout << "  5. Vector - Dynamic arrays for IAT, packet lengths\n";
    cout << "  6. Multi-threading - Worker threads for pipeline stages\n";
    cout << "  7. Mutex Locks - Thread-safe flow management\n";

    return 0;
}
