/*
 * statefulipfilter.{cc,hh} -- Stateful IP-packet filter
 *
 */

#include <click/config.h>
#include <click/confparse.hh>
#include "statefulfirewall.hh"

/* Add header files as required*/
CLICK_DECLS

//Add your implementation here.
int Connection::compare(const Connection other) const {
    //Add your implementation here.
    // TODO: Is this compare only used with map? The comparison is not accurate for IP addresses

    if (*this == other) {
        return 0;
    } else if (proto < other.proto
               || proto == other.proto && sourceip < other.sourceip
               || proto == other.proto && sourceip == other.sourceip && destip < other.destip
               || proto == other.proto && sourceip == other.sourceip && destip == other.destip
                  && sourceport < other.sourceport
               || proto == other.proto && sourceip == other.sourceip && destip == other.destip
                  && sourceport == other.sourceport && destport < other.destport) {
        return -1;
    } else {
        return 1;
    }
}

uint32_t Policy::parseIPStr(const String& ip) {
    int count = 0;
    int pos[3];
    for (String::iterator it = ip.begin(); it != ip.end(); ++it) {
        if (*it == '.') {
            pos[count++] = it - ip.begin();
        }
    }
    return (((uint32_t)atoi(ip.substring(0, pos[0]).c_str())) << 24)
           + (((uint32_t)atoi(ip.substring(pos[0] + 1, pos[1] - pos[0] - 1).c_str())) << 16)
           + (((uint32_t)atoi(ip.substring(pos[1] + 1, pos[2] - pos[1] - 1).c_str())) << 8)
           + (uint32_t)atoi(ip.substring(pos[2] + 1).c_str());
}

Connection Policy::getConnection() {
//    click_chatter("%s %s %d %d", sourceip.c_str(), destip.c_str(), parseIPStr(sourceip), parseIPStr(destip));
    bool isfw = (parseIPStr(sourceip) < parseIPStr(destip));
    return Connection(isfw ? sourceip : destip, isfw ? destip: sourceip, isfw ? sourceport : destport
            , isfw ? destport : sourceport, 0, 0, proto, isfw);
}

int Policy::getAction() {
    return action;
}

int StatefulFirewall::configure(Vector<String> &conf, ErrorHandler *errh) {
    String policyFile;
    if (Args(conf, this, errh)
                .read("POLICYFILE", policyFile)
                .read("DEFAULT", DEFAULTACTION).complete() < 0)
        return -1;
    return read_policy_config(policyFile);
}

bool StatefulFirewall::check_if_new_connection(const Packet *packet) {
    if (packet->ip_header()->ip_p == IP_PROTO_TCP
        && packet->tcp_header()->th_flags & TH_SYN
        && (packet->tcp_header()->th_flags ^ TH_SYN) == 0 // https://piazza.com/class/jqdb9rmezfq1y5?cid=158
        && connections.count(get_canonicalized_connection(packet)) == 0) {
        return true;
    } else {
        return false;
    }
}

bool StatefulFirewall::check_if_connection_reset(const Packet *packet) {
    if (packet->ip_header()->ip_p == IP_PROTO_TCP && packet->tcp_header()->th_flags & TH_RST) {
        return true;
    } else {
        return false;
    }
}

void StatefulFirewall::add_connection(Connection &c, int action) {
    connections[c].action = action;
    connections[c].step = CONN_SYN;
    connections[c].client_seq = c.get_sourceseq();
    connections[c].server_seq = 0;
    connections[c].isfw = c.isfw;
}

void StatefulFirewall::delete_connection(Connection &c) {
    connections.erase(c);
}

Connection StatefulFirewall::get_canonicalized_connection(const Packet *packet) {
    char sourceip[16];
    char destip[16];
    memset(sourceip, 0, 16);
    memset(destip, 0, 16);
    dotted_addr((uint32_t *)&(packet->ip_header()->ip_src), sourceip);
    dotted_addr((uint32_t *)&(packet->ip_header()->ip_dst), destip);
    bool isfw = (ntohl((uint32_t)(packet->ip_header()->ip_src.s_addr)) < ntohl((uint32_t)(packet->ip_header()->ip_dst.s_addr)));
    int sport = 0;
    int dport = 0;
    int sseq = 0;
    int dseq = 0;
    if (packet->ip_header()->ip_p == IP_PROTO_TCP) {
        sport = ntohs(packet->tcp_header()->th_sport);
        dport = ntohs(packet->tcp_header()->th_dport);
        sseq = ntohl(packet->tcp_header()->th_seq);
        dseq = ntohl(packet->tcp_header()->th_ack); // TODO: should I use ack number as dseq here?
    } else if (packet->ip_header()->ip_p == IP_PROTO_UDP) {
        sport = ntohs(packet->udp_header()->uh_sport);
        dport = ntohs(packet->udp_header()->uh_dport);
    }
    return Connection(String(isfw ? sourceip : destip), String(isfw ? destip : sourceip), isfw ? sport : dport
            , isfw ? dport : sport, sseq, dseq, packet->ip_header()->ip_p, isfw);
}

int StatefulFirewall::read_policy_config(const String& policyFile) {
    std::ifstream fin(policyFile.c_str());
    string line;
    while (getline(fin, line)) {
        if (line.length() > 1 && (line[0] != '#' || line[1] != '#')) {
            int ptr = 0;
            vector<int> beginPos;
            vector<int> endPos;
            // Supporting arbitrary length of '\t' and ' ' as delimiter
            while (ptr < line.length() - 1) {
                if ((line[ptr] == ' ' || line[ptr] == '\t') && line[ptr + 1] != ' ' && line[ptr + 1] != '\t') {
                    beginPos.push_back(ptr + 1);
                } else if (line[ptr] != ' ' && line[ptr] != '\t' && (line[ptr + 1] == ' ' || line[ptr + 1] == '\t')) {
                    endPos.push_back(ptr + 1);
                }
                ++ptr;
            }
            if (line[0] != ' ' && line[0] != '\t') {
                beginPos.insert(beginPos.begin(), 0);
            }
            if (line[line.length() - 1] != ' ' && line[line.length() - 1] != '\t') {
                endPos.push_back(line.length());
            }
//            click_chatter("line: %s, beginPos.size() = %d, endPos.size() = %d", line.c_str(), beginPos.size(), endPos.size());
//            for (int i = 0; i < beginPos.size(); ++i) {
//                click_chatter("%d %d", beginPos[i], endPos[i]);
//            }
            if (beginPos.size() != 6 || endPos.size() != 6) {
                return -1;
            }
            list_of_policies.push_back(Policy(line.substr(beginPos[0], endPos[0] - beginPos[0]).c_str()
                    , line.substr(beginPos[2], endPos[2] - beginPos[2]).c_str()
                    , atoi(line.substr(beginPos[1], endPos[1] - beginPos[1]).c_str())
                    , atoi(line.substr(beginPos[3], endPos[3] - beginPos[3]).c_str())
                    , atoi(line.substr(beginPos[4], endPos[4] - beginPos[4]).c_str())
                    , atoi(line.substr(beginPos[5], endPos[5] - beginPos[5]).c_str())));
        }
    }
    fin.close();
    return 0;
}

void StatefulFirewall::dotted_addr(const uint32_t *addr, char *s) {
    uint32_t addrInt = ntohl(*addr);
    sprintf(s, "%d.%d.%d.%d", (addrInt & 0xff000000) >> 24, (addrInt & 0x00ff0000) >> 16, (addrInt & 0x0000ff00) >> 8, addrInt & 0x000000ff);
}

int StatefulFirewall::filter_packet_non_tcp(const Connection& connection) {
    for (vector<Policy>::iterator it = list_of_policies.begin(); it != list_of_policies.end(); ++it) {
        Connection policyConnection = it->getConnection();
//        policyConnection.print();
//        connection.print();
        if (policyConnection == connection && policyConnection.is_forward() == connection.is_forward()) {
            return it->getAction();
        }
    }
    return DEFAULTACTION;
}

int StatefulFirewall::filter_packet(const Packet *packet) {
    Connection connection = get_canonicalized_connection(packet);
    if (negative_cache.count(connection)) {
        return 0;
    }
    int action = filter_packet_non_tcp(connection);
    // For non-TCP protocols, the processing logic can be simplified to filter_packet_non_tcp()
    if (packet->ip_header()->ip_p == IP_PROTO_TCP) {
        if (connections.count(connection)) {
            if (check_if_connection_reset(packet)) {
                // RST can be sent anytime, regardless of the status of the connection
                delete_connection(connection);
            } else if (connections[connection].step == CONN_SYN) {
                // Still waiting for ACK for the initial SYN (which is usually a SYNACK)
                if ((packet->tcp_header()->th_flags & TH_ACK)
                    && ntohl(packet->tcp_header()->th_ack) == connections[connection].client_seq + 1
                    && connection.isfw != connections[connection].isfw) {
                    connections[connection].step = CONN_SYNACK;
                    connections[connection].server_seq = ntohl(packet->tcp_header()->th_seq);
                    connections[connection].isfw = connection.isfw;
                    action = 1;
                } else {
                    // Reject all packets other than a correct ACK from server
                    action = 0;
                }
            } else if (connections[connection].step == CONN_SYNACK && connection.isfw != connections[connection].isfw) {
                // Received SYNACK, waiting for the 3rd packet ACK
                if ((packet->tcp_header()->th_flags & TH_ACK)
                    && ntohl(packet->tcp_header()->th_ack) == connections[connection].server_seq + 1) {
                    connections[connection].step = CONN_ACK;
                    connections[connection].client_seq = ntohl(packet->tcp_header()->th_seq);
                    action = 1;
                    connections[connection].isfw = connection.isfw;
                    connections[connection].action = 1;
//                    connection.print();
                }
            } else {
                // connection fully established
                action = connections[connection].action;
            }
        } else if (check_if_new_connection(packet) && action == 1) {
            add_connection(connection, action);
//            click_chatter("add_connection %d %s %d %s %d", connection.proto, connection.sourceip.c_str(), connection.sourceport, connection.destip.c_str(), connection.destport);
        }
    }
    if (action == 0) {
        negative_cache.insert(connection);
    }
    return action;
}

void StatefulFirewall::push(int port, Packet *packet) {
//    get_canonicalized_connection(packet).print();
    output(filter_packet(packet)).push(packet);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(StatefulFirewall)
