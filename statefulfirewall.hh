#ifndef CLICK_STATEFULFIREWALL_HH
#define CLICK_STATEFULFIREWALL_HH
#include <click/args.hh>
#include <click/element.hh>
#include <clicknet/ip.h>
#include <clicknet/tcp.h>
#include <clicknet/udp.h>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <vector>
CLICK_DECLS

using namespace std;

/* Handshake status */
#define SYN 0
#define SYNACK 1
#define HS_DONE 2

class Connection{
    friend class StatefulFirewall;
private:
	String sourceip;
    String destip;
    int sourceport;
    int destport;
    int proto;
    unsigned long sourceseq;
    unsigned long destseq;
    int handshake_stat;
    bool isfw; //true if forward connection. false if reverse connection.
public:
	Connection(String s, String d, int sp, int dp, unsigned long seq_s, unsigned long seq_d, int pr, bool fwdflag)
        : sourceip(s), destip(d), sourceport(sp), destport(dp), proto(pr), sourceseq(seq_s), destseq(seq_d),
          isfw(fwdflag), handshake_stat(0) {
    	//Add your implementation here.
	}

    Connection() : sourceip("0.0.0.0"), destip("0.0.0.0"), sourceport(0), destport(0), proto(0)
            , sourceseq(0), destseq(0), isfw(false), handshake_stat(0) {
	}

    ~Connection() {}

	/* Can be useful for debugging*/
	void print() const {
    	//Add your implementation here.
        click_chatter("proto = %d, %s:%d[%d] -> %s:%d[%d], isfw = %d", proto, sourceip.c_str(), sourceport, sourceseq, destip.c_str(), destport, destseq, isfw);
	}

	/* Overload == operator to check if two Connection objects are equal.
	 * You may or may not want to ignore the isfw flag for comparison depending on your implementation.
	 * Return true if equal. false otherwise. */
    bool operator==(const Connection &other) const {
    	//Add your implementation here.
        return proto == other.proto && sourceip == other.sourceip && sourceport == other.sourceport
               && destip == other.destip && destport == other.destport;
    }

    /*Compare two connections to determine the sequence in map.*/
    int compare(const Connection other) const;

    unsigned long get_sourceseq() {
        //Add your implementation here.
        return sourceseq;
    }

    unsigned long get_destseq() {
        //Add your implementation here.
        return destseq;
    }

    void set_sourceseq( unsigned long seq_s ) {
        //Add your implementation here.
        sourceseq = seq_s;
    }

    void set_destseq( unsigned long seq_d ) {
        //Add your implementation here.
        destseq = seq_d;
    }

    int get_handshake_stat() {
        //Add your implementation here.
        return handshake_stat;
    }

    /* Update the status of the handshake */
    void update_handshake_stat() {
        //Add your implementation here.
        handshake_stat = 1;
    }

	/* Return value of isfw*/
	bool is_forward() const {
        return isfw;
    }
};

class Policy{
private:
	String sourceip;
	String destip;
	int sourceport;
	int destport;
	int proto;
	int action;

   static uint32_t parseIPStr(const String& ip);
public:
	Policy(String s, String d, int sp, int dp, int p, int act)
            : sourceip(s), destip(d), sourceport(sp), destport(dp), proto(p), action(act) {
    	//Add your implementation here.
	}

	~Policy() {}
	/* Return a Connection object representing policy */
	Connection getConnection();
	/* Return action for this Policy */
	int getAction();
};

struct cmp_connection {
   bool operator()(const Connection& a, const Connection& b) const {
      return a.compare(b) < 0;
   }
};

struct ConnStatus {
    int action;
    int step;
    uint32_t client_seq;
    uint32_t server_seq;
    bool isfw;
};

class StatefulFirewall : public Element {
private:
    enum {CONN_SYN, CONN_SYNACK, CONN_ACK}; // 3 steps in establishing a TCP connection
	std::map<Connection, ConnStatus, cmp_connection> connections; // Map of connections to their action and status.
    std::set<Connection, cmp_connection> negative_cache; // simulate the behavior described in https://piazza.com/class/jqdb9rmezfq1y5?cid=160
	std::vector<Policy> list_of_policies;
public:
	StatefulFirewall() : DEFAULTACTION(0) {}

    ~StatefulFirewall() {}

    /* Take the configuration parameters as input corresponding to
     * POLICYFILE and DEFAULT where
     * POLICYFILE : Path of policy file
     * DEFAULT : Default action (0/1)
     *
     * Hint: Refer to configure methods in other elements.*/
    int configure(Vector<String> &conf, ErrorHandler *errh);

    const char *class_name() const		{ return "StatefulFirewall"; }
    const char *port_count() const		{ return "1/2"; }
    const char *processing() const		{ return PUSH; }
    // this element does not need AlignmentInfo; override Classifier's "A" flag
    const char *flags() const			{ return ""; }

    /* return true if Packet represents a new connection
     * i.e., check if the connection exists in the map.
     * You can also check the SYN flag in the header to be sure.
     * else return false.
     * Hint: Check the connection ID database.
     */
    bool check_if_new_connection(const Packet *);

    /*Check if the packet represent Connection reset
     * i.e., if the RST flag is set in the header.
     * Return true if connection reset
     * else return false.*/
    bool check_if_connection_reset(const Packet *);

    /* Add a new connection to the map along with its action.*/
    void add_connection(Connection &c, int action);

    /* Delete the connection from map*/
    void delete_connection(Connection &c);

    /* Create a new connection object for Packet.
     * Make sure you canonicalize the source and destination ip address and port number.
     * i.e, make the source less than the destination and
     * update isfw to false if you have to swap source and destination.
     * return NULL on error. */
    Connection get_canonicalized_connection(const Packet *);

    /* Read policy from a config file whose path is passed as parameter.
     * Update the policy database.
     * Policy config file structure would be space separated list of
     * <source_ip source_port destination_ip destination_port protocol action>
     * Add Policy objects to the list_of_policies
     * */
    int read_policy_config(const String&);

    /* Convert the integer ip address to string in dotted format.
     * Store the string in s.
     *
     * Hint: ntohl could be useful.*/
    void dotted_addr(const uint32_t *addr, char *s);


   /* Check if Packet belongs to new connection.
    * If new connection, apply the policy on this packet
    * and add the result to the connection map.
    * Else return the action in map.
    * If Packet indicates connection reset,
    * delete the connection from connection map.
    *
    * Return 1 if packet is allowed to pass
    * Return 0 if packet is to be discarded
    */
    int filter_packet(const Packet *);

    int filter_packet_non_tcp(const Connection& connection);

    /* Push valid traffic on port 1
    * Push discarded traffic on port 0*/
    void push(int port, Packet *);

    /*The default action configured for the firewall.*/
    int DEFAULTACTION;
};

CLICK_ENDDECLS
#endif
