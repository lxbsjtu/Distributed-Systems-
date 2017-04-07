#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <thread>
#include <iostream>
#include <vector>
#include <sstream>
#include <fstream>
#include <map>
#include <dirent.h>
#include <mutex>
#include <algorithm>

using std::string;
using std::vector;
using std::stringstream;
using std::cin;
using std::pair;
using std::mutex;
using std::map;
using std::thread;

#define MAXBUFLEN 1000
#define PING_INTERVAL 1500

#define USER_NAME "xl14"

/*
 * Helper function of split method below
 */
void split(const string &s, char delim, vector<string> &elems) {
    stringstream ss;
    ss.str(s);
    string item;
    while (getline(ss, item, delim)) {
        elems.push_back(item);
    }
}

/*
 * Parse the received message
 */
vector<string> split(const string &s, char delim) {
    vector<string> elems;
    split(s, delim, elems);
    return elems;
}

std::string exec_ret(const char* cmd) {
    char buffer[256];
    std::string result = "";
    std::shared_ptr<FILE> pipe(popen(cmd, "r"), pclose);
    if (!pipe) throw std::runtime_error("popen() failed!");
    while (!feof(pipe.get())) {
        if (fgets(buffer, 128, pipe.get()) != NULL)
            result += buffer;
    }
    return result;
}

int get_node_number(string hostname) {
    vector<string> split1 = split(hostname, '-');
    vector<string> split2 = split(split1.back(), '.');
    return std::stoi(split2.front());
}

string get_hostname(int node_number) {
    char var[3];
    sprintf(var,"%02d",node_number);
    return "fa16-cs425-g19-" + string(var) + ".cs.illinois.edu";
}

struct ID {
    pair<unsigned long, string> values;

    bool operator==(const ID &b) const { return values == b.values; }

    bool operator!=(const ID &b) const { return values != b.values; }

    bool operator<(const ID &b) const { return values < b.values; }

    unsigned long timestamp() const { return values.first; }

    string ip() const { return values.second; }

    string Serialize() const {
        return std::to_string(timestamp()) + ":" + ip();
    }

    static ID Deserialize(const string &ids) {
        ID id;
        vector<string> after_split = split(ids, ':');
        id.values = std::make_pair(std::stoul(after_split[0]), after_split[1]);
        return id;
    }
};

mutex m;
string introducer_IP;
string introducer_port;
string master_IP;
string master_port;
string node_IP;
string node_port;
ID node_id;

// easier than decoding the string in node_id
int node_number;

double leaving_time;
double joining_back_time;
// Maintaining a bool to keep track of whether a machine has left. If it has
// left it should not ping others.
bool hasLeft = false;

// Map from ID to port number.
map<ID, string> mapping;
// Membership list containing the IDs. This list is always in sync with
// @mapping above.
vector<ID> members;

//mp3: file table for each node, key: file name, value: nodes' ip addresses
struct FT {
    map<string, vector<ID>> file_map;

    //serialize file table to file $ ID1 # port $ ID2 # port & file $ ID1 # port $ ID2 # port
    string Serialize() const {
        string rst;

        for (auto &elem : file_map) {
            rst += elem.first + "\t";
            for(auto &id : elem.second) {
                if(id.values.first == 0) {
                    rst += std::to_string(get_node_number(id.ip())) + "\t";
                }
            }
            // for (vector<int>::size_type k = 0; k != elem.second.size(); k++) {
            //     if (elem.second[k].values.first == 0) {
            //         rst += elem.second[k].ip() + "\t";
            //     }
            // }
            rst += "\n";
        }
        return rst;
    }
};

FT file_config;
// mutex mtx;

vector<std::string> get_split_files() {
    DIR *dir;
    vector<std::string> split_file;
    struct dirent *ent;
    if ((dir = opendir("split/")) != NULL) {
        /* print all the files and directories within directory */
        while ((ent = readdir(dir)) != NULL) {
            if (ent->d_name[0] == 'p') {
                printf("%s\n", ent->d_name);
                std::string file_name(ent->d_name);
                split_file.push_back(file_name);
            }
        }
        closedir(dir);
    }
    return split_file;
}

void assign_files(vector< pair<int,vector<string>> > &jid_info, const string prefix) {
    int num_jid = jid_info.size();
    vector<string> files;

    for(auto &kv : file_config.file_map) {
        if ( kv.first.substr(0, prefix.size()) == prefix ) {
            // for every file that has the prefix
            files.emplace_back(kv.first);
            printf("+: %s\n", kv.first.c_str());
        } else {
            printf("x: %s\n", kv.first.c_str());
        }
    }

    // determine how many files each jid should get (even split)
    vector<int> num_left(num_jid, 0);
    for(int i = 0; i < num_jid; i++) num_left[i] = files.size() / num_jid;

    int remain = files.size() % num_jid; int i = 0;
    while(remain-- > 0) num_left[(i++)%num_left.size()] += 1;

    // assign files that are on the machine already to the process
    for(int i = 0; i < num_jid; i++) {
        // find any remaining files that are saved in the same server
        // if there aren't any then come back for clean up later

        int node = jid_info[i].first;

        while(num_left[i] > 0) {
            string f = "";
            for(auto &file : files) {
                for(auto id: file_config.file_map[file]) {
                    if(get_node_number(id.ip()) == node) {
                        f = file;
                        break;
                    }
                }
            }

            // if we can't find any more files on the node break
            if (f == "") {
                break;
            } else {
                // remove from list of files f
                auto it = std::find(files.begin(), files.end(), f);
                if(it != files.end())
                    files.erase(it);

                jid_info[i].second.emplace_back(f);
                num_left[i]--;
            }
        }
    }

    // clean up and final assigns on files that are left behind (i.e. files to move)
    for(int i = 0; i < num_jid; i++) {
        while(num_left[i] > 0) {
            jid_info[i].second.emplace_back(files.back());
            files.pop_back();
            num_left[i]--;
        }
    }
}

/*
 * Convert the mappting information to one string of the following format:
 * nodeNum1:IP1:port1;nodeNum2:IP2:port2 ...
 */
string serialize_map() {
    string serialized;
    for (auto elem : mapping) {
        serialized += elem.first.Serialize() + ":" + elem.second + ";";
    }
    return serialized;
}

/*
 * Print the mapping content
 */
void printing_the_map() {
    printf("Mapping:\n");
    for (const auto &elem : mapping) {
        printf("<%s> \n", elem.first.Serialize().c_str());
    }
}

/*
 * Print the membership list
 */
void printing_members() {
    printf("Members:\n");
    for (const auto &elem : mapping) {
        printf("%s \n", elem.first.Serialize().c_str());
    }
}

/*
 * It converts the serialized string message to the vector structured membership
 * list
 * Input: string in the format:
 * "node_id_current_node#memberID1:memberIP1:memberPort1;memberID2:memberIP2:memberPort2;"
 */
void deserialize_string_mapping_map(const string &to_deserialize) {
    const string node_id_string = to_deserialize.substr(0, to_deserialize.find('#'));
    node_id = ID::Deserialize(node_id_string);
    string members_list = to_deserialize.substr(to_deserialize.find('#') + 1);
    printf("The list received from introducer is -> %s\n", members_list.c_str());

    vector<string> member_node = split(members_list, ';');
    {
        std::lock_guard<mutex> lk(m);
        for (int i = 0; i < member_node.size(); i++) {
            printf("triplet[i] = %s\n", member_node[i].c_str());
            vector<string> after_split = split(member_node[i], ':');
            const ID member_node_id(ID::Deserialize(member_node[i]));

            printf("after_split 1= %s, 2=%s, 3=%s\n", after_split[0].c_str(),
                   after_split[1].c_str(), after_split[2].c_str());
            members.push_back(member_node_id);
            string member_node_port = after_split[2];
            mapping[member_node_id] = member_node_port;
        }

        printf("Filled our map initially with the introducer's membership list\n");
        printing_the_map();
    }
}

/*
 * Iterate through the map and send all nodes except the newly joint node
 *(new_node_id) information about the new node.
 * Every message starts with a 4 byte message type, NEWJ, PING, JOIN etc.
 */
void sending_info_to_all_nodes(ID new_or_failed_node_id, string message, bool sendtoself) {
    map<ID, string> mapping_copy;

    {
        std::lock_guard<mutex> lk(m);
        mapping_copy = mapping;
    }

    for (auto &elem : mapping_copy) {
        if (elem.first != new_or_failed_node_id && (sendtoself || elem.first != node_id)) {
            int sockfd;
            struct addrinfo hints, *servinfo, *p;
            int rv, numbytes;
            memset(&hints, 0, sizeof hints);
            hints.ai_family = AF_UNSPEC; // set to AF_INET to force IPv4
            hints.ai_socktype = SOCK_DGRAM;
            hints.ai_flags = AI_PASSIVE; // use my IP

            printf("id= %s, port = %s \n", elem.first.Serialize().c_str(),
                   elem.second.c_str());
            printf("new_or_failed_id = <%s> %s \n",
                   new_or_failed_node_id.Serialize().c_str(),
                   mapping_copy[new_or_failed_node_id].c_str());

            if ((rv = getaddrinfo(elem.first.ip().c_str(), elem.second.c_str(), &hints, &servinfo)) != 0) {
                fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
                continue;
            }

            // loop through all the results and bind to the first we can
            for (p = servinfo; p != NULL; p = p->ai_next) {
                if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
                    perror("talker: socket for sending other nodes information about the newly-joined node");
                    continue;
                }

                break;
            }

            if (p == NULL) {
                fprintf(stderr, "talker: failed to bind socket for sending other nodes "
                        "information about the newly-joined node\n");
                return;
            }

            // Sending message to that node
            // Message has the following format: NEWJ#node_id:IP:port
            printf("Send message = %s\n", message.c_str());
            if ((numbytes = sendto(sockfd, message.c_str(), message.length(), 0, p->ai_addr, p->ai_addrlen)) == -1) {
                printf("Sending %s from %s to %s\n", message.substr(0, 4).c_str(),
                       mapping_copy[new_or_failed_node_id].c_str(), elem.second.c_str());
                perror("Sending failed");
            }
            freeaddrinfo(servinfo);
            close(sockfd);
        }
    }
}

/*
 * This method sends the join message to the INTRODUCER node, and asks to join
 * the membership community
 * Then it receives the membership message from the INTRODUCER node, and parses
 * it the vectorized membership list.
 */
void sending_join_receiving_list_making_map() {
    int sockfd;
    struct addrinfo hints, *servinfo, *p;
    int rv;
    int numbytes;
    int numbytes2;
    char buf[MAXBUFLEN];
    string message;
    int bytesReceived = 0;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    if ((rv = getaddrinfo(introducer_IP.c_str(), introducer_port.c_str(), &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return;
    }

    // loop through all the results and make a socket
    for (p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            perror("talker: socket");
            continue;
        }

        break;
    }

    if (p == NULL) {
        fprintf(stderr, "talker: failed to create socket\n");
        return;
    }

    hasLeft = false; // Now it has joined back or is alive
    printf("sending join request   \n");
    message = "JOIN:" + node_IP + ":" + node_port;
    // sent "JOIN" request to introducer node
    if ((numbytes = sendto(sockfd, message.c_str(), message.length(), 0, p->ai_addr, p->ai_addrlen)) == -1) {
        perror("talker: sendto");
        exit(1);
    }

    printf("Sent JOIN request from %s to introducer node\n", node_IP.c_str());

    printf("Sent %d bytes to %s\n", numbytes, introducer_IP.c_str());
    printf("Sent %s bytes to \n", message.c_str());

    // it receives the node number ID along with membership list in the following format:
    // node_id#nodeNum1:IP1:port1;nodeNum2:IP2:port2 ...
    if ((numbytes2 = recvfrom(sockfd, buf, MAXBUFLEN - 1, 0, p->ai_addr, &p->ai_addrlen)) == -1) {
        perror("recvfrom");
        exit(1);
    }

    printf("Received Join approval packet which is %d bytes long\n", numbytes2);
    buf[numbytes2] = '\0';
    printf("Join approval packet contains \"%s\"\n", buf);
    string bufst = string(buf);
    // We will first delete the vector and map if it has been filled already
    // (if node was alive once and it left and is joining back)
    // We will fill the map again by the list given by the introducer

    {
        std::lock_guard<mutex> lk(m);
        members.clear(); // empty vector
        printf("Cleared the vector\n");
        mapping.clear(); // empty map
        printf("Cleared the map\n");
        printing_members();
        // cleared the vector and map. Now it can be filled again by the latest list
    }

    deserialize_string_mapping_map(bufst);
    // it will create the map from information given b the introducer
    // The vector of members and the mapping has been initialized with the list given by
    // introducer
    freeaddrinfo(servinfo);
    close(sockfd);
}

/*
 * It sends one PING message to other normal node for every interval
 * If it does not receive the ACK from other node in a soecific time interval,
 * we treat the node as a failed node and
 * asks other nodes to delete it from the membership list.
 */
void sending_one_ping_message_per_interval(const ID &member_id, string port) {
    struct addrinfo hints, *servinfo, *p;
    int sockfd, rv, numbytes, numbytes2;
    string message = "";
    char buf[MAXBUFLEN];
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 500000;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // set to AF_INET to force IPv4
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE; // use my IP

    if ((rv = getaddrinfo(member_id.ip().c_str(), port.c_str(), &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return;
    }

    // loop through all the results and bind to the first we can
    for (p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            perror("talker: socket for sending other nodes information");
            continue;
        }

        break;
    }

    if (p == NULL) {
        fprintf(stderr, "talker: failed to bind socket for sending other nodes information\n");
        return;
    }

    message = "PING#" + member_id.Serialize();
    if ((numbytes = sendto(sockfd, message.c_str(), message.length(), 0, p->ai_addr, p->ai_addrlen)) == -1) {
        perror("talker: Failed to send PING message.");
        exit(1);
    }

    // sent "PING" ping request to a normal node
    // printf("Sent %d bytes of PING message from %s to %s port \n", numbytes,
    // node_id.Serialize().c_str(), member_id.Serialize().c_str());
    // printf("Sent the message: %s\n", message.c_str());

    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // If the node does not receive the message from the node within the time
    if ((numbytes2 = recvfrom(sockfd, buf, MAXBUFLEN - 1, 0, p->ai_addr, &p->ai_addrlen)) < 0) {
        // On timeout, we will send a message to all other machines to remove this node from
        // their list. The message will be of the format: "FAIL#node_id"
        printf("TIMEOUT occured of member_id = %s and port = %s\n",
               member_id.Serialize().c_str(), port.c_str());
        string message2 = "FAIL#" + member_id.Serialize();
        sending_info_to_all_nodes(member_id, message2, true);
    } else {
        // it receives the ACKK
        // printf("Acknowledgement packet received %d bytes long on sending "
        //                       "PING from %s to %s \n", numbytes2, node_id.Serialize().c_str(), member_id.Serialize().c_str());
        buf[numbytes2] = '\0';
    }
    close(sockfd);
}

/*
 * We iterate through vector<ID> to find index of the node_id whose timestamp is just
 * greater than the current node id.
 * Vector<ID> members will be of the form: [<1, IP1>,<2, IP2>,<3, IP3> --------]
 * In other words,
 * Node 0: pings in the order 1->2->3->4->5->6->7
 * Node 1: pings in the order 2->3->4->5->6->7->0
 * Node 2: pings in the order 3->4->5->6->7->0->1
 * Node 3: pings in the order 4->5->6->7->0->1->2
 */
void sending_pings() {
    int pointer = 0;
    {
        std::lock_guard<mutex> lk(m);
        for (int i = 0; i < members.size(); i++) {
            if (members[i].timestamp() > node_id.timestamp()) {
                pointer = i;
                break;
            }
        }
    }

    while (1) {
        string ip, port;
        ID member_id;
        bool member_size_one;
        bool member_size_zero;
        {
            std::lock_guard<mutex> lk(m);
            member_size_one = members.size() == 1;
            member_size_zero = members.size() == 0;
            if (!member_size_zero) {
                int index = pointer % members.size();
                pointer++;
                member_id = members[index];
                port = mapping[member_id];
            }
        }

        // if the node is left, then do not ping. Sleep for sometime and check again
        if (hasLeft) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            continue;
        }
        // if member list is zero, sleep for a while and check later
        if (member_size_zero) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            continue;
        }

        // To prevent the main introducer node from sending messages to himself
        if (member_id == node_id) {
            // Since it does not need to send PING to itself, it can sleep for a while
            if (member_size_one) {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }
            continue;
        }
        thread first(sending_one_ping_message_per_interval, member_id, port);
        first.detach();


        std::this_thread::sleep_for(std::chrono::milliseconds(PING_INTERVAL));
    }
}

/*
 * It first sleeps, then executes the following steps to leave the membership
 * community
 * It sends LEAV#node_id message to all nodes except itself; all nodes will
 * remove this node from their list
 * We also empty its map so that it doesn't ping others
 */
void leaving() {
    // int leaving_time_int = leaving_time * 1000;
    // std::this_thread::sleep_for(std::chrono::milliseconds(leaving_time_int));
    hasLeft = true; // Instead of emptying the map, we set this variable.
    string message = "LEAV#" + node_id.Serialize();
    // Sends LEAV#node_id message to all nodes except itself
    // all nodes will remove this node from their list
    sending_info_to_all_nodes(node_id, message, false);
    printf("Sent LEAV message to all other nodes\n");
    // we will remove its entry from the map, so that it can pick it up from
    // here on joining back
    {
        std::lock_guard<mutex> lk(m);
        for (auto it = members.begin(); it != members.end(); ++it) {
            if (*it == node_id) {
                members.erase(it);
                break;
            }
        }
        mapping.erase(node_id);
        printing_members();
    }
}

void *get_in_addr(struct sockaddr *sa) {
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in *) sa)->sin_addr);
    }

    return &(((struct sockaddr_in6 *) sa)->sin6_addr);
}

// mp3 functions declared as follows

void file_add(const string file, const string file_ip) {
    ID file_id;
    file_id.values = std::make_pair(0, file_ip);

    printf("file_add_called: %s, %s\n", file.c_str(), file_ip.c_str());

    if (file_config.file_map.find(file) == file_config.file_map.end()) {
        vector<ID> file_vec = {file_id};
        file_config.file_map[file] = file_vec;
    } else {
        for(auto &id: file_config.file_map[file]) {
            if (id.ip() == file_ip) {
                //printf("file already mapped: %s, %s\n", file.c_str(), file_ip.c_str());
                if (id.values.first == 1)
                    id.values.first = 0;
                return;
            }
        }

        file_config.file_map[file].emplace_back(file_id);
    }
}

void file_del(const string file) {
    file_config.file_map.erase(file);
}


/* put file fname to target hostname (in sdfs)
 * does not do any checking, use with caution
 * the file must be in the sdfs, and must not be on hostname
 */
void put_file(string fname, string hostname) {
    file_add(fname, hostname);

    string msg;
    msg += "FPUT" + fname;
    msg += "#" + hostname;

    char exec[254];
    sprintf(exec, "scp -o StrictHostKeyChecking=no %s@%s:~/sdfs/%s %s@%s:~/sdfs/%s",
            USER_NAME, file_config.file_map[fname].front().ip().c_str(), fname.c_str(),
            USER_NAME, hostname.c_str(), fname.c_str());

    if (system(exec) == 0) {
        printf("\nFile %s moved successfully\n", fname.c_str());
    } else {
        printf("\nFile %s not moved successfully\n", fname.c_str());
    }

    sending_info_to_all_nodes(node_id, msg, false);
    // printf("%s", file_config.Serialize().c_str());
}

/* should remove specified file from the sdfs
 */
void rm_file(string file) {
    // delete the file across machines
    string msg;

    msg += "FDEL" + file;

    // update local file table by removing the specified file entry
    file_del(file);

    // check if file exists locally, if it does then delete it
    if (file_config.file_map.find(file) == file_config.file_map.end()) {
        // the file does not exist at all actually...
    } else {
        for(ID id: file_config.file_map[file]) {
            // check if the file is in the current machine's ip
            if (id.ip() == node_id.ip()) {
                // the file exists in the machine! <I think, could use a second opinion>
                if(!fork()) {
                    char exec[180];
                    sprintf(exec, "rm ~/sdfs/%s", file.c_str());
                    if (system(exec) == 0) {
                        printf("\nFile %s deleted successfully", file.c_str());
                    } else {
                        printf("\nFile %s not deleted\n", file.c_str());
                        exit(1);
                    }
                    exit(0);
                }
                break; // exec time break; doesn't really matter
            }
        }
    }

    // send delete message to all other servers to let them delete the file as well

    sending_info_to_all_nodes(node_id, msg, false);
}

void put_new_file(string file, string remote_file_name) {
    string msg;
    msg += "FPUT" + remote_file_name;
    // printf("here is ok");
    // let the server the client resides on add file to their file tables
    if (members.size() <= 3) {
        std::lock_guard<mutex> lk(m);
        for (ID member : members) {
            file_add(remote_file_name, member.ip());
        }
    } else {
        std::lock_guard<mutex> lk(m);
        int min = 0, max = (int) members.size() - 1;
        srand(time(NULL));
        while (file_config.file_map[remote_file_name].size() < 3) {
            int candidate = min + (std::rand() % (max - min + 1));
            string cand_str = members[candidate].ip();
            if (file_config.file_map[remote_file_name].size() == 0) {
                file_add(remote_file_name, cand_str);
            } else {
                int fg = 1;
                for (int m = 0; m < file_config.file_map[remote_file_name].size(); ++m) {
                    if (cand_str == file_config.file_map[remote_file_name][m].ip()) {
                        fg = 0;
                        break;
                    }
                }
                if (fg) {
                    file_add(remote_file_name, cand_str);
                }
            }
        }
    }

    for (ID member : file_config.file_map[remote_file_name]) {
        msg += "#" + member.ip();
        if (node_id.ip() != member.ip()) {
            char exec[180];
            sprintf(exec, "scp -o StrictHostKeyChecking=no %s %s@%s:~/sdfs/%s", file.c_str(),
                    USER_NAME,
                    member.ip().c_str(),
                    remote_file_name.c_str());
            if (system(exec) != 0) {
                printf("\nFile %s not moved successfully\n", file.c_str());
            }
        } else {
            char exec1[100];
            sprintf(exec1, "cp %s ~/sdfs/%s", file.c_str(), remote_file_name.c_str());
            if (system(exec1) != 0) {
                printf("\nFile mv failed\n");
            }
        }

    }
    sending_info_to_all_nodes(node_id, msg, false);
}

bool member_alive(int node) {
    std::lock_guard<mutex> lk(m);
    bool ret = false;
    for(auto mem: members) {
        if(get_node_number(mem.ip()) == node) {
            ret = true; break;
        }
    }
    return ret;
}

void handle_maple(string exe, int mid, int node, int total, vector<string> files, string pref, bool &done) {
    // copy the file onto the machine if it's not there
    // split the file if needed
    string fstr;
    string hname = get_hostname(node);
    for(string file: files) {
        // check if file needs to be put
        bool need_to_move = true;
        auto locs = file_config.file_map[file];
        for(auto id: locs) {
            if(id.ip() == hname) {
                need_to_move = false;
                break;
            }
        }

        if(need_to_move) put_file(file, get_hostname(node));
        fstr = fstr + "~/sdfs/"+ file + " ";
    }

    char exec[254];
    // run the program
    sprintf(exec, "ssh %s@%s ~/%s %02d %d %s %s", USER_NAME, get_hostname(node).c_str(), exe.c_str(), mid, total, pref.c_str(), fstr.c_str());
    if (system(exec) == 0)
        printf("\nmid %d@%d succeeded in exec\n", mid, node);
    else {
        printf("\nmid %d@%d failed in exec, waiting to restart\n", mid, node);
        return;
    }

    done = true;
}

void handle_juice(string exe, int jid, int node, vector<string> files, bool &done) {
    // move any absent files into where they need to be
    // for(auto pair: jid_info) {
    string hname = get_hostname(node);

    for(string file: files) {
        // if the file is not in the node for the jid
        // move it there
        bool need_to_move = true;
        auto locs = file_config.file_map[file];
        for(auto id: locs) {
            if(id.ip() == hname) {
                need_to_move = false;
                break;
            }
        }

        if(need_to_move) {
            put_file(file, hname);
        }
    }

    // launch juice_exe prcoess across all machines
    // for(auto pair: jid_info) {
    string file_str = "";
    for(auto s: files)
        file_str += "/home/raghu3/sdfs/" + s + " ";

    char exec[180];
    sprintf(exec, "ssh %s@%s ~/%s %s", USER_NAME, get_hostname(node).c_str(), exe.c_str(), file_str.c_str());
    if (system(exec) == 0) {
        printf("\njuiced successfully\n");
    } else {
        printf("\njuicing failed\n");
    }
    // }

    // string s = exec_ret(exec);
    // printf("input: %s\n", file_str.c_str());

    done = true;
}

int demo_action() {
    string demo_action = "";
    // Thread waiting for user input
    while (1) {

        getline(cin, demo_action);
        if (demo_action.compare("list") == 0) {
            // list the membership
            printing_members();
        } else if (demo_action.compare("id") == 0) {
            // list self's id
            printf("Self's id =%s\n", node_id.Serialize().c_str());
        } else if ((demo_action.compare("join")) == 0) {
            // join the membershi group
            sending_join_receiving_list_making_map();
        } else if ((demo_action.compare("leave")) == 0) {
            // leave the membership group
            leaving();
        } else if ((demo_action.substr(0, 3).compare("put")) == 0) {
            //When client receives the put command, it will send all the
            // update information to 3 other servers to let them add the new file in
            //their file tables

            vector<string> file_arg = split(demo_action, ' ');
            if (file_arg.size() < 2) {
                printf("usage: put [file_name] [sdfs_file_name]");
                continue;
            }
            put_new_file(file_arg[1], file_arg[2]);
        } else if((demo_action.substr(0, 4).compare("file")) == 0){
            // get the file table contents
            // mtx.lock();
            printf("%s",file_config.Serialize().c_str());
            // mtx.unlock();
        } else if ((demo_action.substr(0, 3).compare("get")) == 0) {
            //get the specified file to the client side
            vector<string> file_arg = split(demo_action, ' ');
            string remote_file = file_arg[1];
            string local_file = file_arg[2];
            string msg;
            msg += "FGET" + remote_file;

            ID server;
            // mtx.lock();
            for (auto it = file_config.file_map[remote_file].begin();
                 it != file_config.file_map[remote_file].end(); ++it) {
                if (((*it).ip() != node_id.ip()) && ((*it).values.first == 0)) {
                    server = *it;
                    break;
                }
            }
            // mtx.unlock();

            if(!fork()) {
                char exec[180];
                sprintf(exec, "scp -o StrictHostKeyChecking=no %s@%s:~/sdfs/%s ./%s", USER_NAME, server.ip().c_str(),
                        remote_file.c_str(), local_file.c_str());
                if (system(exec) == 0)
                    printf("\nFile %s to local successfully\n", local_file.c_str());
                else {
                    printf("\nFile %s not moved locally\n", local_file.c_str());
                    exit(1);
                }
                exit(0);
            }
        } else if ((demo_action.substr(0, 2).compare("ls") == 0)) {
            // list the specified file storage information
            vector<string> file_arg = split(demo_action, ' ');
            string file = file_arg[1];
            string rst;
            // mtx.lock();
            for (auto it = file_config.file_map[file].begin(); it != file_config.file_map[file].end(); ++it) {
                rst += (*it).ip() + "\t";
            }
            // mtx.unlock();
            rst += "\n";
            printf("%s",rst.c_str());
        } else if ((demo_action.substr(0, 6).compare("delete") == 0)) {
            // delete the file across machines
            vector<string> file_arg = split(demo_action, ' ');
            rm_file(file_arg[1]);
        } else if((demo_action.substr(0, 5).compare("maple") == 0)) {
            //maple wc_m 4 pref test.txt
            std::vector<std::string> file_arg = split(demo_action, ' ');
            if(file_arg.size() < 5) continue;

            //std::string sdfs_dir = file_arg[4];
            string exe = file_arg[1];
            int num_maples = std::atoi(file_arg[2].c_str());
            string pref = file_arg[3];

            vector<string> files;
            for(int i = 4; i < file_arg.size(); i++)
                files.emplace_back(file_arg[i]);

            //file_arg[4:] is the list of all the files
            //each of the mid's is responsible for copying and splitting that specific file in it's node
            //this is better b/c the weight is shifted to the specific machine to exec the process
            //this thread serves as a control mechanism in the cases where the server crashes
            bool done[num_maples];
            vector<int> node_assign(num_maples);
            vector<thread> maples(num_maples);

            {
                std::lock_guard<mutex> lk(m);
                for(int i = 0; i < num_maples; i++) {
                    node_assign[i] = get_node_number(members[i % members.size()].ip());
                    done[i] = false;
                    maples[i] = thread(handle_maple, exe, i, node_assign[i], num_maples, files, pref, std::ref(done[i]));
                }
            }

            // execute the maple_exe and in doing so generate a large number of files locally
            bool loop;
            do {
                loop = false;
                // if all of the threads are done then break
                for(bool complete: done) {
                    if(not complete) {
                        loop = true;
                        break; // break from the for loop
                    }
                }
            } while(loop);

            for(int i = 0; i < num_maples; i++) {
                maples[i].join();
            }

            // now merge all the outputs that have the same name
            for(int node: node_assign) {
                char exec[256];
                sprintf(exec, "ssh %s@%s ls ~/mapout/", USER_NAME, get_hostname(node).c_str());
                string output = exec_ret(exec);

                vector<string> files = split(output, '\n');

                for(string file : files) {
                    vector<string> inf = split(file, '_');

                    char exec[256];
                    sprintf(exec, "ssh %s@%s cat ~/mapout/%s >> ~/tmp/%s_%s", USER_NAME, get_hostname(node).c_str(), file.c_str(), pref.c_str(), inf[2].c_str());
                    system(exec);

                    // delete the used files
                    sprintf(exec, "ssh %s@%s rm ~/mapout/%s", USER_NAME, get_hostname(node).c_str(),file.c_str());
                    system(exec);
                }
            }

            char exec[256];
            sprintf(exec, "ls ~/tmp/");
            string output = exec_ret(exec);

            vector<string> files_dir = split(output, '\n');

            for(string file : files_dir) {
                // sleep for a really short time, just to let other things catch up a bit
                // this resolves some issues with flooding the scp ports
                std::this_thread::sleep_for(std::chrono::milliseconds(250));
                put_new_file( "~/tmp/" + file, file);
            }

            // delete the merge tmp files
            sprintf(exec, "rm ~/tmp/*");
            system(exec);

            printf("end maple~!\n");
        } else if ((demo_action.substr(0, 5).compare("juice") == 0)) {
            // juice juice_word.py 4 pref result.txt 0
            vector<string> juice_args = split(demo_action, ' ');

            string exec_name = juice_args[1];
            int num_juices = std::stoi(juice_args[2]);
            string prefix = juice_args[3];
            string dest = juice_args[4];
            bool del_after = (std::stoi(juice_args[5]) == 0) ? false : true;

            // determine where to invoke processes
            vector<string> s;
            vector< pair<int,vector<string>> > jid_info(num_juices, std::make_pair(0,s));
            bool done[num_juices];

            for (int i = 0; i < num_juices; i++) {
                std::lock_guard<mutex> lk(m);
                jid_info[i].first = get_node_number(members[i % members.size()].ip());
                done[i] = false;
            }

            // assign keys / files to jid (juice 'process id')
            assign_files(jid_info, prefix);

            for (auto pair: jid_info) {
                for (string s: pair.second) {
                    printf("%s\n", s.c_str());
                }
            }

            vector<thread> juicers(num_juices);
            // launch a number of threads that move needed files and run juice_exe
            for (int i = 0; i < num_juices; i++) {
                juicers[i] = thread(handle_juice, exec_name, i, jid_info[i].first, jid_info[i].second, std::ref(done[i]) );
            }

            bool loop;
            do {
                loop = false;
                // if all of the threads are done then break
                for(bool complete: done) {
                    if(not complete) {
                        loop = true;
                        break; // break from the for loop
                    }
                }
            } while(loop);

            for(int i = 0; i < num_juices; i++) {
                juicers[i].join();
            }

            // merge the result files into one big file on this machine and add to sdfs
            for(auto pair: jid_info) {
                // look for output files then copy them over locally
                // then use 'cat file1 >> target' over and over to merge files
                char exec[254];
                sprintf(exec, "ssh %s@%s cat tmp/result >> %s", USER_NAME, get_hostname(pair.first).c_str(), dest.c_str());
                if (system(exec) == 0) {
                    printf("\nJMerged successfully\n");
                } else {
                    printf("\nJMerge failed\n");
                }

                char exec_2[254];
                sprintf(exec_2, "ssh %s@%s rm tmp/result", USER_NAME, get_hostname(pair.first).c_str());
                if (system(exec_2) == 0) {
                    printf("\nJDeld successfully\n");
                } else {
                    printf("\nJDel failed\n");
                }
            }

            // add the 'target' file to the sdfs -- have to emulate put code here
            put_new_file(dest, dest);

            remove the file that was just added to the sdfs to make things clean
            char exec[254];
            sprintf(exec, "rm %s", dest.c_str());
            system(exec);

            // if del_after then delete the prefix'd files from the file system
            if(del_after) {
                vector<string> files;

                for(auto &kv : file_config.file_map) {
                    if ( kv.first.substr(0, prefix.size()) == prefix ) {
                        // for every file that has the prefix
                        files.emplace_back(kv.first);
                    }
                }

                for(auto file: files) {
                    rm_file(file);
                }
            }
        } else if ((demo_action.substr(0, 4).compare("push") == 0)) {
            vector<string> file_arg = split(demo_action, ' ');
            put_file(file_arg[1], get_hostname(std::stoi(file_arg[2])));
        } else perror("Invalid demo action. Please type ");

    }

    return 0;
}

/*
 * Cleint side testing function
 * It first leave, then ask to join, and send pings.
 */
int client_talker() {
    sending_pings();
    return 0;
}

/*
 * Checks if file exists on at least min(nmachines,3) machines, if not sends them around
 * TODO: Needs to be checked, "putting" needs to be implemented
 */
void file_checking() {
    // for every file
    // if you own the file
    // if there are less than min(nm, 3) nodes w/ the file
    // send the file to any other nodes that don't have the file

    // mtx.lock();
    for(auto& kv : file_config.file_map) {
        if(kv.second.size() >= 3) continue;

        bool in_machine = false;
        bool have_priority = true;
        // check if the file is in the machine
        for(auto& v : kv.second) {
            if (v.ip() == node_id.ip()) {
                in_machine = true;
            }

            //get the vmnumber of the current node and
            int vm = get_node_number(v.ip());

            // if there's a machine w/ a lower vm number then we don't have prio
            // note: this is a simple workaround for leader using leader election
            if (node_number > vm)
                have_priority = false;
        }

        {
            std::lock_guard<mutex> lk(m);
            if (have_priority && in_machine && std::min((int) members.size(),3) > kv.second.size()) {
                for(auto &member : members) {

                    bool has_file = false;
                    // check if the machine already has the file
                    for(auto &mm : kv.second) {
                        if(member.ip() == mm.ip()) {
                            has_file = true;
                            break;
                        }
                    }


                    // if it doesn't have the file
                    if (!has_file) {
                        // put the file on to the machine!
                        file_add(kv.first, member.ip());

                        string msg;
                        msg += "FPUT" + kv.first;
                        msg += "#" + member.ip();

                        if(node_id.ip() != member.ip()) {
                            char exec[180];
                            sprintf(exec, "scp -o StrictHostKeyChecking=no ~/sdfs/%s %s@%s:~/sdfs/%s", kv.first.c_str(), USER_NAME,
                                    member.ip().c_str(),
                                    kv.first.c_str());
                            if (system(exec) == 0)
                                printf("\nFile %s moved successfully\n", kv.first.c_str());
                            else {
                                printf("\nFile %s not moved successfully\n", kv.first.c_str());
                            }
                        }

                        sending_info_to_all_nodes(node_id, msg, false);

                        printf("%s", file_config.Serialize().c_str());

                        if (file_config.file_map[kv.first].size() >= std::min((int) members.size(),3))
                            break;

                    }
                } // end inner for loop on active machine list
            } // end if statement
        } // end mutex
    } // end outermost for loop (by file)
    // mtx.unlock();
}

/*
 * Node that receives and execute correpsonding message
 *
 */
int server_listening() {
    int sockfd;
    struct addrinfo hints, *servinfo, *p;
    int rv;
    int numbytes;
    int numbytes2;
    struct sockaddr_storage their_addr;
    char buf[MAXBUFLEN];
    socklen_t addr_len;
    char s[INET6_ADDRSTRLEN];
    string message = "ack";

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // set to AF_INET to force IPv4
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE; // use my IP

    if ((rv = getaddrinfo(node_IP.c_str(), node_port.c_str(), &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    // loop through all the results and bind to the first we can
    for (p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            perror("listener: socket");
            continue;
        }

        if (::bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("listener: bind");
            continue;
        }

        break;
    }

    if (p == NULL) {
        fprintf(stderr, "listener: failed to bind socket\n");
        return 2;
    }

    printf("listener: waiting to recvfrom...\n");

    while (1) { // main accept() loop
        addr_len = sizeof their_addr;
        if ((numbytes = recvfrom(sockfd, buf, MAXBUFLEN - 1, 0, (struct sockaddr *) &their_addr, &addr_len)) == -1) {
            perror("recvfrom");
            exit(1);
        }

        inet_ntop(their_addr.ss_family,
                  get_in_addr((struct sockaddr *) &their_addr), s, sizeof s);

        buf[numbytes] = '\0';
        string bufst = string(buf);

        // getting the first four characters of the received packet

        if (bufst.substr(0, 4) == "JOIN") {
            // If the node receives the "JOIN" message, then it is an INTRODUCER NODE
            // message in the format "JOIN:IP:Port Number"

            // printf("Received a JOIN request: \"%s\"\n", bufst.c_str());

            // Get the current timestamp
            auto milliseconds_nodeid_time_stamp = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();

            // Parse the message
            vector<string> after_split = split(bufst, ':');

            ID new_id;
            new_id.values = std::make_pair(milliseconds_nodeid_time_stamp, after_split[1]);
            const string new_port = after_split[2];

            // sending message in the format node_id#membership_list
            // node_id#nodeNum1:IP1:port1;nodeNum2:IP2:port2 .......
            // e.g. on 2nd machine's JOIN request, it sends "2#1:IP1:port1"

            message = new_id.Serialize();

            // If the introducer node has left and the JOIN request is from some other
            // node (other than itself) it must be ignored
            // So, when introducer node has left, it should only take into account its
            // own join request
            if (hasLeft && new_id.ip() != introducer_IP) {
                continue;
            }

            {
                std::lock_guard<mutex> lk(m);
                members.push_back(new_id);
                mapping[new_id] = new_port; // filling map
                printing_the_map();
                message += "#" + serialize_map();
            }

            printf("Updated map \n");

            // this is the child process
            if (!fork()) {

                // Send the newly joined node information to all other nodes.
                if ((numbytes2 = sendto(sockfd, message.c_str(), message.length(), 0, (struct sockaddr *) &their_addr, addr_len)) == -1) {
                    perror("server sending error");
                    close(sockfd);
                    exit(1);
                }//lxb

                string message2 = "NEWJ#" + new_id.Serialize() + ":" + new_port;
                // calling a function to send other nodes information about the new node
                sending_info_to_all_nodes(new_id, message2, false);
                close(sockfd);
                exit(0);
            }

            // TODO: check if all files are in at least 3 machines, if not send them to other machines
            // file_checking();
        }

        // If a node receives a PING message
        // then it sends back a ACKK message to the sender
        if (bufst.substr(0, 4) == "PING") {
            // If the node has left, it should not take account of these messages
            if (hasLeft) {
                continue;
            }
            // A NORMAL NODE receives a PING request
            // printf("Received a PING message: \"%s\"\n", bufst.c_str());
            const ID pinged_id(ID::Deserialize(split(bufst, '#')[1]));
            if (pinged_id != node_id) {
                continue;
            }
            message = "ACKK";
            if ((numbytes2 = sendto(sockfd, message.c_str(), message.length(), 0,
                                    (struct sockaddr *) &their_addr, addr_len)) == -1) {
                perror("Server sending error: acknowledgement on ping");
                printf("Sending ACKK acknowledgement back\n");
                close(sockfd);
                exit(1);
            }//lxb how to distinguish sending socket and receiving socket
        }

        // NORMAL NODE
        // Receiving message about a new node having joined the group
        if (bufst.substr(0, 4) == "NEWJ") {
            // If the node has left, it should not take account of these messages
            if (hasLeft) {
                continue;
            }

            printf("Received a new node request: \"%s\"\n", bufst.c_str());
            // the node must be added to the membership list
            // (i.e. a vector) and an entry of it must be added
            // The received message is in the following format: "NEWJ#node_id:IP:port"
            // "node_id:IP:port"
            string nodeIdIpPort = bufst.substr(5);
            // printf("new_node_id_port = %s\n", nodeIdIpPort.c_str());

            // Parse the received message
            // Output is in the following foramt: <node_id, IP, port are now split>
            vector<string> after_split = split(nodeIdIpPort, ':');
            const ID new_node_id(ID::Deserialize(nodeIdIpPort));
            //printf("new_node_id = %s\n", new_node_id.Serialize().c_str());
            string new_node_port = after_split[2];
            //printf("new_node_port = %s\n", new_node_port.c_str());

            {
                std::lock_guard<mutex> lk(m);
                printf("BEFORE Adding the new node:\n");
                printing_members();
                members.push_back(new_node_id);
                mapping[new_node_id] = new_node_port;
                printf("AFTER Adding the new node:\n");
                printing_members();
            }
        }

        // NORMAL NODE receiving message about a node failing/leaving
        // Then the node must be removed from the members vector and from the
        // mapping
        if (bufst.substr(0, 4) == "FAIL" || bufst.substr(0, 4) == "LEAV") {
            // If the node has left, it should not take account of these messages
            if (hasLeft) {
                continue;
            }
            // message is in the format: "FAIL#failed_node_id" or
            // "LEAV#leaving_node_id"
            printf("Received a %s request\n", bufst.substr(0, 4).c_str());

            string nodeIdIpPort = bufst.substr(5);
            // "failed_node_id" or "leaving_node_id"
            // printf("failed or leaving node_id_port = %s\n", nodeIdIpPort.c_str());
            ID fail_node = ID::Deserialize(nodeIdIpPort);
            const ID remove_node_id(fail_node);
            // printf("failed or leaving node_id = %s\n", remove_node_id.Serialize().c_str());

            // string failed_node_IP = mapping[failed_node_id].first;
            // printf("failed_node_IP = %s\n", failed_node_IP.c_str());
            // string fail_node_port = mapping[failed_node_id].second;
            // printf("failed_node_port = %s\n", fail_node_port.c_str());

            {
                std::lock_guard<mutex> lk(m);
                printf("BEFORE Removing the Node\n");
                printing_the_map();
                for (auto it = members.begin(); it != members.end(); ++it) {
                    if (*it == remove_node_id) {
                        members.erase(it);
                        break;
                    }
                }
                mapping.erase(remove_node_id);
                printf("AFTER Removing the Node\n");
                printing_the_map();
            }

            // TODO: check if all files are in at least 3 machines, if not send them to other machines

            {
                std::lock_guard<mutex> lk(m);
                for (auto &file_entry : file_config.file_map) {
                    vector<ID> update_id;
                    for (auto it = file_entry.second.begin(); it != file_entry.second.end(); ++it) {
                        if ((*it).ip() != fail_node.ip()) {
                            update_id.emplace_back((*it));
                        }
                    }
                    file_entry.second = update_id;
                }
            }

            string msg = "REMOVE" + fail_node.ip();
            sending_info_to_all_nodes(node_id, msg, false);


            file_checking();

        }

        if(bufst.substr(0, 6) == "REMOVE") {
            printf("Received remove failed node id information: %s \n", bufst.c_str());

            string fail_node = bufst.substr(6);

            // mtx.lock();
            for (auto &file_entry : file_config.file_map) {
                for(auto &id: file_entry.second) {
                    if (id.ip() == fail_node)
                        id.values.first = 1;
                }
            }
            // mtx.unlock();

            file_checking();
        }

        //mp3 : handle the fput information and update the file table
        if (bufst.substr(0, 4) == "FPUT") {
            printf("Received fput file information: %s \n", bufst.c_str());

            vector<string> file_vec = split(bufst.substr(4), '#');
            // FT *file_p = &file_config;
            string fname = file_vec[0];
            file_vec.erase(file_vec.begin());

            for (auto &ip: file_vec) {
                file_add(fname, ip);
            }

        }

        if(bufst.substr(0, 4) == "FDEL") {
            // delete file if it exists locally and update file table
            printf("Received fdel file information: %s \n", bufst.c_str());
            string file = bufst.substr(4, bufst.length());
            // check if file exists locally, if it does then delete it
            if (file_config.file_map.find(file) == file_config.file_map.end()) {
                printf("the file does not exist at all actually...");
            } else {
                for(ID id: file_config.file_map[file]) {
                    // check if the file is in the current machine's ip
                    if (id.ip() == node_id.ip()) {
                        // the file exists in the machine! <I think, could use a second opinion>

                        char exec[180];
                        sprintf(exec, "rm ~/sdfs/%s", file.c_str());
                        if (system(exec) == 0)
                            printf("\nFile %s deleted successfully", file.c_str());
                        else
                            printf("\nFile %s not deleted\n", file.c_str());
                        break;
                    }
                }
                // update local file table by removing the specified file entry
            }

            file_del(file);
        }
    }
    freeaddrinfo(servinfo);
    close(sockfd);
    return 0;
}

/*
 * Input: the vm_number
 * Output: the corresponding remote host
 */
string generate_ip(string vm_number) {
    string node_vmname;
    string vmnumber;
    int vm = std::stoi(vm_number);
    if (vm < 10) {
        vmnumber = "0" + std::to_string(vm);
    } else {
        vmnumber = "10";
    }
    node_vmname = "fa16-cs425-g19-" + vmnumber + ".cs.illinois.edu";//lxb
    return node_vmname;
}

int main(int argc, char *argv[]) {

    if (argc != 5) {
        fprintf(stderr, "usage: talker introducer_vm introducer_port_no. node_vm "
                "node_port_no.\n");
        exit(1);
    }

    // Parse the arguments and store to the corresponing global variables.
    string vm_introducer = argv[1];
    introducer_IP = generate_ip(vm_introducer);
    introducer_port = argv[2];
    string vm_node = argv[3];

    // set global variable for program's node number
    node_number = std::stoi(vm_node);

    node_IP = generate_ip(vm_node);
    node_port = argv[4];
    //leaving_time = std::stoi(argv[5]);
    //joining_back_time = std::stoi(argv[6]);

    // Output to the log
    /**
    string temp = "machine." + vm_node + ".log";
    const char* file_name = temp.c_str();
    freopen(file_name, "w", stdout);
    **/

    thread third(demo_action);
    // Multi thread
    thread first(server_listening);
    thread second(client_talker);
    // thread fourth(send_file_to_client());
    first.join();
    second.join();
    third.join();
    // fourth.join();
    return 0;
}