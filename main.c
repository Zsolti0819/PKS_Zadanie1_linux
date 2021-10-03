#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <pcap/pcap.h>

char**** categories[3][4][7][10];

struct IP_header {
    char* src_ip_addr;
    int tx_packets;
    bool is_tcp_packet;
    struct IP_header* next;
};

struct packet {
    int frame_number;
    char* src_ip_addr;
    char* dst_ip_addr;
    char* src_port;
    char* dst_port;
    char* flag;
    bool pass;
    struct packet* next;
};

// pomocna funkcia na vkladanie uzlov do spajaneho zoznamu
void insert_packet_to_ll(struct packet **head_ref, char* src_ip_addr, char* dst_ip_addr, char* src_port, char* dst_port, char* flag, int frame_number) {
    struct packet* new_node = malloc(sizeof(struct packet));
    struct packet* last = *head_ref;
    new_node->src_ip_addr = src_ip_addr;
    new_node->dst_ip_addr = dst_ip_addr;
    new_node->src_port = src_port;
    new_node->dst_port = dst_port;
    new_node->flag = flag;
    new_node->frame_number = frame_number;
    new_node->pass = false;
    new_node->next = NULL;

    if (*head_ref == NULL) {
        *head_ref = new_node;
        return;
    }

    while (last->next != NULL)
        last = last->next;

    last->next = new_node;
}

// vypis spajaneho zoznamu
void print_packet(struct packet *node) {
    printf("%s\n", node->flag);
    printf("%d\n", node->frame_number);
    printf("%s\n", node->src_ip_addr);
    printf("%s\n", node->dst_ip_addr);
    printf("%s\n", node->src_port);
    printf("%s\n", node->dst_port);
    printf("\n=============================================================\n");
}

// pomocna funkcia na vkladanie uzlov do spajaneho zoznamu
void insert_src_ip_to_ll(struct IP_header **head_ref, char *ip_address, bool is_tcp) {
    struct IP_header* new_node = malloc(sizeof(struct IP_header));
    struct IP_header* last = *head_ref;
    new_node->src_ip_addr = ip_address;
    new_node->tx_packets = 1;
    new_node->is_tcp_packet = is_tcp;
    new_node->next = NULL;

    if (*head_ref == NULL) {
        *head_ref = new_node;
        return;
    }

    while (last->next != NULL)
        last = last->next;

    last->next = new_node;
}

// vypis spajaneho zoznamu
void print_ll(struct IP_header *node) {
    while (node != NULL) {
        if (node->is_tcp_packet)
            printf("%s\n", node->src_ip_addr);
        node = node->next;
    }
}

void print_ip_with_the_most_packets_sent(struct IP_header *start) {
    struct IP_header* temp = start;
    struct IP_header* temp2 = NULL;

    int max = 0;
    while (temp != NULL) {
        if (temp->tx_packets > max) {
            temp2 = temp;
            max = temp->tx_packets;
        }
        temp = temp->next;
    }
    if (temp2 != NULL)
        printf("Adresa uzla s najvacsim poctom odoslanych paketov:\n%s\t%d paketov\n", temp2->src_ip_addr, temp2->tx_packets);
}

// vymazanie vsetkych uzlov
void delete_ll(struct IP_header** head_ref) {
    struct IP_header* temp = *head_ref;
    struct IP_header* next;

    while (temp != NULL) {
        next = temp->next;
        free(temp);
        temp = next;
    }

    *head_ref = NULL;
}

// hladanie v spajanom zozname
bool search_in_ll(struct IP_header* head, char* data) {
    struct IP_header* temp = head;
    while (temp != NULL) {
        if (strcmp(temp->src_ip_addr, data) == 0) {
            temp->tx_packets++;
            return true;
        }
        temp = temp->next;
    }
    return false;
}

// vypis menu
void print_menu() {
    printf("\n=============================================================\n");
    printf("Vyberte o ktory vypis mate zaujem (zadajte cislo):\n");
    printf("0 - Koniec\n");
    printf("1 - Vypis vsetkych komunikacii\n");
    printf("2 - Vypis komunikacii podla protokolu (viacere moznosti)\n");
    printf("3 - Doimplementacia\n");
    printf("\n=============================================================\n");
}

// pomocna funkcia, pouzivana pri menu
void seek_to_next_line(void) {
    int c;
    while ((c = fgetc(stdin)) != EOF && c != '\n');
}

// zakladne informacie, pouzivane v bode 1.
void print_basic_info(int frame, int caplen, int len) {
    printf("ramec %i\n", frame);
    printf("dlzka ramca poskytnuta pcap API - %d B\n", caplen);
    len = len + 4;
    if (len < 64)len = 64;
        printf("dlzka ramca prenasaneho po mediu - %d B", len);
}

// vypis MAC adresy
void print_MAC_address(const u_char *packet) {
    printf("\nZdrojova MAC adresa: ");
    for (int i = 6; i < 12; i++)
        printf("%.2X ", packet[i]);

    printf("\nCielova MAC adresa: ");
    for (int i = 0; i < 6; i++)
        printf("%.2X ", packet[i]);

    printf("\n");
}

// vypis IP adresy
void print_IP_adress(const u_char *packet) {
    printf("zdrojova IP adresa: %d.%d.%d.%d\n", packet[26], packet[27], packet[28], packet[29]);
    printf("cielova IP adresa: %d.%d.%d.%d\n", packet[30], packet[31], packet[32], packet[33]);
}

// formalny vypis v hexa tvare, pouzivan v bode 1.
void print_hexadecimal(int i, const u_char *packet) {
    int move;
    for (move = 0; (move < i); move++) {
        if ((move % 8) == 0 && (move % 16) != 0)
            printf(" ");

        if ((move % 16) == 0)
            printf("\n");

        printf("%.2x ", packet[move]);
    }
    printf("\n");
}

// vypis zdrojoveho a cieloveho portu
void print_src_port_and_dst_port(const u_char *packet) {
    printf("zdrojovy port: %d\ncielovy port: %d\n", packet[34] * 256 + packet[35], packet[36] * 256 + packet[37]);
}

// funckia vrati zdrojovu IP adresu vo formate char *
char* get_src_ip(const u_char* packet) {
    char* src_ip_addr;
    src_ip_addr = malloc(sizeof(u_char) * 20);
    sprintf(src_ip_addr, "%d.%d.%d.%d", packet[26], packet[27], packet[28], packet[29]);
    return src_ip_addr;
}

// funckia vrati cielovu IP adresu vo formate char *
char* get_dst_ip(const u_char* packet) {
    char* dst_ip_addr;
    dst_ip_addr = malloc(sizeof(u_char) * 20);
    sprintf(dst_ip_addr, "%d.%d.%d.%d", packet[30], packet[31], packet[32], packet[33]);
    return dst_ip_addr;
}

char* get_src_port(const u_char* packet) {
    char* src_port;
    src_port = malloc(sizeof(u_char) * 20);
    sprintf(src_port, "%d", packet[34] * 256 + packet[35]);
    return src_port;

}

char* get_dst_port(const u_char* packet) {
    char* dst_port;
    dst_port = malloc(sizeof(u_char) * 20);
    sprintf(dst_port, "%d", packet[36] * 256 + packet[37]);
    return dst_port;

}

// funkcia vrati retazec s obsahom typom je ramca
char* get_frame_type(const u_char* packet) {
    if (packet[12] * 256 + packet[13] > 0x5DC)
        return "Ethernet II";
    else
        return "802.3";
}

char* get_tcp_flag(const u_char* packet) {
    if (packet[47] == 0x002)
        return "SYN";
    else if (packet[47] == 0x012)
        return "SYN, ACK";
    else if (packet[47] == 0x010)
        return "ACK";
    else if (packet[47] == 0x011 || packet[47] == 0x019)
        return "FIN, ACK";
    else if (packet[47] == 0x018)
        return "PSH, ACK";
    return NULL;
}

// nasledujuce funkcie su podobne, ale kazdy pracuje s inym suborom, a vracia nejaku hodnotu vycitaneho zo subor
char* get_ether_type(const u_char* packet, FILE* ethertypes) {
    int value_in_the_file = 0;
    int real_value = packet[12] * 256 + packet[13];
    rewind(ethertypes);
    char c;
    char ethertype_buff[50] = { 0 };
    int i = 0;

    while ((c = getc(ethertypes)) != '-') {
        if (c == '#') {
            fscanf(ethertypes, "%x", &value_in_the_file);
            if (real_value == value_in_the_file) {
                while ((c = getc(ethertypes)) != '\n')
                    if (c != '\t')
                        ethertype_buff[i++] = c;
                break;
            }
        }
    }
    char* ethertype;
    ethertype = malloc(sizeof(u_char) * i);
    sprintf(ethertype, "%s", ethertype_buff);
    return ethertype;
}

char* get_protocol(const u_char* packet, FILE* ip_protocols) {
    int value_in_the_file = 0;
    int real_value = packet[23];
    rewind(ip_protocols);
    char c;
    char protocol_buff[50] = { 0 };
    int i = 0;

    while ((c = getc(ip_protocols)) != '-') {
        if (c == '#') {
            fscanf(ip_protocols, "%x ", &value_in_the_file);
            if (real_value == value_in_the_file) {
                while ((c = getc(ip_protocols)) != '\n')
                    if (c != '\t')
                        protocol_buff[i++] = c;
                break;
            }
        }
    }
    char* protocol;
    protocol = malloc(sizeof(u_char) * i);
    sprintf(protocol, "%s", protocol_buff);
    return protocol;
}

char* get_tcp_or_udp_port(const u_char* packet, FILE* file_w_ports) {
    int value_in_the_file = 0;

    int src_real_value = packet[34] * 256 + packet[35];
    int dst_real_value = packet[36] * 256 + packet[37];
    rewind(file_w_ports);
    char c;
    char tcp_port_buff[50] = { 0 };
    int i = 0;

    while ((c = getc(file_w_ports)) != '-') {
        if (c == '#') {
            fscanf(file_w_ports, "%x", &value_in_the_file);
            if (src_real_value == value_in_the_file || dst_real_value == value_in_the_file) {
                while ((c = getc(file_w_ports)) != '\n')
                    if (c != '\t')
                        tcp_port_buff[i++] = c;
                break;
            }
        }
    }
    char* tcp_port;
    tcp_port = malloc(sizeof(u_char) * i);
    sprintf(tcp_port, "%s", tcp_port_buff);

    return tcp_port;
}

char* get_icmp_port(const u_char* packet, FILE* icmp_ports) {
    int value_in_the_file = 0;

    int real_value = packet[34];

    rewind(icmp_ports);
    char c;
    char icmp_port_buff[50] = { 0 };
    int i = 0;

    while ((c = getc(icmp_ports)) != '-') {
        if (c == '#') {
            fscanf(icmp_ports, "%x", &value_in_the_file);
            if (real_value == value_in_the_file) {
                while ((c = getc(icmp_ports)) != '\n')
                    if (c != '\t')
                        icmp_port_buff[i++] = c;
                break;
            }
        }
    }
    char* icmp_port;
    icmp_port = malloc(sizeof(u_char) * i);
    sprintf(icmp_port, "%s", icmp_port_buff);

    return icmp_port;
}

char* get_arp_value(const u_char* packet, FILE* arp_file) {
    int value_in_the_file = 0;

    int real_value = packet[20] * 256 + packet[21];
    rewind(arp_file);
    char c;
    char arp_buff[50] = { 0 };
    int i = 0;

    while ((c = getc(arp_file)) != '-') {
        if (c == '#') {
            fscanf(arp_file, "%x", &value_in_the_file);
            if (real_value == value_in_the_file) {
                while ((c = getc(arp_file)) != '\n')
                    if (c != '\t')
                        arp_buff[i++] = c;
                break;
            }
        }
    }
    char* arp_value;
    arp_value = malloc(sizeof(u_char) * i);
    sprintf(arp_value, "%s", arp_buff);

    return arp_value;

}

char* get_802_3_value(const u_char* packet, FILE* _802_03_file)
{
    int value_in_the_file = 0;

    int real_value1 = packet[14];
    int real_value2 = packet[15];
    rewind(_802_03_file);
    char c;
    char eighthundredtwo_three_buff[50] = { 0 };
    int i = 0;

    while ((c = getc(_802_03_file)) != '-') {
        if (c == '#') {
            fscanf(_802_03_file, "%x", &value_in_the_file);
            if (real_value1 == value_in_the_file && real_value2 == value_in_the_file) {
                while ((c = getc(_802_03_file)) != '\n')
                    if (c != '\t')
                        eighthundredtwo_three_buff[i++] = c;
                break;
            }
        }
    }
    char* eighthundredtwo_three_value;
    eighthundredtwo_three_value = malloc(sizeof(u_char) * i);
    sprintf(eighthundredtwo_three_value, "%s", eighthundredtwo_three_buff);

    return eighthundredtwo_three_value;
}

void open_txt_files(FILE **_802_3, FILE **ethertypes, FILE **ip_protocols, FILE **tcp_ports, FILE **udp_ports, FILE **icmp_ports, FILE **arp_operation, FILE **sap_file) {
    if (((*_802_3) = fopen("/home/zsolti/CLionProjects/PKS_Z1/txt/802_3.txt", "r")) == NULL) printf("Chyba pri otvoreni 802_3.txt suboru.\n");
    if (((*ethertypes) = fopen("/home/zsolti/CLionProjects/PKS_Z1/txt/ethertypes.txt", "r")) == NULL) printf("Chyba pri otvoreni ethertypes.txt suboru.\n");
    if (((*ip_protocols) = fopen("/home/zsolti/CLionProjects/PKS_Z1/txt/ip_protocols.txt", "r")) == NULL) printf("Chyba pri otvoreni ip_protocols.txt suboru.\n");
    if (((*tcp_ports) = fopen("/home/zsolti/CLionProjects/PKS_Z1/txt/tcp_ports.txt", "r")) == NULL) printf("Chyba pri otvoreni tcp_ports.txt suboru.\n");
    if (((*udp_ports) = fopen("/home/zsolti/CLionProjects/PKS_Z1/txt/udp_ports.txt", "r")) == NULL) printf("Chyba pri otvoreni udp_ports.txt suboru.\n");
    if (((*icmp_ports) = fopen("/home/zsolti/CLionProjects/PKS_Z1/txt/icmp_ports.txt", "r")) == NULL) printf("Chyba pri otvoreni icmp_ports.txt suboru.\n");
    if (((*arp_operation) = fopen("/home/zsolti/CLionProjects/PKS_Z1/txt/arp_values.txt", "r")) == NULL) printf("Chyba pri otvoreni arp_values.txt suboru.\n");
    if (((*sap_file) = fopen("/home/zsolti/CLionProjects/PKS_Z1/txt/sap_file.txt", "r")) == NULL) printf("Chyba pri otvoreni sap_file.txt suboru.\n");
}

void fill_categories_mda() {
    int i, j, k, l;
    for (i = 0; i < 3; i++)
        for (j = 0; j < 4; j++)
            for (k = 0; k < 7; k++)
                for (l = 0; l < 10; l++)
                    strcpy((char *) &categories[i][j][k][l], "-");
    strcpy((char *) &categories[1][0][0][0], "IPv4");
    strcpy((char *) &categories[1][1][0][0], "TCP");
    strcpy((char *) &categories[1][1][1][0], "FTP DATA");
    strcpy((char *) &categories[1][1][2][0], "FTP CONTROL");
    strcpy((char *) &categories[1][1][3][0], "SSH");
    strcpy((char *) &categories[1][1][4][0], "TELNET");
    strcpy((char *) &categories[1][1][5][0], "HTTP");
    strcpy((char *) &categories[1][1][6][0], "HTTPS");
    strcpy((char *) &categories[1][2][0][0], "UDP");
    strcpy((char *) &categories[1][2][1][0], "TFTP");
    strcpy((char *) &categories[1][3][0][0], "ICMP");
    strcpy((char *) &categories[2][0][0][0], "ARP");
}

void verify_termination(struct packet *temp4, struct packet *temp5, struct packet *temp6, struct packet *temp7,
                        int temp_frame_number, const char *temp_src_port) {
    while (temp4 != NULL) {
        if (temp_frame_number < temp4->frame_number && temp4->pass == false && strcmp(temp_src_port, temp4->dst_port) == 0 && strcmp(temp4->flag, "FIN, ACK") == 0) {
            printf("TEST\n");
            while (temp5 != NULL) {
                if (temp4->frame_number < temp5->frame_number && temp4->pass == false && temp5->pass == false && strcmp(temp4->dst_port, temp5->src_port) == 0 && strcmp(temp5->flag, "ACK") == 0) {
                    while (temp6 != NULL) {
                        if (temp5->frame_number < temp6->frame_number && temp4->pass == false && temp5->pass == false && temp6->pass == false && strcmp(temp5->src_port, temp6->src_port) == 0 && strcmp(temp5->dst_port, temp6->dst_port) == 0 && strcmp(temp6->flag, "FIN, ACK") == 0) {
                            while (temp7 != NULL) {
                                if (temp6->frame_number < temp7->frame_number && temp4->pass == false && temp5->pass == false && temp6->pass == false && temp7->pass == false && strcmp(temp6->src_port, temp7->dst_port) == 0 && strcmp(temp6->dst_port, temp7->src_port) == 0 && strcmp(temp7->flag, "ACK") == 0) {
                                    temp4 -> pass = true;
                                    temp5 -> pass = true;
                                    temp6 -> pass = true;
                                    temp7 -> pass = true;

//                                    print_packet(temp4);
//                                    print_packet(temp5);
//                                    print_packet(temp6);
//                                    print_packet(temp7);
                                    return;
                                }
                                temp7 = temp7->next;
                            }
                        }
                        temp6 = temp6->next;
                    }
                }
                temp5 = temp5->next;
            }
        }
        temp4 = temp4->next;
    }
}

char * verify_3WHS(struct packet *temp, struct packet *temp2, struct packet *temp3) {
    while (temp != NULL) {
        if (strcmp(temp -> flag, "SYN") == 0 && temp -> pass == false) {
            while (temp2 != NULL) {
                if (temp -> pass == false && temp2 -> pass == false && temp -> frame_number < temp2 -> frame_number && strcmp(temp->src_port, temp2->dst_port) == 0 && strcmp(temp->dst_port, temp2->src_port)  == 0 && strcmp(temp2->flag, "SYN, ACK") == 0) {
                    while (temp3 != NULL) {
                        if (temp -> pass == false && temp2 -> pass == false && temp3-> pass == false && temp2 -> frame_number < temp3 -> frame_number && strcmp(temp2->src_port, temp3->dst_port) == 0 && strcmp(temp2->dst_port, temp3->src_port)  == 0 && strcmp(temp3->flag, "ACK") == 0) {
                            temp -> pass = true;
                            temp2 -> pass = true;
                            temp3 -> pass = true;

//                            print_packet(temp);
//                            print_packet(temp2);
//                            print_packet(temp3);

                            char *_3whs_syn = malloc(sizeof(u_char) * 20);
                            sprintf(_3whs_syn, "%d %s", temp -> frame_number, temp -> src_port);
                            return _3whs_syn;
                        }
                        temp3 = temp3 -> next;
                    }
                }
                temp2 = temp2-> next;
            }
        }
        temp = temp -> next;
    }
    return "0 0";
}

int main() {

    char* file_name = { "/home/zsolti/CLionProjects/PKS_Z1/vzorky_pcap_na_analyzu/trace-10.pcap" }; // sem vlozit subor
    char pcap_file_error[PCAP_ERRBUF_SIZE];
    pcap_t* pcap_file;

    FILE *_802_3;
    FILE *ethertypes;
    FILE *ip_protocols;
    FILE *tcp_ports;
    FILE *udp_ports;
    FILE *icmp_ports;
    FILE *arp_operation;
    FILE *sap_file;
    open_txt_files(&_802_3, &ethertypes, &ip_protocols, &tcp_ports, &udp_ports, &icmp_ports, &arp_operation, &sap_file);

    struct pcap_pkthdr* pcap_header;
    const u_char* packet;
    struct IP_header* head = NULL;
    struct packet* packet_head = NULL;
    int frames = 0;
    int choice;

    do {
        print_menu();
        scanf("%d", &choice);
        seek_to_next_line();
        switch (choice) {
            case 1: {

                if ((pcap_file = pcap_open_offline(file_name, pcap_file_error)) == NULL) {
                    printf("Chyba pri otvoreni PCAP suboru.");
                    exit(0);
                }

                while ((pcap_next_ex(pcap_file, &pcap_header, &packet)) >= 0) {
                    frames++;
                    char* frame_type = get_frame_type(packet);
                    char* ethertype_buff = get_ether_type(packet, ethertypes);
                    char* protocol_buff;
                    char* _802_3_buff = get_802_3_value(packet, _802_3);

                    // Je 802.3
                    if (strcmp(frame_type, "802.3") == 0) {

                        // ramec cislo x, dlzky ramca
                        print_basic_info(frames, pcap_header->caplen, pcap_header->len);

                        // 802.3
                        printf("\n%s", frame_type);

                        if (strcmp(_802_3_buff, "SNAP") == 0 || strcmp(_802_3_buff, "Global DSAP") == 0) {

                            // 802.3 SNAP + LLC
                            if (strcmp(_802_3_buff, "SNAP") == 0)
                                printf(" LLC + %s", _802_3_buff);
                            
                            // 802.3 Global DSAP (?)
                            else
                                printf("%s", _802_3_buff);

                        }

                        // 802.3 RAW
                        else
                            printf(" RAW");
                        
                        print_MAC_address(packet);
                    }

                    // Je Ethernet II
                    else if (strcmp(frame_type, "Ethernet II") == 0) {
                        // Je ARP, vypiseme ARP-Request/Reply,IP, MAC
                        if (strcmp(ethertype_buff, "ARP") == 0) {
                            protocol_buff = get_protocol(packet, arp_operation);
                            char* arp_buff = get_arp_value(packet, arp_operation);
                            char arp_dst_ip[20];
                            char arp_src_ip[20];

                            char arp_src_mac[50];
                            char arp_dst_mac[50];

                            sprintf(arp_dst_ip, "%d.%d.%d.%d", packet[38], packet[39], packet[40], packet[41]);
                            sprintf(arp_src_ip, "%d.%d.%d.%d", packet[28], packet[29], packet[30], packet[31]);
                            sprintf(arp_dst_mac, "%.2X %.2X %.2X %.2X %.2X %.2X ", packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]);
                            sprintf(arp_src_mac, "%.2X %.2X %.2X %.2X %.2X %.2X ", packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);

                            // Request
                            if (strcmp(arp_buff, "Request") == 0) {
                                printf("%s-%s, IP Adresa: %s, MAC Adresa: %s\n", ethertype_buff, arp_buff, arp_dst_ip, arp_dst_mac);
                                printf("Zdrojova IP: %s, Cielova IP: %s", arp_src_ip, arp_dst_ip);
                            }

                            // Reply
                            else {
                                printf("%s-%s, IP Adresa: %s, MAC Adresa: %s\n", ethertype_buff, arp_buff, arp_src_ip, arp_src_mac);
                                printf("Zdrojova IP: %s, Cielova IP: %s", arp_src_ip, arp_dst_ip);
                            }

                            printf("%s\n", protocol_buff);

                        }

                        // Je IP, pokracujeme, len ulozime aky ma protokol
                        else
                            protocol_buff = get_protocol(packet, ip_protocols);

                        // ramec cislo x, dlzky ramca
                        print_basic_info(frames, pcap_header->caplen, pcap_header->len);

                        // Ethernet II
                        printf("\n%s", frame_type);

                        // MAC adresy
                        print_MAC_address(packet);
                        printf("%s\n", ethertype_buff);

                        // Je IP
                        if (strcmp(ethertype_buff, "ARP") != 0)
                            print_IP_adress(packet);

                        printf("%s\n", protocol_buff);

                        char* src_ip_buff;
                        src_ip_buff = get_src_ip(packet);
                        if ((strcmp(ethertype_buff, "IPv4") == 0)  && search_in_ll(head, src_ip_buff) == false) {
                            if (strcmp(protocol_buff, "TCP") == 0)
                                insert_src_ip_to_ll(&head, get_src_ip(packet), true);
                            else
                                insert_src_ip_to_ll(&head, get_src_ip(packet), false);
                        }

                        char* port_buff;
                        if (strcmp(protocol_buff, "TCP") == 0) {
                            port_buff = get_tcp_or_udp_port(packet, tcp_ports);
                            printf("%s\n", port_buff);
                            print_src_port_and_dst_port(packet);
                        }

                        else if (strcmp(protocol_buff, "UDP") == 0) {
                            port_buff = get_tcp_or_udp_port(packet, udp_ports);
                            printf("%s\n", port_buff);
                            print_src_port_and_dst_port(packet);
                        }

                        else if (strcmp(protocol_buff, "ICMP") == 0) {
                            port_buff = get_icmp_port(packet, icmp_ports);
                            printf("%s\n", port_buff);
                            print_src_port_and_dst_port(packet);
                        }
                    }

                    print_hexadecimal(pcap_header->len, packet);
                    printf("\n=============================================================\n");

                }
                printf("IP adresy vysielajucich uzlov:\n");
                print_ll(head);
                print_ip_with_the_most_packets_sent(head);
                pcap_close(pcap_file);
                delete_ll(&head);
                frames = 0;
                break;
            }

            /* pocet ramcov nesmie byt viac ako 20 */
            case 2: {

                if ((pcap_file = pcap_open_offline(file_name, pcap_file_error)) == NULL) {
                    printf("Chyba pri otvoreni PCAP suboru.");
                    exit(0);
                }

                printf("Zadajte protokol. Moznosti su:\n\nHTTP\nHTTPS\nTELNET\nFTP CONTROL\nICMP\n");
                printf("\n=============================================================\n");

                fill_categories_mda();
                char choice2[20];
                fgets(choice2, 20, stdin);
                choice2[strlen(choice2) - 1] = '\0';
                /* puts(choice2); */

                int op_ethertype;
                int op_protocol;
                int op_port;
                int count = 0;

                int i, j, k;
                for (i = 1; i < 3; i++)
                    for (j = 0; j < 4; j++)
                        for (k = 0; k < 7; k++)
                            if (strcmp(choice2, (const char *) &categories[i][j][k][0]) == 0) {
                                op_ethertype = i;
                                op_protocol = j;
                                op_port = k;
                            }
                /* printf("%d %d %d\n", op_ethertype, op_protocol, op_port); */

                while ((pcap_next_ex(pcap_file, &pcap_header, &packet)) >= 0) {
                    frames++;
                    char* frame_type_buff = get_frame_type(packet);
                    if (strcmp(frame_type_buff, "Ethernet II") == 0) {
                        char* ethertype_buff;
                        ethertype_buff = get_ether_type(packet, ethertypes);
                        char* protocol_buff;
                        protocol_buff = get_protocol(packet, ip_protocols);
                        char* port_buff;
                        if (op_protocol == 1)
                            port_buff = get_tcp_or_udp_port(packet, tcp_ports);
                        else if (op_protocol == 2)
                            port_buff = get_tcp_or_udp_port(packet, udp_ports);
                        else
                            port_buff = get_icmp_port(packet, icmp_ports);

                        /*
                        printf("%d\n", frames);
                        printf("ethertype_buff: %s\n", ethertype_buff);
                        printf("protocol_buff: %s\n", protocol_buff);
                        printf("port_buff: %s\n", port_buff);
                        printf("choice2: %s\n", choice2);
                        printf("&categories[op_ethertype][op_protocol][op_port]: %s\n", &categories[op_ethertype][op_protocol][op_port]);
                        */

                        // ak nasiel hladany protokol
                        if (strcmp(port_buff, (const char *) &categories[op_ethertype][op_protocol][op_port]) == 0 || strcmp(protocol_buff, "ICMP") == 0 && strcmp(choice2, protocol_buff) == 0) {
                            print_basic_info(frames, pcap_header->caplen, pcap_header->len);
                            printf("\n%s", frame_type_buff);
                            print_MAC_address(packet);
                            printf("%s\n", ethertype_buff);
                            print_IP_adress(packet);
                            printf("%s\n", protocol_buff);
                            printf("%s\n", port_buff);
                            print_src_port_and_dst_port(packet);
                            print_hexadecimal(pcap_header->len, packet);
                            count++;
                            printf("\n=============================================================\n");
                        }
                    }
                }
                printf("Tento subor obsahoval %d protokolov typu %s.\n", count, choice2);
                pcap_close(pcap_file);
                frames = 0;
                op_ethertype = 0;
                op_protocol = 0;
                op_port = 0;
                break;
            }

                /* pocet ramcov nesmie byt viac ako 20 */
            case 3: {

                if ((pcap_file = pcap_open_offline(file_name, pcap_file_error)) == NULL) {
                    printf("Chyba pri otvoreni PCAP suboru.");
                    exit(0);
                }

                fill_categories_mda();
                char choice2[20];
                strcpy(choice2, "HTTP");


                while ((pcap_next_ex(pcap_file, &pcap_header, &packet)) >= 0) {
                    frames++;
                    char* port_buff;
                    port_buff = get_tcp_or_udp_port(packet, tcp_ports);

                    if (strcmp(port_buff, "HTTP") == 0) {
                        insert_packet_to_ll(&packet_head, get_src_ip(packet), get_dst_ip(packet), get_src_port(packet), get_dst_port(packet), get_tcp_flag(packet), frames);
                    }
                }

                frames = 0;

                struct packet *temp = packet_head;
                struct packet *temp2 = temp;
                struct packet *temp3 = temp2;
                struct packet *temp4 = packet_head;
                struct packet *temp5 = temp4;
                struct packet *temp6 = temp5;
                struct packet *temp7 = temp6;

                char *str = verify_3WHS(temp, temp2, temp3);
                char* token;
                char* rest = str;

                char *array[3];
                int x = 0;

                while ((token = strtok_r(rest, " ", &rest)))
                    array[x++] = token;

                int temp_frame_number = atoi(array[0]);
                char *temp_src_port = array[1];

//                printf("%d %s\n", temp_frame_number, array[1]);

                if (temp_frame_number == 0 && strcmp(temp_src_port, "0") == 0)
                    printf("SYN ERROR\n");

                verify_termination(temp4, temp5, temp6, temp7, temp_frame_number, temp_src_port);

                pcap_close(pcap_file);

                if ((pcap_file = pcap_open_offline(file_name, pcap_file_error)) == NULL) {
                    printf("Chyba pri otvoreni PCAP suboru.");
                    exit(0);
                }

                while ((pcap_next_ex(pcap_file, &pcap_header, &packet)) >= 0) {
                    frames++;
                    char* frame_type_buff = get_frame_type(packet);
                    char* ethertype_buff;
                    ethertype_buff = get_ether_type(packet, ethertypes);
                    char* protocol_buff;
                    protocol_buff = get_protocol(packet, ip_protocols);
                    char* port_buff;
                    port_buff = get_tcp_or_udp_port(packet, tcp_ports);

                    if (strcmp(get_src_port(packet), temp_src_port) == 0 || strcmp(get_dst_port(packet), temp_src_port) == 0) {
                        print_basic_info(frames, pcap_header->caplen, pcap_header->len);
                        printf("\n%s", frame_type_buff);
                        print_MAC_address(packet);
                        printf("%s\n", ethertype_buff);
                        print_IP_adress(packet);
                        printf("%s\n", protocol_buff);
                        printf("%s\n", port_buff);
                        print_src_port_and_dst_port(packet);
                        print_hexadecimal(pcap_header->len, packet);
                        printf("\n=============================================================\n");
                    }
                }

                pcap_close(pcap_file);
                frames = 0;
                break;
            }

            default:
                break;
        }
    } while (choice != 0);

    return 0;
}


