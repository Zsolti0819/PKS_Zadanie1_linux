#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <pcap/pcap.h>

struct IP_header
{
    char* dst_ip_addr;
    int rx_packets;
    bool* tcp;
    struct IP_header* next;
};

// pomocna funkcia na vkladanie uzlov do spajaneho zoznamu
void insert_node_to_linked_list(struct IP_header** head_ref, char* ip_address, bool tcp)
{
    struct IP_header* new_node = malloc(sizeof(struct IP_header));
    struct IP_header* last = *head_ref;
    new_node->dst_ip_addr = ip_address;
    new_node->rx_packets = 1;
    //new_node->tcp = tcp;
    new_node->next = NULL;

    if (*head_ref == NULL)
    {
        *head_ref = new_node;
        return;
    }

    while (last->next != NULL)
        last = last->next;

    last->next = new_node;
    return;
}

// vypis spajaneho zoznamu
void print_linked_list(struct IP_header* node, FILE* output)
{
    while (node != NULL)
    {
        //if (node->tcp) // chceme aby to bolo TCP
        //{
        printf("%s\n", node->dst_ip_addr);
        fprintf(output, "%s\n", node->dst_ip_addr);
        // printf("Packets: %d\n\n", node->rx_packets); // v pripade ak by sme chceli packety IPv4/TCP
        //}
        node = node->next;
    }
}

void print_ip_with_the_most_packets(struct IP_header* start, FILE* output)
{
    struct IP_header* temp = start;
    struct IP_header* temp2 = NULL;

    int max = 0;
    while (temp != NULL)
    {
        if (temp->rx_packets > max)
        {
            temp2 = temp;
            max = temp->rx_packets;
        }

        temp = temp->next;
    }
    printf("Adresa uzla s najvacsim poctom prijatych paketov:\n%s\t%d paketov\n", temp2->dst_ip_addr, temp2->rx_packets);
    fprintf(output, "Adresa uzla s najvacsim poctom prijatych paketov:\n%s\t%d paketov\n", temp2->dst_ip_addr, temp2->rx_packets);
}

// vymazanie vsetkych uzlov
void delete_linked_list(struct IP_header** head_ref)
{
    struct IP_header* temp = *head_ref;
    struct IP_header* next;

    while (temp != NULL)
    {
        next = temp->next;
        free(temp);
        temp = next;
    }

    *head_ref = NULL;
}

// hladanie v spajanom zozname
bool search_in_linked_list(struct IP_header* head, char* data)
{
    struct IP_header* temp = head;
    while (temp != NULL)
    {
        if (strcmp(temp->dst_ip_addr, data) == 0)
        {
            temp->rx_packets++;
            return true;
        }

        temp = temp->next;
    }
    return false;
}

// vypis menu
void print_menu()
{
    printf("\n=======================================================================\n");
    printf("Vyberte o ktory vypis mate zaujem (zadajte cislo):\n");
    printf("0 - Koniec\n");
    printf("1 - Vypis vsetkych komunikacii\n");
    printf("2 - Vypis komunikacii podla protokolu (viacere moznosti)\n");
    printf("3 - Doimplementacia\n");
    printf("Zadajte prosim cislo: ");
    printf("\n=======================================================================\n");
}

// pomocna funkcia, pouzivana pri menu
void seek_to_next_line(void)
{
    int c;
    while ((c = fgetc(stdin)) != EOF && c != '\n');
}

// zakladne informacie, pouzivane v bode 1.
void print_basic_info(int frame, int caplen, int len, FILE* output) {
    printf("ramec %i\n", frame);
    fprintf(output, "ramec %i\n", frame);
    printf("dlzka ramca poskytnuta pcap API - %d B\n", caplen);
    fprintf(output, "dlzka ramca poskytnuta pcap API - %d B\n", caplen);
    len = len + 4;
    if (len < 64)len = 64;
    printf("dlzka ramca prenasaneho po mediu - %d B", len);
    fprintf(output, "dlzka ramca prenasaneho po mediu - %d B", len);
}

// vypis MAC adresy
void print_MAC_address(const u_char* packet, FILE* output) {
    printf("\nZdrojova MAC adresa: ");
    fprintf(output, "\nZdrojova MAC adresa: ");
    for (int i = 6; i < 12; i++)
    {
        printf("%.2X ", packet[i]);
        fprintf(output, "%.2X ", packet[i]);
    }

    printf("\nCielova MAC adresa: ");
    fprintf(output, "\nCielova MAC adresa: ");
    for (int i = 0; i < 6; i++)
    {
        printf("%.2X ", packet[i]);
        fprintf(output, "%.2X ", packet[i]);
    }

    printf("\n");
    fprintf(output, "\n");
}

// vypis IP adresy
void print_IP_adress(const u_char* packet, FILE* output) {
    printf("zdrojova IP adresa: %d.%d.%d.%d\n", packet[26], packet[27], packet[28], packet[29]);
    fprintf(output, "zdrojova IP adresa: %d.%d.%d.%d\n", packet[26], packet[27], packet[28], packet[29]);
    printf("cielova IP adresa: %d.%d.%d.%d\n", packet[30], packet[31], packet[32], packet[33]);
    fprintf(output, "cielova IP adresa: %d.%d.%d.%d\n", packet[30], packet[31], packet[32], packet[33]);
}

// formalny vypis v hexa tvare, pouzivan v bode 1.
void print_hexadecimal(int i, const u_char* packet, FILE* output) {
    int move;
    for (move = 0; (move < i); move++) {
        if ((move % 8) == 0 && (move % 16) != 0)
        {
            printf(" ");
            fprintf(output, " ");
        }

        if ((move % 16) == 0)
        {
            printf("\n");
            fprintf(output, "\n");
        }

        printf("%.2x ", packet[move]);
        fprintf(output, "%.2x ", packet[move]);
    }
    printf("\n");
    fprintf(output, "\n");
}

// vypis zdrojoveho a cieloveho portu
void print_src_port_and_dst_port(const u_char* packet, FILE* output)
{
    printf("zdrojovy port: %d\ncielovy port: %d", packet[34] * 256 + packet[35], packet[36] * 256 + packet[37]);
    fprintf(output, "zdrojovy port: %d\ncielovy port: %d", packet[34] * 256 + packet[35], packet[36] * 256 + packet[37]);
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

// funkcia vrati retazec s obsahom typom je ramca
char* get_frame_type(const u_char* packet) {
    if (packet[12] * 256 + packet[13] > 0x5DC)
        return "Ethernet II";
    else
        return "802.3";
}

// nasledujuce funkcie su podobne, ale kazdy pracuje s inym suborom, a vracia nejaku hodnotu vycitaneho zo subor
char* get_ether_type(const u_char* packet, FILE* ethertypes)
{
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
    sprintf(ethertype, ethertype_buff);
    return ethertype;
}

char* get_protocol(const u_char* packet, FILE* ip_protocols)
{
    int value_in_the_file = 0;
    int real_value = packet[23];
    rewind(ip_protocols);
    char c;
    char protocol_buff[50] = { 0 };
    int i = 0;

    while ((c = getc(ip_protocols)) != '-') {
        if (c == '#') {
            fscanf(ip_protocols, "%x", &value_in_the_file);
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
    sprintf(protocol, protocol_buff);
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
    sprintf(tcp_port, tcp_port_buff);

    return tcp_port;
}

char* get_icmp_port(const u_char* packet, FILE* icmp_ports)
{
    int value_in_the_file = 0;

    int real_value = packet[34];

    int pom = 0;
    rewind(icmp_ports);
    char c;
    char icmp_port_buff[50] = { 0 };
    int i = 0;

    while ((c = getc(icmp_ports)) != '-') {
        if (c == '#') {
            fscanf(icmp_ports, "%x", &value_in_the_file);
            if (real_value == value_in_the_file) {
                pom = value_in_the_file;
                while ((c = getc(icmp_ports)) != '\n')
                    if (c != '\t')
                        icmp_port_buff[i++] = c;
                break;
            }
        }
    }
    char* icmp_port;
    icmp_port = malloc(sizeof(u_char) * i);
    sprintf(icmp_port, icmp_port_buff);

    return icmp_port;
}

char* get_arp_value(const u_char* packet, FILE* arp_file)
{
    int value_in_the_file = 0;

    int real_value = packet[20] * 256 + packet[21];
    int pom = 0;
    rewind(arp_file);
    char c;
    char arp_buff[50] = { 0 };
    int i = 0;

    while ((c = getc(arp_file)) != '-') {
        if (c == '#') {
            fscanf(arp_file, "%x", &value_in_the_file);
            if (real_value == value_in_the_file) {
                pom = value_in_the_file;
                while ((c = getc(arp_file)) != '\n')
                    if (c != '\t')
                        arp_buff[i++] = c;
                break;
            }
        }
    }
    char* arp_value;
    arp_value = malloc(sizeof(u_char) * i);
    sprintf(arp_value, arp_buff);

    return arp_value;

}

char* get_802_3_value(const u_char* packet, FILE* eighthundredtwo_three_file)
{
    int value_in_the_file = 0;

    int real_value1 = packet[14];
    int real_value2 = packet[15];
    int pom = 0;
    rewind(eighthundredtwo_three_file);
    char c;
    char eighthundredtwo_three_buff[50] = { 0 };
    int i = 0;

    while ((c = getc(eighthundredtwo_three_file)) != '-') {
        if (c == '#') {
            fscanf(eighthundredtwo_three_file, "%x", &value_in_the_file);
            if (real_value1 == value_in_the_file && real_value2 == value_in_the_file) {
                pom = value_in_the_file;
                while ((c = getc(eighthundredtwo_three_file)) != '\n')
                    if (c != '\t')
                        eighthundredtwo_three_buff[i++] = c;
                break;
            }
        }
    }
    char* eighthundredtwo_three_value;
    eighthundredtwo_three_value = malloc(sizeof(u_char) * i);
    sprintf(eighthundredtwo_three_value, eighthundredtwo_three_buff);

    return eighthundredtwo_three_value;
}

/*
char* get_sap(const u_char* packet, FILE* sap_file)
{
    int value_in_the_file = 0;

    int real_value1 = packet[14];
    int real_value2 = packet[15];

    rewind(sap_file);
    char c;
    char eighthundredtwo_three_buff[50] = { 0 };
    int i = 0;

    while ((c = getc(sap_file)) != '-') {
        if (c == '#') {
            fscanf(sap_file, "%x", &value_in_the_file);
            if (real_value1 == value_in_the_file || real_value2 == value_in_the_file) {
                while ((c = getc(sap_file)) != '\n')
                    if (c != '\t')
                    {
                        eighthundredtwo_three_buff[i++] = c;
                        printf("%c", c);
                    }

                break;
            }
        }
    }
    char* eighthundredtwo_three_value;
    eighthundredtwo_three_value = malloc(sizeof(u_char) * i);
    sprintf(eighthundredtwo_three_value, eighthundredtwo_three_buff);

    return eighthundredtwo_three_value;
}
*/


int main() {
    char* file_name = { "/home/zsolti/CLionProjects/PKS_Z1/vzorky_pcap_na_analyzu/trace-26.pcap" }; // sem vlozte subor
    char chyba_pcap_suboru[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr* pcap_header;
    const u_char* packet;
    pcap_t* pcap_file;

    FILE* ethertypes;
    if ((ethertypes = fopen("/home/zsolti/CLionProjects/PKS_Z1/txt/ethertypes.txt", "r")) == NULL) printf("Neotvoreny subor \"ethertypes.txt\"\n");

    FILE* ip_protocols;
    if ((ip_protocols = fopen("/home/zsolti/CLionProjects/PKS_Z1/txt/ip_protocols.txt", "r")) == NULL) printf("Neotvoreny subor \"ip_protocols.txt\"\n");

    FILE* tcp_ports;
    if ((tcp_ports = fopen("/home/zsolti/CLionProjects/PKS_Z1/txt/tcp_ports.txt", "r")) == NULL) printf("Neotvoreny subor \"tcp_ports.txt\"\n");

    FILE* udp_ports;
    if ((udp_ports = fopen("/home/zsolti/CLionProjects/PKS_Z1/txt/udp_ports.txt", "r")) == NULL) printf("Neotvoreny subor \"udp_ports.txt\"\n");

    FILE* icmp_ports;
    if ((icmp_ports = fopen("/home/zsolti/CLionProjects/PKS_Z1/txt/icmp_ports.txt", "r")) == NULL) printf("Neotvoreny subor \"icmp_ports.txt\"\n");

    FILE* arp_operation;
    if ((arp_operation = fopen("/home/zsolti/CLionProjects/PKS_Z1/txt/arp_values.txt", "r")) == NULL) printf("Neotvoreny subor \"arp_values.txt\"\n");

    FILE* eighthundredtwo_three;
    if ((eighthundredtwo_three = fopen("/home/zsolti/CLionProjects/PKS_Z1/txt/802_3.txt", "r")) == NULL) printf("Neotvoreny subor \"802_3.txt\"\n");

    FILE* sap_file;
    if ((sap_file = fopen("/home/zsolti/CLionProjects/PKS_Z1/txt/sap_file.txt", "r")) == NULL) printf("Neotvoreny subor \"sap_file.txt\"\n");

    FILE* output;
    output = fopen("/home/zsolti/CLionProjects/PKS_Z1/txt/output.txt", "w");

    struct IP_header* head = NULL;

    u_int frames = 0;
    int choice;

    do
    {
        print_menu();
        scanf("%d", &choice);
        seek_to_next_line();
        switch (choice)
        {
            case 1:
            {
                if ((pcap_file = pcap_open_offline(file_name, chyba_pcap_suboru)) == NULL)
                {
                    printf("Subor sa neda otvorit!");
                    fprintf(output, "Subor sa neda otvorit!");
                }

                while ((pcap_next_ex(pcap_file, &pcap_header, &packet)) >= 0) {
                    frames++;

                    char* ethertype_buff = get_ether_type(packet, ethertypes);

                    char* eighthundredtwo_three_buff;
                    eighthundredtwo_three_buff = get_802_3_value(packet, eighthundredtwo_three);

                    char* frame_type = get_frame_type(packet);

                    char* protocol_buff;
                    if (strcmp(ethertype_buff, "ARP") == 0)
                    {

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

                        if (strcmp(arp_buff, "Request") == 0)
                        {
                            printf("%s-%s, IP Adresa: %s, MAC Adresa: %s\n", ethertype_buff, arp_buff, arp_dst_ip, arp_dst_mac);
                            fprintf(output, "%s-%s, IP Adresa: %s, MAC Adresa: %s\n", ethertype_buff, arp_buff, arp_dst_ip, arp_dst_mac);
                            printf("Zdrojova IP: %s, Cielova IP: %s\n", arp_src_ip, arp_dst_ip);
                            fprintf(output, "Zdrojova IP: %s, Cielova IP: %s\n", arp_src_ip, arp_dst_ip);

                        }
                        else // Reply
                        {
                            printf("%s-%s, IP Adresa: %s, MAC Adresa: %s\n", ethertype_buff, arp_buff, arp_src_ip, arp_src_mac);
                            fprintf(output, "%s-%s, IP Adresa: %s, MAC Adresa: %s\n", ethertype_buff, arp_buff, arp_src_ip, arp_src_mac);
                            printf("Zdrojova IP: %s, Cielova IP: %s\n", arp_src_ip, arp_dst_ip);
                            fprintf(output, "Zdrojova IP: %s, Cielova IP: %s\n", arp_src_ip, arp_dst_ip);
                        }

                        printf("%s\n", protocol_buff);
                        fprintf(output, "%s\n", protocol_buff);

                    }
                    else
                        protocol_buff = get_protocol(packet, ip_protocols);

                    print_basic_info(frames, pcap_header->caplen, pcap_header->len, output);
                    printf("\n%s", get_frame_type(packet));
                    fprintf(output, "\n%s", get_frame_type(packet));



                    if (strcmp(frame_type, "Ethernet II"))
                    {
                        if (strcmp(eighthundredtwo_three_buff, "SNAP") == 0 || strcmp(eighthundredtwo_three_buff, "Global DSAP") == 0)
                        {

                            if (strcmp(eighthundredtwo_three_buff, "SNAP") == 0)
                            {
                                printf(" LLC + %s\n", eighthundredtwo_three_buff);
                                fprintf(output, " LLC + %s\n", eighthundredtwo_three_buff);
                            }

                            else
                            {
                                printf("%s\n", eighthundredtwo_three_buff);
                                fprintf(output, "%s\n", eighthundredtwo_three_buff);
                            }
                        }
                        else
                            printf("RAW\n");
                        fprintf(output, "RAW\n");
                    }
                    print_MAC_address(packet, output);

                    if (strcmp(frame_type, "Ethernet II") == 0)
                    {
                        printf("%s\n", ethertype_buff);
                        fprintf(output, "%s\n", ethertype_buff);
                        if (strcmp(ethertype_buff, "ARP"))
                            print_IP_adress(packet, output);
                        printf("%s\n", protocol_buff);
                        fprintf(output, "%s\n", protocol_buff);


                        char* dst_ip_buff;
                        dst_ip_buff = get_dst_ip(packet);
                        if ((strcmp(ethertype_buff, "IPv4") == 0) && search_in_linked_list(head, dst_ip_buff) == false)
                        {
                            if (strcmp(protocol_buff, "TCP") == 0)
                                insert_node_to_linked_list(&head, get_dst_ip(packet), true);
                            else
                                insert_node_to_linked_list(&head, get_dst_ip(packet), false);
                        }

                        char* port_buff = { 0 };
                        if (strcmp(protocol_buff, "TCP") == 0)
                        {
                            port_buff = get_tcp_or_udp_port(packet, tcp_ports);
                            printf("%s\n", port_buff);
                            fprintf(output, "%s\n", port_buff);
                            print_src_port_and_dst_port(packet, output);
                        }

                        else if (strcmp(protocol_buff, "UDP") == 0)
                        {
                            port_buff = get_tcp_or_udp_port(packet, udp_ports);
                            printf("%s\n", port_buff);
                            fprintf(output, "%s\n", port_buff);
                            print_src_port_and_dst_port(packet, output);
                        }


                        else if (strcmp(protocol_buff, "ICMP") == 0)
                        {
                            port_buff = get_icmp_port(packet, icmp_ports);
                            printf("%s\n", port_buff);
                            fprintf(output, "%s\n", port_buff);
                            print_src_port_and_dst_port(packet, output);
                        }
                    }
                    print_hexadecimal(pcap_header->len, packet, output);
                    printf("\n=======================================================================\n");
                    fprintf(output, "\n=======================================================================\n");

                }
                printf("IP adresy prijimajucich uzlov:\n");
                fprintf(output, "IP adresy prijimajucich uzlov:\n");
                print_linked_list(head, output);
                print_ip_with_the_most_packets(head, output);
                pcap_close(pcap_file);
                delete_linked_list(&head);
                frames = 0;

                break;
            }

            case 2:
            {
                printf("Zadajte protokol. Moznosti su:\n\nHTTP\nHTTPS\nTELNET\nFTP CONTROL\nICMP\n");
                printf("\n=======================================================================\n");
                int i, j, k, l;
                char**** categories[3][4][7][10];
                for (i = 0; i < 3; i++)
                    for (j = 0; j < 4; j++)
                        for (k = 0; k < 7; k++)
                            for (l = 0; l < 10; l++)
                                strcpy(&categories[i][j][k][l], "-");
                strcpy(&categories[1][0][0][0], "IPv4");
                strcpy(&categories[1][1][0][0], "TCP");
                strcpy(&categories[1][1][1][0], "FTP DATA");
                strcpy(&categories[1][1][2][0], "FTP CONTROL");
                strcpy(&categories[1][1][3][0], "SSH");
                strcpy(&categories[1][1][4][0], "TELNET");
                strcpy(&categories[1][1][5][0], "HTTP");
                strcpy(&categories[1][1][6][0], "HTTPS");
                strcpy(&categories[1][2][0][0], "UDP");
                strcpy(&categories[1][2][1][0], "TFTP");
                strcpy(&categories[1][3][0][0], "ICMP");
                strcpy(&categories[2][0][0][0], "ARP");
                char choice2[20];
                fgets(choice2, 20, stdin);
                choice2[strlen(choice2) - 1] = '\0'; // odsranim enter kvoli fgets
                // puts(choice2);
                int op_ethertype;
                int op_protocol;
                int op_port;
                int count = 0;
                for (i = 1; i < 3; i++)
                    for (j = 0; j < 4; j++)
                        for (k = 0; k < 7; k++)
                            if (strcmp(choice2, &categories[i][j][k][0]) == 0)
                            {
                                op_ethertype = i;
                                op_protocol = j;
                                op_port = k;
                            }
                // printf("%d %d %d\n", op_ethertype, op_protocol, op_port);
                if ((pcap_file = pcap_open_offline(file_name, chyba_pcap_suboru)) == NULL)
                {
                    printf("Subor sa neda otvorit!");
                    fprintf(output, "Subor sa neda otvorit!");
                }


                while ((pcap_next_ex(pcap_file, &pcap_header, &packet)) >= 0) {
                    frames++;
                    char* frame_type = get_frame_type(packet);
                    if (strcmp(frame_type, "Ethernet II") == 0)
                    {
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
                        // ked nasiel hladany protokol
                        if (strcmp(port_buff, &categories[op_ethertype][op_protocol][op_port]) == 0 || strcmp(protocol_buff, "ICMP") == 0 && strcmp(choice2, protocol_buff) == 0)
                        {
                            print_basic_info(frames, pcap_header->caplen, pcap_header->len, output);
                            printf("\n%s", get_frame_type(packet));
                            fprintf(output, "\n%s", get_frame_type(packet));
                            print_MAC_address(packet, output);
                            printf("%s\n", ethertype_buff);
                            fprintf(output, "%s\n", ethertype_buff);
                            print_IP_adress(packet, output);
                            printf("%s\n", protocol_buff);
                            fprintf(output, "%s\n", protocol_buff);
                            printf("%s\n", port_buff);
                            fprintf(output, "%s\n", port_buff);
                            print_src_port_and_dst_port(packet, output);
                            print_hexadecimal(pcap_header->len, packet, output);
                            count++;
                            printf("\n=======================================================================\n\n");
                            fprintf(output, "\n=======================================================================\n\n");
                        }
                    }
                }
                printf("Tento subor ubsahoval %d protokolov typu %s.\n", count, choice2);
                fprintf(output, "Tento subor ubsahoval %d protokolov typu %s.\n", count, choice2);
                pcap_close(pcap_file);
                frames = 0;
                op_ethertype = 0;
                op_protocol = 0;
                op_port = 0;
                count = 0;
                break;
            }

                // Doimplementacia
                // vystupny subor je pod priecinkom txt pod menom output.txt
            case 3:
            {
                char choice2[20];
                strcpy(choice2, "STP");
                int count = 0;

                if ((pcap_file = pcap_open_offline(file_name, chyba_pcap_suboru)) == NULL)
                {
                    printf("Subor sa neda otvorit!");
                    fprintf(output, "Subor sa neda otvorit!");
                }


                while ((pcap_next_ex(pcap_file, &pcap_header, &packet)) >= 0) {
                    frames++;
                    char* frame_type = get_frame_type(packet);
                    if (strcmp(frame_type, "802.3") == 0)
                    {
                        char* sap_buff;
                        sap_buff = get_802_3_value(packet, sap_file);

                        if (strcmp(sap_buff, "STP") == 0)
                        {
                            print_basic_info(frames, pcap_header->caplen, pcap_header->len, output);
                            printf("\n%s", get_frame_type(packet));
                            fprintf(output, "\n%s", get_frame_type(packet));
                            print_MAC_address(packet, output);
                            print_IP_adress(packet, output);
                            print_src_port_and_dst_port(packet, output);
                            print_hexadecimal(pcap_header->len, packet, output);
                            count++;
                            printf("\n=======================================================================\n\n");
                            fprintf(output, "\n=======================================================================\n\n");

                        }
                    }
                }
                printf("Tento subor ubsahoval %d protokolov typu %s.\n", count, choice2);
                fprintf(output, "Tento subor ubsahoval %d protokolov typu %s.\n", count, choice2);
                pcap_close(pcap_file);
                frames = 0;
                count = 0;
                break;
            }


            default:
                break;
        }
    } while (choice != 0);


    return 0;
}


