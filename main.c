#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <pcap/pcap.h>

char**** categories[3][4][7][10];

struct Packet {
    int frameNumber;
    char* srcPort;
    char* dstPort;
    char* flag;
    bool isMarked;
    struct Packet* next;
};

bool findPacketInList(struct Packet* head, int frameNumber) {
    struct Packet* temp = head;
    while (temp != NULL) {
        if (temp->frameNumber == frameNumber)
            return true;

        temp = temp->next;
    }
    return false;
}

void insertPacketToList(struct Packet **headRef, char *srcPort, char *dstPort, char *flag, int frameNumber) {
    struct Packet* newNode = malloc(sizeof(struct Packet));
    struct Packet* last = *headRef;
    newNode->srcPort = srcPort;
    newNode->dstPort = dstPort;
    newNode->flag = flag;
    newNode->frameNumber = frameNumber;
    newNode->isMarked = false;
    newNode->next = NULL;

    if (*headRef == NULL) {
        *headRef = newNode;
        return;
    }

    while (last->next != NULL)
        last = last->next;

    last->next = newNode;
}

void deletePacketList(struct Packet** headRef) {
    struct Packet* temp = *headRef;
    struct Packet* next;

    while (temp != NULL) {
        next = temp->next;
        free(temp);
        temp = next;
    }
    *headRef = NULL;
}

void printPacket(struct Packet *node) {
    printf("~~~~~~~~~~\n");
    printf("%s\n", node->flag);
    printf("FRAME: %d\n", node->frameNumber);
    printf("SRC: %s\n", node->srcPort);
    printf("DST: %s\n", node->dstPort);
}

struct IPv4Packet {
    char* srcIPAdress;
    int txPackets;
    bool isTCP;
    struct IPv4Packet* next;
};

bool findIPv4PacketInList(struct IPv4Packet* head, char* data) {
    struct IPv4Packet* temp = head;
    while (temp != NULL) {
        if (strcmp(temp->srcIPAdress, data) == 0) {
            temp->txPackets++;
            return true;
        }
        temp = temp->next;
    }
    return false;
}

void insertIPv4PacketToList(struct IPv4Packet **headRef, char *srcIPAdress, bool isTCP) {
    struct IPv4Packet* newNode = malloc(sizeof(struct IPv4Packet));
    struct IPv4Packet* last = *headRef;
    newNode->srcIPAdress = srcIPAdress;
    newNode->txPackets = 1;
    newNode->isTCP = isTCP;
    newNode->next = NULL;

    if (*headRef == NULL) {
        *headRef = newNode;
        return;
    }

    while (last->next != NULL)
        last = last->next;

    last->next = newNode;
}

void deleteIPv4PacketList(struct IPv4Packet** headRef) {
    struct IPv4Packet* temp = *headRef;
    struct IPv4Packet* next;

    while (temp != NULL) {
        next = temp->next;
        free(temp);
        temp = next;
    }
    *headRef = NULL;
}

void printIPv4PacketList(struct IPv4Packet *node) {
    while (node != NULL) {
        if (node->isTCP)
            printf("%s\n", node->srcIPAdress);
        node = node->next;
    }
}

void printIPWithTheMostPacketsSent(struct IPv4Packet *start) {
    struct IPv4Packet* temp = start;
    struct IPv4Packet* temp2 = NULL;

    int max = 0;
    while (temp != NULL) {
        if (temp->txPackets > max) {
            temp2 = temp;
            max = temp->txPackets;
        }
        temp = temp->next;
    }
    if (temp2 != NULL)
        printf("Adresa uzla s najvacsim poctom odoslanych paketov:\n%s\t%d paketov\n", temp2->srcIPAdress, temp2->txPackets);
}

void printMenu() {
    printf("\nVyberte o ktory vypis mate zaujem (zadajte cislo):\n");
    printf("0 - Koniec\n");
    printf("1 - Vypis vsetkych komunikacii\n");
    printf("2 - Filter ramcov (viacere moznosti)\n");
    printf("3 - HTTP komunikacie\n");
    printf("=============================================================\n");
}

void seekToNextLine(void) {
    int c;
    while ((c = fgetc(stdin)) != EOF && c != '\n');
}

void printBasicInfo(int frame, int caplen, int len) {
    printf("ramec %i\n", frame);
    printf("dlzka ramca poskytnuta pcap API - %d B\n", caplen);
    len = len + 4;
    if (len < 64)len = 64;
        printf("dlzka ramca prenasaneho po mediu - %d B", len);
}

void printMACAddress(const u_char *packet) {
    printf("\nZdrojova MAC adresa: ");
    for (int i = 6; i < 12; i++)
        printf("%.2X ", packet[i]);

    printf("\nCielova MAC adresa: ");
    for (int i = 0; i < 6; i++)
        printf("%.2X ", packet[i]);

    printf("\n");
}

void printIPAdresses(const u_char *packet) {
    printf("zdrojova IP adresa: %d.%d.%d.%d\n", packet[26], packet[27], packet[28], packet[29]);
    printf("cielova IP adresa: %d.%d.%d.%d\n", packet[30], packet[31], packet[32], packet[33]);
}

void printHexadecimal(int i, const u_char *packet) {
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

void printSrcPortAndDstPort(const u_char *packet) {
    printf("zdrojovy port: %d\ncielovy port: %d\n", packet[34] * 256 + packet[35], packet[36] * 256 + packet[37]);
}

char* getSrcIP(const u_char* packet) {
    char* srcIPAddress;
    srcIPAddress = malloc(sizeof(u_char) * 20);
    sprintf(srcIPAddress, "%d.%d.%d.%d", packet[26], packet[27], packet[28], packet[29]);
    return srcIPAddress;
}

char* getDstIP(const u_char* packet) {
    char* dstIPAddress;
    dstIPAddress = malloc(sizeof(u_char) * 20);
    sprintf(dstIPAddress, "%d.%d.%d.%d", packet[30], packet[31], packet[32], packet[33]);
    return dstIPAddress;
}

char* getSrcPort(const u_char* packet) {
    char* srcPort;
    srcPort = malloc(sizeof(u_char) * 20);
    sprintf(srcPort, "%d", packet[34] * 256 + packet[35]);
    return srcPort;

}

char* getDstPort(const u_char* packet) {
    char* dstPort;
    dstPort = malloc(sizeof(u_char) * 20);
    sprintf(dstPort, "%d", packet[36] * 256 + packet[37]);
    return dstPort;

}

char* getFrameType(const u_char* packet) {
    if (packet[12] * 256 + packet[13] > 0x5DC)
        return "Ethernet II";
    else
        return "802.3";
}

char* getEtherType(const u_char* packet, FILE* ethertypes) {
    int valueInTheFile = 0;
    int realValue = packet[12] * 256 + packet[13];
    rewind(ethertypes);
    char c;
    char ethertypeBuff[50] = { 0 };
    int i = 0;

    while ((c = getc(ethertypes)) != '-') {
        if (c == '#') {
            fscanf(ethertypes, "%x", &valueInTheFile);
            if (realValue == valueInTheFile) {
                while ((c = getc(ethertypes)) != '\n')
                    if (c != '\t')
                        ethertypeBuff[i++] = c;
                break;
            }
        }
    }
    char* ethertype;
    ethertype = malloc(sizeof(u_char) * i);
    sprintf(ethertype, "%s", ethertypeBuff);
    return ethertype;
}

char* getProtocol(const u_char* packet, FILE* IPProtocols) {
    int valueInTheFile = 0;
    int realValue = packet[23];
    rewind(IPProtocols);
    char c;
    char protocolBuff[50] = { 0 };
    int i = 0;

    while ((c = getc(IPProtocols)) != '-') {
        if (c == '#') {
            fscanf(IPProtocols, "%x ", &valueInTheFile);
            if (realValue == valueInTheFile) {
                while ((c = getc(IPProtocols)) != '\n')
                    if (c != '\t')
                        protocolBuff[i++] = c;
                break;
            }
        }
    }
    char* protocol;
    protocol = malloc(sizeof(u_char) * i);
    sprintf(protocol, "%s", protocolBuff);
    return protocol;
}

char* getTCPOrUDPPort(const u_char* packet, FILE* fileWithPorts) {
    int valueInTheFile = 0;

    int srcRealValue = packet[34] * 256 + packet[35];
    int dstRealValue = packet[36] * 256 + packet[37];
    rewind(fileWithPorts);
    char c;
    char TCPPortBuff[50] = { 0 };
    int i = 0;

    while ((c = getc(fileWithPorts)) != '-') {
        if (c == '#') {
            fscanf(fileWithPorts, "%x ", &valueInTheFile);
            if (srcRealValue == valueInTheFile || dstRealValue == valueInTheFile) {
                while ((c = getc(fileWithPorts)) != '\n')
                    if (c != '\t')
                        TCPPortBuff[i++] = c;
                break;
            }
        }
    }
    char* TCPPort;
    TCPPort = malloc(sizeof(u_char) * i);
    sprintf(TCPPort, "%s", TCPPortBuff);

    return TCPPort;
}

char* getICMPPort(const u_char* packet, FILE* ICMPPorts) {
    int valueInTheFile = 0;

    int realValue = packet[34];

    rewind(ICMPPorts);
    char c;
    char ICMPPortBuff[50] = { 0 };
    int i = 0;

    while ((c = getc(ICMPPorts)) != '-') {
        if (c == '#') {
            fscanf(ICMPPorts, "%x ", &valueInTheFile);
            if (realValue == valueInTheFile) {
                while ((c = getc(ICMPPorts)) != '\n')
                    if (c != '\t')
                        ICMPPortBuff[i++] = c;
                break;
            }
        }
    }
    char* ICMPPort;
    ICMPPort = malloc(sizeof(u_char) * i);
    sprintf(ICMPPort, "%s", ICMPPortBuff);

    return ICMPPort;
}

char* getARPValue(const u_char* packet, FILE* ARPFile) {
    int valueInTheFile = 0;

    int realValue = packet[20] * 256 + packet[21];
    rewind(ARPFile);
    char c;
    char ARPBuff[50] = { 0 };
    int i = 0;

    while ((c = getc(ARPFile)) != '-') {
        if (c == '#') {
            fscanf(ARPFile, "%x", &valueInTheFile);
            if (realValue == valueInTheFile) {
                while ((c = getc(ARPFile)) != '\n')
                    if (c != '\t')
                        ARPBuff[i++] = c;
                break;
            }
        }
    }
    char* ARPValue;
    ARPValue = malloc(sizeof(u_char) * i);
    sprintf(ARPValue, "%s", ARPBuff);

    return ARPValue;

}

char* get802_3Value(const u_char* packet, FILE* _802_3File)
{
    int valueInTheFile = 0;

    int realValue1 = packet[14];
    int realValue2 = packet[15];
    rewind(_802_3File);
    char c;
    char _802_3Buff[50] = { 0 };
    int i = 0;

    while ((c = getc(_802_3File)) != '-') {
        if (c == '#') {
            fscanf(_802_3File, "%x", &valueInTheFile);
            if (realValue1 == valueInTheFile && realValue2 == valueInTheFile) {
                while ((c = getc(_802_3File)) != '\n')
                    if (c != '\t')
                        _802_3Buff[i++] = c;
                break;
            }
        }
    }
    char* _802_3Value;
    _802_3Value = malloc(sizeof(u_char) * i);
    sprintf(_802_3Value, "%s", _802_3Buff);

    return _802_3Value;
}

char* getTCPFlag(const u_char* packet) {
    if (packet[47] == 0x002)
        return "SYN";
    else if (packet[47] == 0x012)
        return "SYN, ACK";
    else if (packet[47] == 0x010)
        return "ACK";
    else if (packet[47] == 0x004  || packet[47] == 0x014)
        return "RST";
    else if (packet[47] == 0x011 || packet[47] == 0x019)
        return "FIN";
    return "NULL";
}

void openTxtFiles(FILE **_802_3, FILE **ethertypes, FILE **IPProtocols, FILE **TCPPorts, FILE **UDPPorts, FILE **ICMPPorts, FILE **ARPOperation, FILE **SAPFile) {
    if (((*_802_3) = fopen("/home/zsolti/CLionProjects/PKS_Zadanie1_linux/txt/802_3.txt", "r")) == NULL) printf("Chyba pri otvoreni 802_3.txt suboru.\n");
    if (((*ethertypes) = fopen("/home/zsolti/CLionProjects/PKS_Zadanie1_linux/txt/ethertypes.txt", "r")) == NULL) printf("Chyba pri otvoreni ethertypes.txt suboru.\n");
    if (((*IPProtocols) = fopen("/home/zsolti/CLionProjects/PKS_Zadanie1_linux/txt/IPProtocols.txt", "r")) == NULL) printf("Chyba pri otvoreni IPProtocols.txt suboru.\n");
    if (((*TCPPorts) = fopen("/home/zsolti/CLionProjects/PKS_Zadanie1_linux/txt/TCPPorts.txt", "r")) == NULL) printf("Chyba pri otvoreni TCPPorts.txt suboru.\n");
    if (((*UDPPorts) = fopen("/home/zsolti/CLionProjects/PKS_Zadanie1_linux/txt/UDPPorts.txt", "r")) == NULL) printf("Chyba pri otvoreni UDPPorts.txt suboru.\n");
    if (((*ICMPPorts) = fopen("/home/zsolti/CLionProjects/PKS_Zadanie1_linux/txt/ICMPPorts.txt", "r")) == NULL) printf("Chyba pri otvoreni ICMPPorts.txt suboru.\n");
    if (((*ARPOperation) = fopen("/home/zsolti/CLionProjects/PKS_Zadanie1_linux/txt/ARPValues.txt", "r")) == NULL) printf("Chyba pri otvoreni ARPValues.txt suboru.\n");
    if (((*SAPFile) = fopen("/home/zsolti/CLionProjects/PKS_Zadanie1_linux/txt/SAPFile.txt", "r")) == NULL) printf("Chyba pri otvoreni SAPFile.txt suboru.\n");
}

void fillCategoriesMDA() {
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

// temp = client, temp2 = server, temp3 = client
char * verify3WHS(struct Packet *temp, struct Packet *temp2, struct Packet *temp3) {
    while (temp != NULL) {
        if (strcmp(temp -> flag, "SYN") == 0 && temp -> isMarked == false) {
            while (temp2 != NULL) {
                if (temp -> isMarked == false && temp2 -> isMarked == false && temp -> frameNumber < temp2 -> frameNumber && strcmp(temp->srcPort, temp2->dstPort) == 0 && strcmp(temp->dstPort, temp2->srcPort) == 0 && strcmp(temp2->flag, "SYN, ACK") == 0) {
                    while (temp3 != NULL) {
                        if (temp -> isMarked == false && temp2 -> isMarked == false && temp3-> isMarked == false && temp2 -> frameNumber < temp3 -> frameNumber && strcmp(temp2->srcPort, temp3->dstPort) == 0 && strcmp(temp2->dstPort, temp3->srcPort) == 0 && strcmp(temp3->flag, "ACK") == 0) {
                            temp -> isMarked = true;
                            temp2 -> isMarked = true;
                            temp3 -> isMarked = true;

                            printPacket(temp);
                            printPacket(temp2);
                            printPacket(temp3);

                            char *_3WHSSYN = malloc(sizeof(u_char) * 20);
                            if (strcmp(temp -> srcPort, "20") == 0 || strcmp(temp -> srcPort, "21") == 0 || strcmp(temp -> srcPort, "22") == 0 || strcmp(temp -> srcPort, "23") == 0 || strcmp(temp -> srcPort, "80") == 0 || strcmp(temp -> srcPort, "443") == 0 || strcmp(temp -> srcPort, "69") == 0)
                                sprintf(_3WHSSYN, "%d %s", temp -> frameNumber, temp -> dstPort);
                            else
                                sprintf(_3WHSSYN, "%d %s", temp -> frameNumber, temp -> srcPort);
                            return _3WHSSYN;
                        }
                        temp3 = temp3 -> next;
                    }
                }
                temp2 = temp2-> next;
            }
        }
        temp = temp -> next;
    }
    char *no3WHS = malloc(sizeof(u_char) * 20);
    strcpy(no3WHS, "0 0");
    return no3WHS;
}

char * verifyTermination(struct Packet *temp4, struct Packet *temp5, int comStart, const char *clientsSourcePort) {
    while (temp4 != NULL) {
        if (comStart < temp4 -> frameNumber && temp4 -> isMarked == false && (strcmp(clientsSourcePort, temp4->dstPort) == 0 || strcmp(clientsSourcePort, temp4->srcPort) == 0 ) && strcmp(temp4->flag, "FIN") == 0) {

            if (strcmp(clientsSourcePort, temp4->dstPort) == 0) {
                while (temp5 != NULL) {
                    if (temp4->frameNumber < temp5->frameNumber && temp4->isMarked == false && temp5->isMarked == false && strcmp(clientsSourcePort, temp5->srcPort) == 0 && (strcmp(temp5->flag, "FIN") == 0 || strcmp(temp5->flag, "RST") == 0)) {
                        temp4 -> isMarked = true;
                        temp5 -> isMarked = true;

                        printPacket(temp4);
                        printPacket(temp5);

                        char *FINbyServer = malloc(sizeof(u_char) * 20);
                        sprintf(FINbyServer, "%d", temp5 -> frameNumber);
                        return FINbyServer;
                    }
                    temp5 = temp5->next;
                }
            }

            else if (strcmp(clientsSourcePort, temp4->srcPort) == 0) {
                while (temp5 != NULL) {
                    if (temp4->frameNumber < temp5->frameNumber && temp4->isMarked == false && temp5->isMarked == false && strcmp(clientsSourcePort, temp5->dstPort) == 0  && (strcmp(temp5->flag, "FIN") == 0 || strcmp(temp5->flag, "RST") == 0)) {
                        temp4 -> isMarked = true;
                        temp5 -> isMarked = true;

                        printPacket(temp4);
                        printPacket(temp5);

                        char *FINbyClient = malloc(sizeof(u_char) * 20);
                        sprintf(FINbyClient, "%d", temp5 -> frameNumber);
                        return FINbyClient;
                    }
                    temp5 = temp5->next;
                }
            }
        }

        else if (comStart < temp4 -> frameNumber && temp4 -> isMarked == false && (strcmp(clientsSourcePort, temp4->dstPort) == 0 || strcmp(clientsSourcePort, temp4->srcPort) == 0 ) && strcmp(temp4->flag, "RST") == 0) {
            temp4 -> isMarked = true;
            char *onlyRST = malloc(sizeof(u_char) * 20);
            sprintf(onlyRST, "%d", temp4 -> frameNumber);
            return onlyRST;
        }
        temp4 = temp4->next;
    }
    char *notTerminated = malloc(sizeof(u_char) * 20);
    strcpy(notTerminated, "0");
    return notTerminated;
}

int main() {

    char* file_name = { "/home/zsolti/CLionProjects/PKS_Zadanie1_linux/vzorky_pcap_na_analyzu/eth-7.pcap" }; // sem vlozit subor
    char pcap_file_error[PCAP_ERRBUF_SIZE];
    pcap_t* pcap_file;

    FILE *_802_3;
    FILE *ethertypes;
    FILE *IPProtocols;
    FILE *TCPPorts;
    FILE *UDPPorts;
    FILE *ICMPPorts;
    FILE *ARPOperation;
    FILE *SAPFile;
    openTxtFiles(&_802_3, &ethertypes, &IPProtocols, &TCPPorts, &UDPPorts, &ICMPPorts, &ARPOperation, &SAPFile);
    fillCategoriesMDA();

    struct pcap_pkthdr* pcapHeader;
    const u_char* packet;
    struct IPv4Packet* IPv4Head = NULL;
    struct Packet* head = NULL;
    int frames = 0;
    int choice;

    do {
        printMenu();
        scanf("%d", &choice);
        seekToNextLine();
        switch (choice) {
            case 1: {

                if ((pcap_file = pcap_open_offline(file_name, pcap_file_error)) == NULL) {
                    printf("Chyba pri otvoreni PCAP suboru.");
                    exit(0);
                }

                while ((pcap_next_ex(pcap_file, &pcapHeader, &packet)) >= 0) {
                    frames++;
                    char* frameType = getFrameType(packet);
                    char* ethertypeBuff = getEtherType(packet, ethertypes);
                    char* protocolBuff;

                    // Je 802.3
                    if (strcmp(frameType, "802.3") == 0) {

                        // ramec cislo x, dlzky ramca
                        printBasicInfo(frames, pcapHeader->caplen, pcapHeader->len);

                        // 802.3
                        printf("\n%s", frameType);

                        char* _802_3Buff = get802_3Value(packet, _802_3);

                        // Global DSAP == FF == RAW
                        if (strcmp(_802_3Buff, "Global DSAP") == 0) {
                            printf(" RAW\n");
                            printf("%s", _802_3Buff);
                        }

                        // SNAP == AA == SNAP + LLC
                        else if (strcmp(_802_3Buff, "SNAP") == 0)
                            printf("LLC + %s", _802_3Buff);

                        // LLC, ani jeden
                        else {
                            printf(" LLC\n");
                            printf("%s", _802_3Buff);
                        }

                        printMACAddress(packet);
                    }

                    // Je Ethernet II
                    else if (strcmp(frameType, "Ethernet II") == 0) {
                        // Je ARP, vypiseme ARP-Request/Reply,IP, MAC
                        if (strcmp(ethertypeBuff, "ARP") == 0) {
                            char* ARPBuff = getARPValue(packet, ARPOperation);
                            char ARPDSTIP[20];
                            char ARPSRCIP[20];
                            char ARPSRCMAC[50];
                            char ARPDSTMAC[50];

                            sprintf(ARPDSTIP, "%d.%d.%d.%d", packet[38], packet[39], packet[40], packet[41]);
                            sprintf(ARPSRCIP, "%d.%d.%d.%d", packet[28], packet[29], packet[30], packet[31]);
                            sprintf(ARPDSTMAC, "%.2X %.2X %.2X %.2X %.2X %.2X ", packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]);
                            sprintf(ARPSRCMAC, "%.2X %.2X %.2X %.2X %.2X %.2X ", packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);

                            // Request
                            if (strcmp(ARPBuff, "Request") == 0) {
                                printf("%s-%s, IP Adresa: %s, MAC Adresa: %s\n", ethertypeBuff, ARPBuff, ARPDSTIP, ARPDSTMAC);
                                printf("Zdrojova IP: %s, Cielova IP: %s\n", ARPSRCIP, ARPDSTIP);
                            }

                            // Reply
                            else {
                                printf("%s-%s, IP Adresa: %s, MAC Adresa: %s\n", ethertypeBuff, ARPBuff, ARPSRCIP, ARPSRCMAC);
                                printf("Zdrojova IP: %s, Cielova IP: %s\n", ARPSRCIP, ARPDSTIP);
                            }

                            printBasicInfo(frames, pcapHeader->caplen, pcapHeader->len);
                            printf("\n%s\n", frameType);
                            printf("%s", ethertypeBuff);
                            printMACAddress(packet);

                        }

                        // Je IP
                        if (strcmp(ethertypeBuff, "ARP") != 0) {
                            printBasicInfo(frames, pcapHeader->caplen, pcapHeader->len);
                            printf("\n%s", frameType);
                            printMACAddress(packet);
                            printf("%s\n", ethertypeBuff);
                            printIPAdresses(packet);
                            protocolBuff = getProtocol(packet, IPProtocols);
                            printf("%s\n", protocolBuff);


                            char* srcIPBuff;
                            srcIPBuff = getSrcIP(packet);
                            if ((strcmp(ethertypeBuff, "IPv4") == 0) && findIPv4PacketInList(IPv4Head, srcIPBuff) == false) {
                                if (strcmp(protocolBuff, "TCP") == 0)
                                    insertIPv4PacketToList(&IPv4Head, getSrcIP(packet), true);
                                else
                                    insertIPv4PacketToList(&IPv4Head, getSrcIP(packet), false);
                            }

                            char* portBuff;
                            if (strcmp(protocolBuff, "TCP") == 0) {
                                portBuff = getTCPOrUDPPort(packet, TCPPorts);
                                printf("%s\n", portBuff);
                                printSrcPortAndDstPort(packet);
                            }

                            else if (strcmp(protocolBuff, "UDP") == 0) {
                                portBuff = getTCPOrUDPPort(packet, UDPPorts);
                                printf("%s\n", portBuff);
                                printSrcPortAndDstPort(packet);
                            }

                            else if (strcmp(protocolBuff, "ICMP") == 0) {
                                portBuff = getICMPPort(packet, ICMPPorts);
                                printf("%s\n", portBuff);
                                printSrcPortAndDstPort(packet);
                            }
                        }
                    }

                    printHexadecimal(pcapHeader -> len, packet);
                    printf("\n=============================================================\n");

                }
                printf("IP adresy vysielajucich uzlov:\n");
                printIPv4PacketList(IPv4Head);
                printIPWithTheMostPacketsSent(IPv4Head);
                pcap_close(pcap_file);
                deleteIPv4PacketList(&IPv4Head);
                frames = 0;
                break;
            }

            case 2: {

                if ((pcap_file = pcap_open_offline(file_name, pcap_file_error)) == NULL) {
                    printf("Chyba pri otvoreni PCAP suboru.");
                    exit(0);
                }

                printf("Zadajte protokol. Moznosti su:\n\nHTTP\nHTTPS\nTELNET\nFTP CONTROL\nICMP\n");
                printf("\n=============================================================\n");

                char choice2[20];
                fgets(choice2, 20, stdin);
                choice2[strlen(choice2) - 1] = '\0';
                /* puts(choice2); */

                int ethertypeKey;
                int protocolKey;
                int portKey;
                int count = 0;

                int i, j, k;
                for (i = 1; i < 3; i++)
                    for (j = 0; j < 4; j++)
                        for (k = 0; k < 7; k++)
                            if (strcmp(choice2, (const char *) &categories[i][j][k][0]) == 0) {
                                ethertypeKey = i;
                                protocolKey = j;
                                portKey = k;
                            }
                /* printf("%d %d %d\n", ethertypeKey, protocolKey, portKey); */

                while ((pcap_next_ex(pcap_file, &pcapHeader, &packet)) >= 0) {
                    frames++;
                    char* frameTypeBuff = getFrameType(packet);
                    if (strcmp(frameTypeBuff, "Ethernet II") == 0) {
                        char* ethertype_buff;
                        ethertype_buff = getEtherType(packet, ethertypes);
                        char* protocolBuff;
                        protocolBuff = getProtocol(packet, IPProtocols);
                        char* portBuff;
                        if (protocolKey == 1)
                            portBuff = getTCPOrUDPPort(packet, TCPPorts);
                        else if (protocolKey == 2)
                            portBuff = getTCPOrUDPPort(packet, UDPPorts);
                        else
                            portBuff = getICMPPort(packet, ICMPPorts);

                        /*
                        printf("%d\n", frames);
                        printf("ethertype_buff: %s\n", ethertype_buff);
                        printf("protocolBuff: %s\n", protocolBuff);
                        printf("portBuff: %s\n", portBuff);
                        printf("choice2: %s\n", choice2);
                        printf("&categories[ethertypeKey][protocolKey][portKey]: %s\n", &categories[ethertypeKey][protocolKey][portKey]);
                        */

                        // ak nasiel hladany protokol
                        if (strcmp(portBuff, (const char *) &categories[ethertypeKey][protocolKey][portKey]) == 0 || strcmp(protocolBuff, "ICMP") == 0 && strcmp(choice2, protocolBuff) == 0) {
                            printBasicInfo(frames, pcapHeader->caplen, pcapHeader->len);
                            printf("\n%s", frameTypeBuff);
                            printMACAddress(packet);
                            printf("%s\n", ethertype_buff);
                            printIPAdresses(packet);
                            printf("%s\n", protocolBuff);
                            printf("%s\n", portBuff);
                            printSrcPortAndDstPort(packet);
                            printHexadecimal(pcapHeader->len, packet);
                            count++;
                            printf("\n=============================================================\n");
                        }
                    }
                }
                printf("Tento subor obsahoval %d protokolov typu %s.\n", count, choice2);
                pcap_close(pcap_file);
                frames = 0;
                ethertypeKey = 0;
                protocolKey = 0;
                portKey = 0;
                break;
            }

            case 3: {

                if ((pcap_file = pcap_open_offline(file_name, pcap_file_error)) == NULL) {
                    printf("Chyba pri otvoreni PCAP suboru.");
                    exit(0);
                }

                char choice2[20];
                fgets(choice2, 20, stdin);
                choice2[strlen(choice2) - 1] = '\0';
//                puts(choice2);

                if (strcasecmp(choice2, "HTTP") == 0 || strcasecmp(choice2, "HTTPS") == 0 || strcasecmp(choice2, "TELNET") == 0 || strcasecmp(choice2, "FTP CONTROL") == 0 || strcasecmp(choice2, "FTP DATA") == 0 || strcasecmp(choice2, "SSH") == 0) {
                    int ethertypeKey;
                    int protocolKey;
                    int portKey;

                    int i, j, k;
                    for (i = 1; i < 3; i++)
                        for (j = 0; j < 4; j++)
                            for (k = 0; k < 7; k++)
                                if (strcasecmp(choice2, (const char *) &categories[i][j][k][0]) == 0) {
                                    ethertypeKey = i;
                                    protocolKey = j;
                                    portKey = k;
                                }

                    // Inserting all packets to a list, which are specific protocol
                    while ((pcap_next_ex(pcap_file, &pcapHeader, &packet)) >= 0) {
                        frames++;
                        char* portBuff;
                        portBuff = getTCPOrUDPPort(packet, TCPPorts);

                        if (strcmp(portBuff, (const char *) &categories[ethertypeKey][protocolKey][portKey]) == 0 && findPacketInList(head, frames) == false)
                            insertPacketToList(&head, getSrcPort(packet), getDstPort(packet), getTCPFlag(packet), frames);
                    }

                    pcap_close(pcap_file);
                    frames = 0;

                    struct Packet *temp = head;
                    struct Packet *temp2 = temp;
                    struct Packet *temp3 = temp2;
                    struct Packet *temp4 = head;
                    struct Packet *temp5 = temp4;

                    char *firstCompleteComPort = "FAKE_EMPTY";
                    char *firstIncompleteComPort = "FAKE_EMPTY";

                    bool completeComFullfilled = false;
                    bool incompleteComFullfilled = false;

                    // Verify 3WHS and termination - find one complete and incomplete communication, save it's port
                    while (true) {
                        if (completeComFullfilled == true && incompleteComFullfilled == true)
                            break;

                        char *str1 = verify3WHS(temp, temp2, temp3);
                        char* token1;
                        char* rest1 = str1;
                        char *stringArray1[3];
                        int x1 = 0;
                        while ((token1 = strtok_r(rest1, " ", &rest1)))
                            stringArray1[x1++] = token1;
                        int tempFrameNumber1 = atoi(stringArray1[0]);
                        char *tempSrcPort1 = stringArray1[1];
                        printf("~~~~~~~~~~\n");
                        printf("[New loop]\n");
                        printf("start: %d Port: %s\n", tempFrameNumber1, tempSrcPort1);

                        // 3WHS Success, looking for complete com
                        if (strcmp(tempSrcPort1, "0") && completeComFullfilled == false) {
                            char *potentionalEnd = verifyTermination(temp4, temp5, tempFrameNumber1, tempSrcPort1);
                            printf("end: %s\n", potentionalEnd);
                            printf("~~~~~~~~~~\n");

                            // 4WHS Success aka complete com
                            if (strcmp(potentionalEnd, "0")) {
                                completeComFullfilled = true;
                                firstCompleteComPort = tempSrcPort1;
                                printf("[4WHS Success, first complete com]\n");
                                printf("1st COMPLETE com [ %s ] = start: %d\tend: %s\n", tempSrcPort1, tempFrameNumber1, potentionalEnd);
                                continue;
                            }

                                // 4WHS Fail at the first itaration
                            else if (strcmp(potentionalEnd, "0") == 0 && incompleteComFullfilled == false) {
                                firstIncompleteComPort = tempSrcPort1;
                                incompleteComFullfilled = true;
                                printf("[4WHS Fail, incomplete com fullfilled, first loop]\n");
                                printf("1st INCOMPLETE com [ %s ] = start: %d\tend: %s\n", tempSrcPort1, tempFrameNumber1, potentionalEnd);
                                continue;
                            }
                        }

                            // 3WHS Success, looking for incomplete com
                        else if (strcmp(tempSrcPort1, "0") && completeComFullfilled == true) {
                            printf("\n[3WHS Success, complete com fullfilled]\n");
                            char *potentionalEnd = verifyTermination(temp4, temp5, tempFrameNumber1, tempSrcPort1);
                            printf("end %s\n", potentionalEnd);
                            printf("~~~~~~~~~~\n");

                            if (strcmp(potentionalEnd, "0") == 0) {
                                incompleteComFullfilled = true;
                                firstIncompleteComPort = tempSrcPort1;
                                printf("[4WHS Fail, incomplete com fullfilled]\n");
                                printf("1st INCOMPLETE com [ %s ] = start: %d\tend: %s\n", tempSrcPort1, tempFrameNumber1, potentionalEnd);
                                break;
                            }
                        }
                            // 3WHS Fail
                        else {
                            printf("[3WHS Fail, no complete com found]\n");
                            break;
                        }
                    }

                    // Counting packets in the complete com
                    if ((pcap_file = pcap_open_offline(file_name, pcap_file_error)) == NULL) {
                        printf("Chyba pri otvoreni PCAP suboru.");
                        exit(0);
                    }
                    int completeComFrameCount = 0;
                    while ((pcap_next_ex(pcap_file, &pcapHeader, &packet)) >= 0) {
                        char* portBuff;
                        portBuff = getTCPOrUDPPort(packet, TCPPorts);
                        if (strcmp(portBuff, (const char *) &categories[ethertypeKey][protocolKey][portKey]) == 0 && (strcmp(getSrcPort(packet), firstCompleteComPort) == 0 || strcmp(getDstPort(packet), firstCompleteComPort) == 0))
                            completeComFrameCount++;
                    }
                    pcap_close(pcap_file);

                    if (completeComFrameCount != 0) {
                        printf("\n=============================================================\n");
                        printf("Prva kompletna komunikacia je pod portom %s, obsahuje %d ramcov", firstCompleteComPort, completeComFrameCount);
                        printf("\n=============================================================\n");
                    }

                    else {
                        printf("\n=============================================================\n");
                        printf("Subor neobsahoval ani jednu kompletnu komunikaciu");
                        printf("\n=============================================================\n");
                    }

                    // Printing the complete com
                    if ((pcap_file = pcap_open_offline(file_name, pcap_file_error)) == NULL) {
                        printf("Chyba pri otvoreni PCAP suboru.");
                        exit(0);
                    }
                    int printedCompleteComCount = 0;
                    while ((pcap_next_ex(pcap_file, &pcapHeader, &packet)) >= 0) {
                        frames++;
                        char* frameTypeBuff = getFrameType(packet);
                        char* ethertypeBuff;
                        ethertypeBuff = getEtherType(packet, ethertypes);
                        char* protocolBuff;
                        protocolBuff = getProtocol(packet, IPProtocols);
                        char* portBuff;
                        portBuff = getTCPOrUDPPort(packet, TCPPorts);

                        if (strcmp(portBuff, (const char *) &categories[ethertypeKey][protocolKey][portKey]) == 0 && (strcmp(getSrcPort(packet), firstCompleteComPort) == 0 || strcmp(getDstPort(packet), firstCompleteComPort) == 0)) {
                            printedCompleteComCount++;
                            if (completeComFrameCount > 20 && (printedCompleteComCount <= 10 || printedCompleteComCount > completeComFrameCount - 10) || completeComFrameCount <= 20) {
                                printBasicInfo(frames, pcapHeader->caplen, pcapHeader->len);
                                printf("\n%s", frameTypeBuff);
                                printMACAddress(packet);
                                printf("%s\n", ethertypeBuff);
                                printIPAdresses(packet);
                                printf("%s\n", protocolBuff);
                                printf("%s\n", portBuff);
                                printSrcPortAndDstPort(packet);
                                printHexadecimal(pcapHeader->len, packet);
                                printf("\n=============================================================\n");
                            }
                        }
                    }
                    pcap_close(pcap_file);
                    frames = 0;

                    // Counting packets in the incomplete com
                    if ((pcap_file = pcap_open_offline(file_name, pcap_file_error)) == NULL) {
                        printf("Chyba pri otvoreni PCAP suboru.");
                        exit(0);
                    }
                    int incompleteComFrameCount = 0;
                    while ((pcap_next_ex(pcap_file, &pcapHeader, &packet)) >= 0) {
                        char* portBuff;
                        portBuff = getTCPOrUDPPort(packet, TCPPorts);
                        if (strcmp(portBuff, (const char *) &categories[ethertypeKey][protocolKey][portKey]) == 0 && (strcmp(getSrcPort(packet), firstIncompleteComPort) == 0 || strcmp(getDstPort(packet), firstIncompleteComPort) == 0))
                            incompleteComFrameCount++;
                    }
                    pcap_close(pcap_file);

                    if (incompleteComFrameCount != 0) {
                        printf("Prva nekompletna komunikacia je pod portom %s, obsahuje %d ramcov", firstIncompleteComPort, incompleteComFrameCount);
                        printf("\n=============================================================\n");
                    }

                    else {
                        printf("Subor neobsahoval ani jednu nekompletnu komunikaciu");
                        printf("\n=============================================================\n");
                    }

                    // Printing the incomplete com
                    if ((pcap_file = pcap_open_offline(file_name, pcap_file_error)) == NULL) {
                        printf("Chyba pri otvoreni PCAP suboru.");
                        exit(0);
                    }
                    int printedIncompleteComCount = 0;
                    while ((pcap_next_ex(pcap_file, &pcapHeader, &packet)) >= 0) {
                        frames++;
                        char* frameTypeBuff = getFrameType(packet);
                        char* ethertypeBuff;
                        ethertypeBuff = getEtherType(packet, ethertypes);
                        char* protocolBuff;
                        protocolBuff = getProtocol(packet, IPProtocols);
                        char* portBuff;
                        portBuff = getTCPOrUDPPort(packet, TCPPorts);

                        if (strcmp(getSrcPort(packet), firstIncompleteComPort) == 0 || strcmp(getDstPort(packet), firstIncompleteComPort) == 0) {
                            printedIncompleteComCount++;
                            if (incompleteComFrameCount > 20 && (printedIncompleteComCount <= 10 || printedIncompleteComCount > incompleteComFrameCount - 10) || incompleteComFrameCount <= 20) {
                                printBasicInfo(frames, pcapHeader->caplen, pcapHeader->len);
                                printf("\n%s", frameTypeBuff);
                                printMACAddress(packet);
                                printf("%s\n", ethertypeBuff);
                                printIPAdresses(packet);
                                printf("%s\n", protocolBuff);
                                printf("%s\n", portBuff);
                                printSrcPortAndDstPort(packet);
                                printHexadecimal(pcapHeader->len, packet);
                                printf("\n=============================================================\n");
                            }
                        }
                    }

                    pcap_close(pcap_file);
                    deletePacketList(&head);
                    frames = 0;
                    ethertypeKey = 0;
                    protocolKey = 0;
                    portKey = 0;
                    break;
                }

                else {
                    printf("Bad luck\n");
                    pcap_close(pcap_file);
                    break;
                }

            }

            default:
                break;
        }
    } while (choice != 0);

    return 0;
}