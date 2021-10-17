#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <pcap/pcap.h>

bool debugMode = true;

struct IPv4Packet {
    char* srcIPAdress;
    int txPackets;
    struct IPv4Packet* next;
};

bool findIPv4PacketInList(struct IPv4Packet* head, char* data) {
    struct IPv4Packet* temp = head;
    while (temp != NULL) {
        if (strcasecmp(temp->srcIPAdress, data) == 0) {
            temp->txPackets++;
            return true;
        }
        temp = temp->next;
    }
    return false;
}

void insertIPv4PacketToList(struct IPv4Packet **headRef, char* srcIPAdress) {
    struct IPv4Packet* newNode = malloc(sizeof(struct IPv4Packet));
    struct IPv4Packet* last = *headRef;
    newNode->srcIPAdress = srcIPAdress;
    newNode->txPackets = 1;
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

struct TCPPacket {
    int frameNumber;
    char* srcPort;
    char* dstPort;
    char* flag;
    bool isMarked;
    struct TCPPacket* next;
};

bool findTCPPacketInList(struct TCPPacket* head, int frameNumber) {
    struct TCPPacket* temp = head;
    while (temp != NULL) {
        if (temp->frameNumber == frameNumber)
            return true;

        temp = temp->next;
    }
    return false;
}

void insertTCPPacketToList(struct TCPPacket **headRef, char* srcPort, char* dstPort, char* flag, int frameNumber) {
    struct TCPPacket* newNode = malloc(sizeof(struct TCPPacket));
    struct TCPPacket* last = *headRef;
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

void deleteTCPPacketList(struct TCPPacket** headRef) {
    struct TCPPacket* temp = *headRef;
    struct TCPPacket* next;

    while (temp != NULL) {
        next = temp->next;
        free(temp);
        temp = next;
    }
    *headRef = NULL;
}

void printTCPPacket(struct TCPPacket *node) {
    printf("~~~~~~~~~~\n");
    printf("%s\n", node->flag);
    printf("FRAME: %d\n", node->frameNumber);
    printf("SRC: %s\n", node->srcPort);
    printf("DST: %s\n", node->dstPort);
}

struct UDPPacket {
    int frameNumber;
    char* srcPort;
    struct UDPPacket* next;
};

bool findUDPPacketInList(struct UDPPacket* head, int frameNumber) {
    struct UDPPacket* temp = head;
    while (temp != NULL) {
        if (temp->frameNumber == frameNumber)
            return true;

        temp = temp->next;
    }
    return false;
}

void insertUDPPacketToList(struct UDPPacket **headRef, char* srcPort, int frameNumber) {
    struct UDPPacket* newNode = malloc(sizeof(struct UDPPacket));
    struct UDPPacket* last = *headRef;
    newNode->srcPort = srcPort;
    newNode->frameNumber = frameNumber;
    newNode->next = NULL;

    if (*headRef == NULL) {
        *headRef = newNode;
        return;
    }

    while (last->next != NULL)
        last = last->next;

    last->next = newNode;
}

void deleteUDPPacketList(struct UDPPacket** headRef) {
    struct UDPPacket* temp = *headRef;
    struct UDPPacket* next;

    while (temp != NULL) {
        next = temp->next;
        free(temp);
        temp = next;
    }
    *headRef = NULL;
}

struct ARPPacket {
    int frameNumber;
    char* srcIPAdress;
    char* dstIPAdress;
    char* srcMACAdress;
    char* dstMACAdress;
    char* opCode;
    bool isMarked;
    struct ARPPacket* next;
};

bool findARPPacketInList(struct ARPPacket* head, int frameNumber) {
    struct ARPPacket* temp = head;
    while (temp != NULL) {
        if (temp->frameNumber == frameNumber)
            return true;

        temp = temp->next;
    }
    return false;
}

void insertARPPacketToList(struct ARPPacket **headRef, int frameNumber, char* srcIPAdress, char* dstIPAdress, char* srcMACAdress, char* dstMACAdress, char* opCode) {
    struct ARPPacket* newNode = malloc(sizeof(struct ARPPacket));
    struct ARPPacket* last = *headRef;
    newNode->frameNumber = frameNumber;
    newNode->srcIPAdress = srcIPAdress;
    newNode->dstIPAdress = dstIPAdress;
    newNode->srcMACAdress = srcMACAdress;
    newNode->dstMACAdress = dstMACAdress;
    newNode->opCode = opCode;
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

void deleteARPPacketList(struct ARPPacket** headRef) {
    struct ARPPacket* temp = *headRef;
    struct ARPPacket* next;

    while (temp != NULL) {
        next = temp->next;
        free(temp);
        temp = next;
    }
    *headRef = NULL;
}

void printARPPacket(struct ARPPacket *node) {
    printf("~~~~~~~~~~\n");
    printf("%d\n", node->frameNumber);
    printf("SRC IP: %s\n", node->srcIPAdress);
    printf("DST IP: %s\n", node->dstIPAdress);
    printf("SRC MAC: %s\n", node->srcMACAdress);
    printf("DST MAC: %s\n", node->dstMACAdress);
    printf("OPCODE: %s\n", node->opCode);
}

void printMenu() {
    printf("\n0 - Koniec\n");
    printf("1 - Vypis vsetkych komunikacii\n");
    printf("2 - Filtrovanie podla protokolu\n");
    printf("3 - Vypis komunikacii podla protokolu (viacere moznosti)\n");
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
        printf("dlzka ramca prenasaneho po mediu - %d B\n", len);

}

void printHexadecimal(int i, const u_char* packet) {
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

char* getARPsrcIP (const u_char* packet) {
    char* ARPSRCIP;
    ARPSRCIP = malloc(sizeof(u_char) * 20);
    sprintf(ARPSRCIP, "%d.%d.%d.%d", packet[28], packet[29], packet[30], packet[31]);
    return ARPSRCIP;
}

char* getARPdstIP (const u_char* packet) {
    char* ARPDSTIP;
    ARPDSTIP = malloc(sizeof(u_char) * 20);
    sprintf(ARPDSTIP, "%d.%d.%d.%d", packet[38], packet[39], packet[40], packet[41]);
    return ARPDSTIP;
}

char* getSrcMAC (const u_char* packet) {
    char* srcMAC;
    srcMAC = malloc(sizeof(char) * 50);
    sprintf(srcMAC, "%.2X %.2X %.2X %.2X %.2X %.2X", packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);
    return srcMAC;
}

char* getDstMAC (const u_char* packet) {
    char* dstMAC;
    dstMAC = malloc(sizeof(char) * 50);
    sprintf(dstMAC, "%.2X %.2X %.2X %.2X %.2X %.2X", packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]);
    return dstMAC;
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

char* getFrameType(const u_char* packet) {
    if (packet[12] * 256 + packet[13] > 0x5DC)
        return "Ethernet II";
    else
        return "802.3";
}

char* getEthertypesFromTXT(const u_char* packet, FILE* ethertypes) {
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

char* getProtocolsFromTXT(const u_char* packet, FILE* IPProtocols) {
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

char* getTCPOrUDPPortsFromTXT(const u_char* packet, FILE* fileWithPorts) {
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

char* getICMPPortsFromTXT(const u_char* packet, FILE* ICMPPorts) {
    int valueInTheFile = 0;

    int realValue = packet[34];
    int realValue2 = packet[54];
    int realValue3 = packet[70];

    rewind(ICMPPorts);
    char c;
    char ICMPPortBuff[50] = { 0 };
    int i = 0;

    while ((c = getc(ICMPPorts)) != '-') {
        if (c == '#') {
            fscanf(ICMPPorts, "%x ", &valueInTheFile);
            if (realValue == valueInTheFile || realValue2 == valueInTheFile || realValue3 == valueInTheFile) {
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

char* getARPOperationsFromTXT(const u_char* packet, FILE* ARPFile) {
    int valueInTheFile = 0;

    int realValue = packet[20] * 256 + packet[21];
    rewind(ARPFile);
    char c;
    char ARPBuff[50] = { 0 };
    int i = 0;

    while ((c = getc(ARPFile)) != '-') {
        if (c == '#') {
            fscanf(ARPFile, "%x ", &valueInTheFile);
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

char* get802_3SAPsFromTXT(const u_char* packet, FILE* _802_3File)
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
            fscanf(_802_3File, "%x ", &valueInTheFile);
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

char* get802_3ProtocolsFromTXT(const u_char* packet, FILE* _802_3File, bool isJustLLC)
{
    int valueInTheFile = 0;
    int realValue1;
    int realValue2;
    int realValue3;

    if (isJustLLC == true) {
        realValue1 = packet[17];
        realValue2 = packet[18];
        realValue3 = packet[19];
    }

    // LLC + SNAP
    else {
        realValue1 = packet[22];
        realValue2 = packet[23];
        realValue3 = packet[24];
    }

    rewind(_802_3File);
    char c;
    char _802_3ProtocolBuff[50] = {0 };
    int i = 0;

    while ((c = getc(_802_3File)) != '-') {
        if (c == '#') {
            fscanf(_802_3File, "%x ", &valueInTheFile);
            if (isJustLLC == false && realValue1 == valueInTheFile && realValue2 == valueInTheFile && realValue3 == 2) {
                while ((c = getc(_802_3File)) != '\n')
                    if (c != '\t')
                        _802_3ProtocolBuff[i++] = c;
                break;
            }
            else if (isJustLLC == true && realValue1 == valueInTheFile && realValue2 == valueInTheFile && realValue3 == 0) {
                while ((c = getc(_802_3File)) != '\n')
                    if (c != '\t')
                        _802_3ProtocolBuff[i++] = c;
                break;
            }
        }
    }
    char* _802_3Protocol;
    _802_3Protocol = malloc(sizeof(u_char) * i);
    sprintf(_802_3Protocol, "%s", _802_3ProtocolBuff);

    return _802_3Protocol;
}

void openTxtFiles(FILE **_802_3SAPs, FILE **_802_3Protocols, FILE **ethertypes, FILE **IPProtocols, FILE **TCPPorts, FILE **UDPPorts, FILE **ICMPPorts, FILE **ARPOperations) {

    if (((*_802_3SAPs) = fopen("/home/zsolti/CLionProjects/PKS_Zadanie1_linux/txt/802_3SAPs.txt", "r")) == NULL) printf("Chyba pri otvoreni 802_3SAPs.txt suboru.\n");
    if (((*_802_3Protocols) = fopen("/home/zsolti/CLionProjects/PKS_Zadanie1_linux/txt/802_3Protocols.txt", "r")) == NULL) printf("Chyba pri otvoreni 802_3Protocols.txt suboru.\n");
    if (((*ethertypes) = fopen("/home/zsolti/CLionProjects/PKS_Zadanie1_linux/txt/ethertypes.txt", "r")) == NULL) printf("Chyba pri otvoreni ethertypes.txt suboru.\n");
    if (((*IPProtocols) = fopen("/home/zsolti/CLionProjects/PKS_Zadanie1_linux/txt/IPProtocols.txt", "r")) == NULL) printf("Chyba pri otvoreni IPProtocols.txt suboru.\n");
    if (((*TCPPorts) = fopen("/home/zsolti/CLionProjects/PKS_Zadanie1_linux/txt/TCPPorts.txt", "r")) == NULL) printf("Chyba pri otvoreni TCPPorts.txt suboru.\n");
    if (((*UDPPorts) = fopen("/home/zsolti/CLionProjects/PKS_Zadanie1_linux/txt/UDPPorts.txt", "r")) == NULL) printf("Chyba pri otvoreni UDPPorts.txt suboru.\n");
    if (((*ICMPPorts) = fopen("/home/zsolti/CLionProjects/PKS_Zadanie1_linux/txt/ICMPPorts.txt", "r")) == NULL) printf("Chyba pri otvoreni ICMPPorts.txt suboru.\n");
    if (((*ARPOperations) = fopen("/home/zsolti/CLionProjects/PKS_Zadanie1_linux/txt/ARPOperations.txt", "r")) == NULL) printf("Chyba pri otvoreni ARPOperations.txt suboru.\n");
}

char* verify3WHS(struct TCPPacket *temp, struct TCPPacket *temp2, struct TCPPacket *temp3) {
    while (temp != NULL) {
        if (strcasecmp(temp -> flag, "SYN") == 0 && temp -> isMarked == false) {
            while (temp2 != NULL) {
                if (temp -> isMarked == false && temp2 -> isMarked == false && temp -> frameNumber < temp2 -> frameNumber && strcasecmp(temp->srcPort, temp2->dstPort) == 0 && strcasecmp(temp->dstPort, temp2->srcPort) == 0  && strcasecmp(temp2->flag, "SYN, ACK") == 0) {
                    while (temp3 != NULL) {
                        if (temp -> isMarked == false && temp2 -> isMarked == false && temp3-> isMarked == false && temp2 -> frameNumber < temp3 -> frameNumber && strcasecmp(temp2->srcPort, temp3->dstPort) == 0 && strcasecmp(temp2->dstPort, temp3->srcPort) == 0 && strcasecmp(temp3->flag, "ACK") == 0) {
                            temp -> isMarked = true;
                            temp2 -> isMarked = true;
                            temp3 -> isMarked = true;

                            if (debugMode == true) {
                                printTCPPacket(temp);
                                printTCPPacket(temp2);
                                printTCPPacket(temp3);
                            }

                            char* _3WHSSYN = malloc(sizeof(u_char) * 20);
                            // FTP DATA
                            if (strcasecmp(temp -> srcPort, "20") == 0)
                                sprintf(_3WHSSYN, "%d %s", temp -> frameNumber, temp -> dstPort);
                            // HTTP, HTTPS, TELNET, SSH, TFP CONTROL
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
    char* no3WHS = malloc(sizeof(u_char) * 20);
    strcpy(no3WHS, "0 0");
    return no3WHS;
}

char* verifyTermination(struct TCPPacket *temp4, struct TCPPacket *temp5, int comStart, const char* clientsSourcePort) {
    while (temp4 != NULL) {
        if (comStart < temp4 -> frameNumber && temp4 -> isMarked == false && (strcasecmp(clientsSourcePort, temp4->dstPort) == 0 || strcasecmp(clientsSourcePort, temp4->srcPort) == 0 ) && strcasecmp(temp4->flag, "FIN") == 0) {

            if (strcasecmp(clientsSourcePort, temp4->dstPort) == 0) {
                while (temp5 != NULL) {
                    if (temp4->frameNumber < temp5->frameNumber && temp4->isMarked == false && temp5->isMarked == false && strcasecmp(clientsSourcePort, temp5->srcPort) == 0 && (strcasecmp(temp5->flag, "FIN") == 0 || strcasecmp(temp5->flag, "RST") == 0)) {
                        temp4 -> isMarked = true;
                        temp5 -> isMarked = true;

                        if (debugMode == true) {
                            printf("FIN or RST by HOST B\n");
                            printTCPPacket(temp4);
                            printTCPPacket(temp5);
                        }

                        char* FINbyServer = malloc(sizeof(u_char) * 20);
                        sprintf(FINbyServer, "%d", temp5 -> frameNumber);
                        return FINbyServer;
                    }
                    temp5 = temp5->next;
                }
            }

            else if (strcasecmp(clientsSourcePort, temp4->srcPort) == 0) {
                while (temp5 != NULL) {
                    if (temp4->frameNumber < temp5->frameNumber && temp4->isMarked == false && temp5->isMarked == false && strcasecmp(clientsSourcePort, temp5->dstPort) == 0  && (strcasecmp(temp5->flag, "FIN") == 0 || strcasecmp(temp5->flag, "RST") == 0)) {
                        temp4 -> isMarked = true;
                        temp5 -> isMarked = true;

                        if (debugMode == true) {
                            printf("FIN or RST by HOST A\n");
                            printTCPPacket(temp4);
                            printTCPPacket(temp5);
                        }

                        char* FINbyClient = malloc(sizeof(u_char) * 20);
                        sprintf(FINbyClient, "%d", temp5 -> frameNumber);
                        return FINbyClient;
                    }
                    temp5 = temp5->next;
                }
            }
        }

        else if (comStart < temp4 -> frameNumber && temp4 -> isMarked == false && (strcasecmp(clientsSourcePort, temp4->dstPort) == 0 || strcasecmp(clientsSourcePort, temp4->srcPort) == 0 ) && strcasecmp(temp4->flag, "RST") == 0) {
            temp4 -> isMarked = true;
            if (debugMode == true) {
                printf("Only RST by HOST A or HOST B\n");
                printTCPPacket(temp4);
                printTCPPacket(temp5);
            }
            char* onlyRST = malloc(sizeof(u_char) * 20);
            sprintf(onlyRST, "%d", temp4 -> frameNumber);
            return onlyRST;
        }
        temp4 = temp4->next;
    }
    char* notTerminated = malloc(sizeof(u_char) * 20);
    strcpy(notTerminated, "0");
    return notTerminated;
}

char* connectARPPairs (struct ARPPacket *temp, struct ARPPacket *temp2) {
    while (temp != NULL) {
        if (strcasecmp(temp -> opCode, "Request") == 0 && temp->isMarked == false) {
            while (temp2 != NULL) {
                if (strcasecmp(temp2 -> opCode, "Reply") == 0  && temp2->isMarked == false && temp->frameNumber < temp2->frameNumber) {
                    if (strcmp(temp->srcMACAdress, temp2->dstMACAdress) == 0) {
                        temp->isMarked = true;
                        temp2->isMarked = true;

                        if (debugMode == true) {
                            printARPPacket(temp);
                            printARPPacket(temp2);
                        }

                        char* ARPPair = malloc(sizeof(u_char) * 20);
                        sprintf(ARPPair, "%d %d", temp -> frameNumber, temp2 -> frameNumber);
                        return ARPPair;
                    }
                    else
                        break;
                }
                temp2 = temp2 -> next;
            }
        }
        temp = temp -> next;
    }

    char* noARPPair = malloc(sizeof(u_char) * 20);
    strcpy(noARPPair, "0 0");
    return noARPPair;
}

int differenceSetOperation(int* excludeFrames, int excludeSize, int yy, const int* bufferArraySet, int* finalSet) {
    int i = 0;
    int j = 0;
    int k = 0;
    int flag = 0;

    for (i = 0; i < yy; i++) {
        flag = 1;
        for (j = 0; j < excludeSize; j++) {
            if (bufferArraySet[i] == excludeFrames[j]) {
                flag = 0;
                break;
            }
        }
        if (flag == 1) {
            finalSet[k] = bufferArraySet[i];
            k++;
        }
    }
    return k;
}

int main() {

    char* file_name = { "/home/zsolti/CLionProjects/PKS_Zadanie1_linux/vzorky_pcap_na_analyzu/trace-2.pcap" }; // sem vlozit subor
    char pcap_file_error[PCAP_ERRBUF_SIZE];
    pcap_t* pcap_file;

    FILE *_802_3SAPs;
    FILE *_802_3Protocols;
    FILE *ethertypes;
    FILE *IPProtocols;
    FILE *TCPPorts;
    FILE *UDPPorts;
    FILE *ICMPPorts;
    FILE *ARPOperations;
    openTxtFiles(&_802_3SAPs, &_802_3Protocols, &ethertypes, &IPProtocols, &TCPPorts, &UDPPorts, &ICMPPorts, &ARPOperations);

    struct pcap_pkthdr* pcapHeader;
    const u_char* packet;
    struct IPv4Packet* IPv4Head = NULL;
    struct ARPPacket* ARPhead = NULL;
    struct TCPPacket* TCPhead = NULL;
    struct UDPPacket* UDPhead = NULL;
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
                    char* frameTypeBuff = getFrameType(packet);

                    // Je 802.3
                    if (strcasecmp(frameTypeBuff, "802.3") == 0) {

                        // ramec cislo x, dlzky ramca
                        printBasicInfo(frames, pcapHeader->caplen, pcapHeader->len);

                        // 802.3
                        printf("%s ", frameTypeBuff);

                        char* _802_3Buff = get802_3SAPsFromTXT(packet, _802_3SAPs);

                        // Global DSAP == FF == RAW
                        if (strcasecmp(_802_3Buff, "Global DSAP") == 0) {
                            printf("RAW\n");
                            printf("%s\n", _802_3Buff);
                        }

                        // SNAP == AA == SNAP + LLC
                        else if (strcasecmp(_802_3Buff, "SNAP") == 0) {
                            printf("LLC + %s\n", _802_3Buff);
                            char* _802_3ProtocolBuff = get802_3ProtocolsFromTXT(packet, _802_3Protocols, false);
                            printf("%s\n", _802_3ProtocolBuff);

                        }

                        // LLC, ani jeden
                        else {
                            printf("LLC\n");
                            printf("%s\n", _802_3Buff);
                            char* _802_3ProtocolBuff = get802_3ProtocolsFromTXT(packet, _802_3Protocols, true);
                            printf("%s\n", _802_3ProtocolBuff);
                        }

                        printf("Zdrojova MAC adresa: %s\n", getSrcMAC(packet));
                        printf("Cielova MAC adresa: %s\n", getDstMAC(packet));
                    }

                    // Je Ethernet II
                    else if (strcasecmp(frameTypeBuff, "Ethernet II") == 0) {
                        char* ethertypeBuff = getEthertypesFromTXT(packet, ethertypes);

                        // Je ARP, vypiseme ARP-Request/Reply,IP, MAC
                        if (strcasecmp(ethertypeBuff, "ARP") == 0) {
                            char* ARPBuff = getARPOperationsFromTXT(packet, ARPOperations);
                            char* ARPDSTIP = getARPdstIP(packet);
                            char* ARPSRCIP = getARPsrcIP(packet);
                            char* ARPSRCMAC = getSrcMAC(packet);
                            char* ARPDSTMAC = getDstMAC(packet);

                            // Request
                            if (strcasecmp(ARPBuff, "Request") == 0) {
                                printf("%s-%s, IP Adresa: %s, MAC Adresa: %s\n", ethertypeBuff, ARPBuff, ARPDSTIP, ARPDSTMAC);
                                printf("Zdrojova IP: %s, Cielova IP: %s\n", ARPSRCIP, ARPDSTIP);
                            }

                            // Reply
                            else {
                                printf("%s-%s, IP Adresa: %s, MAC Adresa: %s\n", ethertypeBuff, ARPBuff, ARPSRCIP, ARPSRCMAC);
                                printf("Zdrojova IP: %s, Cielova IP: %s\n", ARPSRCIP, ARPDSTIP);
                            }

                            printBasicInfo(frames, pcapHeader->caplen, pcapHeader->len);
                            printf("%s\n", frameTypeBuff);
                            printf("%s\n", ethertypeBuff);
                            printf("Zdrojova MAC adresa: %s\n", getSrcMAC(packet));
                            printf("Cielova MAC adresa: %s\n", getDstMAC(packet));
                        }

                        // Je IP
                        else if (strcasecmp(ethertypeBuff, "ARP") != 0) {
                            printBasicInfo(frames, pcapHeader->caplen, pcapHeader->len);
                            printf("%s\n", frameTypeBuff);
                            printf("Zdrojova MAC adresa: %s\n", getSrcMAC(packet));
                            printf("Cielova MAC adresa: %s\n", getDstMAC(packet));
                            printf("%s\n", ethertypeBuff);
                            printf("zdrojova IP adresa: %s\n", getSrcIP(packet));
                            printf("cielova IP adresa: %s\n", getDstIP(packet));
                            char* protocolBuff = getProtocolsFromTXT(packet, IPProtocols);
                            printf("%s\n", protocolBuff);

                            char* srcIPBuff = getSrcIP(packet);
                            if ((strcasecmp(ethertypeBuff, "IPv4") == 0) && findIPv4PacketInList(IPv4Head, srcIPBuff) == false)
                                insertIPv4PacketToList(&IPv4Head, getSrcIP(packet));

                            char* portBuff;
                            if (strcasecmp(protocolBuff, "TCP") == 0) {
                                portBuff = getTCPOrUDPPortsFromTXT(packet, TCPPorts);
                                printf("%s\n", portBuff);
                                printf("zdrojovy port: %s\n", getSrcPort(packet));
                                printf("cielovy port: %s\n", getDstPort(packet));
                            }

                            else if (strcasecmp(protocolBuff, "UDP") == 0) {
                                portBuff = getTCPOrUDPPortsFromTXT(packet, UDPPorts);
                                printf("%s\n", portBuff);
                                printf("zdrojovy port: %s\n", getSrcPort(packet));
                                printf("cielovy port: %s\n", getDstPort(packet));
                            }

                            else if (strcasecmp(protocolBuff, "ICMP") == 0) {
                                portBuff = getICMPPortsFromTXT(packet, ICMPPorts);
                                printf("%s\n", portBuff);
                                printf("zdrojovy port: %s\n", getSrcPort(packet));
                                printf("cielovy port: %s\n", getDstPort(packet));
                            }
                        }
                    }

                    printHexadecimal(pcapHeader -> len, packet);
                    printf("\n=============================================================\n");

                }
                printf("IP adresy vysielajucich uzlov:\n");
                printIPv4PacketList(IPv4Head);
                printIPWithTheMostPacketsSent(IPv4Head);
                frames = 0;
                pcap_close(pcap_file);
                deleteIPv4PacketList(&IPv4Head);

                break;
            }

            case 2: {

                if ((pcap_file = pcap_open_offline(file_name, pcap_file_error)) == NULL) {
                    printf("Chyba pri otvoreni PCAP suboru.");
                    exit(0);
                }

                printf("Zadajte protokol.\n");
                char choice2[20];
                fgets(choice2, 20, stdin);
                choice2[strlen(choice2) - 1] = '\0';

                int count = 0;

                while ((pcap_next_ex(pcap_file, &pcapHeader, &packet)) >= 0) {
                    frames++;
                    char* frameTypeBuff = getFrameType(packet);

                    // Ethernet II
                    if (strcasecmp(frameTypeBuff, "Ethernet II") == 0) {
                        char* ethertypeBuff = getEthertypesFromTXT(packet, ethertypes);

                        // IPv4
                        if (strcasecmp(ethertypeBuff, "IPv4") == 0) {
                            char* protocolBuff = getProtocolsFromTXT(packet, IPProtocols);

                            //TCP
                            if (strcasecmp(protocolBuff, "TCP") == 0) {
                                char* portBuff = getTCPOrUDPPortsFromTXT(packet, TCPPorts);
                                if (strcasecmp(portBuff, choice2) == 0) {
                                    printBasicInfo(frames, pcapHeader->caplen, pcapHeader->len);
                                    printf("%s\n", frameTypeBuff);
                                    printf("Zdrojova MAC adresa: %s\n", getSrcMAC(packet));
                                    printf("Cielova MAC adresa: %s\n", getDstMAC(packet));
                                    printf("%s\n", ethertypeBuff);
                                    printf("zdrojova IP adresa: %s\n", getSrcIP(packet));
                                    printf("cielova IP adresa: %s\n", getDstIP(packet));
                                    printf("%s\n", protocolBuff);
                                    printf("%s\n", portBuff);
                                    printf("zdrojovy port: %s\n", getSrcPort(packet));
                                    printf("cielovy port: %s\n", getDstPort(packet));
                                    printHexadecimal(pcapHeader->len, packet);
                                    count++;
                                    printf("\n=============================================================\n");
                                }

                            }

                            // UDP
                            else if (strcasecmp(protocolBuff, "UDP") == 0) {
                                char* portBuff = getTCPOrUDPPortsFromTXT(packet, UDPPorts);
                                if (strcasecmp(portBuff, choice2) == 0) {
                                    printBasicInfo(frames, pcapHeader->caplen, pcapHeader->len);
                                    printf("%s\n", frameTypeBuff);
                                    printf("Zdrojova MAC adresa: %s\n", getSrcMAC(packet));
                                    printf("Cielova MAC adresa: %s\n", getDstMAC(packet));
                                    printf("%s\n", ethertypeBuff);
                                    printf("zdrojova IP adresa: %s\n", getSrcIP(packet));
                                    printf("cielova IP adresa: %s\n", getDstIP(packet));
                                    printf("%s\n", protocolBuff);
                                    printf("%s\n", portBuff);
                                    printf("zdrojovy port: %s\n", getSrcPort(packet));
                                    printf("cielovy port: %s\n", getDstPort(packet));
                                    printHexadecimal(pcapHeader->len, packet);
                                    count++;
                                    printf("\n=============================================================\n");
                                }

                            }

                            // ICMP
                            else if (strcasecmp(protocolBuff, "ICMP") == 0) {
                                char* portBuff = getICMPPortsFromTXT(packet, ICMPPorts);
                                if (strcasecmp(protocolBuff, choice2) == 0) {
                                    printBasicInfo(frames, pcapHeader->caplen, pcapHeader->len);
                                    printf("%s\n", frameTypeBuff);
                                    printf("Zdrojova MAC adresa: %s\n", getSrcMAC(packet));
                                    printf("Cielova MAC adresa: %s\n", getDstMAC(packet));
                                    printf("%s\n", ethertypeBuff);
                                    printf("zdrojova IP adresa: %s\n", getSrcIP(packet));
                                    printf("cielova IP adresa: %s\n", getDstIP(packet));
                                    printf("%s\n", protocolBuff);
                                    printf("%s\n", portBuff);
                                    printHexadecimal(pcapHeader->len, packet);
                                    count++;
                                    printf("\n=============================================================\n");
                                }

                            }
                        }
                        if (strcasecmp(ethertypeBuff, "ARP") == 0) {
                            if (strcasecmp(ethertypeBuff, choice2) == 0) {
                                char* ARPBuff = getARPOperationsFromTXT(packet, ARPOperations);
                                char* ARPDSTIP = getARPdstIP(packet);
                                char* ARPSRCIP = getARPsrcIP(packet);
                                char* ARPSRCMAC = getSrcMAC(packet);
                                char* ARPDSTMAC = getDstMAC(packet);

                                // Request
                                if (strcasecmp(ARPBuff, "Request") == 0) {
                                    printf("%s-%s, IP Adresa: %s, MAC Adresa: %s\n", ethertypeBuff, ARPBuff, ARPDSTIP, ARPDSTMAC);
                                    printf("Zdrojova IP: %s, Cielova IP: %s\n", ARPSRCIP, ARPDSTIP);
                                }

                                // Reply
                                else {
                                    printf("%s-%s, IP Adresa: %s, MAC Adresa: %s\n", ethertypeBuff, ARPBuff, ARPSRCIP, ARPSRCMAC);
                                    printf("Zdrojova IP: %s, Cielova IP: %s\n", ARPSRCIP, ARPDSTIP);
                                }

                                printBasicInfo(frames, pcapHeader->caplen, pcapHeader->len);
                                printf("%s\n", frameTypeBuff);
                                printf("%s\n", ethertypeBuff);
                                printf("Zdrojova MAC adresa: %s\n", getSrcMAC(packet));
                                printf("Cielova MAC adresa: %s\n", getDstMAC(packet));
                                printHexadecimal(pcapHeader->len, packet);
                                printf("\n=============================================================\n");
                                count++;
                            }
                        }
                    }

                    // 802.3
                    else if (strcasecmp(frameTypeBuff, "802.3") == 0) {
                        char* _802_3Buff = get802_3SAPsFromTXT(packet, _802_3SAPs);
                            // AA
                            if (strcasecmp(_802_3Buff, "SNAP") == 0) {
                                char* _802_3ProtocolBuff = get802_3ProtocolsFromTXT(packet, _802_3Protocols, false);
                                if (strcmp(_802_3ProtocolBuff, "STP") == 0) {
                                    if (strcmp(_802_3ProtocolBuff, choice2) == 0) {
                                        printBasicInfo(frames, pcapHeader->caplen, pcapHeader->len);
                                        printf("%s ", frameTypeBuff);
                                        printf("%s + LLC\n", _802_3Buff);
                                        printf("%s\n", _802_3ProtocolBuff);
                                        printf("Zdrojova MAC adresa: %s\n", getSrcMAC(packet));
                                        printf("Cielova MAC adresa: %s\n", getDstMAC(packet));
                                        printHexadecimal(pcapHeader->len, packet);
                                        count++;
                                        printf("\n=============================================================\n");
                                    }
                                }
                            }

                            // Just LLC
                            else if (strcasecmp(_802_3Buff, "BPDU (Bridge PDU / 802.1 Spanning Tree)") == 0) {
                                char* _802_3ProtocolBuff = get802_3ProtocolsFromTXT(packet, _802_3Protocols, true);
                                if (strcmp(_802_3ProtocolBuff, "STP") == 0) {
                                    if (strcmp(_802_3ProtocolBuff, choice2) == 0){
                                        printBasicInfo(frames, pcapHeader->caplen, pcapHeader->len);
                                        printf("%s ", frameTypeBuff);
                                        printf("LLC\n");
                                        printf("%s\n", _802_3Buff);
                                        printf("%s\n", _802_3ProtocolBuff);
                                        printf("Zdrojova MAC adresa: %s\n", getSrcMAC(packet));
                                        printf("Cielova MAC adresa: %s\n", getDstMAC(packet));
                                        printHexadecimal(pcapHeader->len, packet);
                                        count++;
                                        printf("\n=============================================================\n");
                                    }
                                }
                            }
                    }
                }
                printf("Tento subor obsahoval %d protokolov typu %s.\n", count, choice2);
                frames = 0;
                pcap_close(pcap_file);

                break;
            }

            case 3: {

                printf("Zadajte protokol. Moznosti su:\n\nHTTP\nHTTPS\nTELNET\nSSH\nFTP CONTROL\nFTP DATA\nTFTP\nICMP\nARP\n");
                printf("\n=============================================================\n");
                char choice2[20];
                fgets(choice2, 20, stdin);
                choice2[strlen(choice2) - 1] = '\0';

                if (strcasecmp(choice2, "HTTP") == 0 || strcasecmp(choice2, "HTTPS") == 0 || strcasecmp(choice2, "TELNET") == 0 ||
                    strcasecmp(choice2, "FTP CONTROL") == 0 || strcasecmp(choice2, "FTP DATA") == 0 || strcasecmp(choice2, "SSH") == 0 ||
                    strcasecmp(choice2, "TFTP") == 0 || strcasecmp(choice2, "ICMP") == 0 || strcasecmp(choice2, "ARP") == 0) {

                    // If not ICMP, insert all frames to a list if meets port criteria
                    if (strcasecmp(choice2, "ICMP")) {
                        if ((pcap_file = pcap_open_offline(file_name, pcap_file_error)) == NULL) {
                            printf("Chyba pri otvoreni PCAP suboru.");
                            exit(0);
                        }
                        while ((pcap_next_ex(pcap_file, &pcapHeader, &packet)) >= 0) {
                            frames++;
                            char* frameTypeBuff = getFrameType(packet);

                            // Ethernet II
                            if (strcasecmp(frameTypeBuff, "Ethernet II") == 0) {
                                char* ethertypeBuff = getEthertypesFromTXT(packet, ethertypes);

                                // IPv4
                                if (strcasecmp(ethertypeBuff, "IPv4") == 0) {
                                    char* protocolBuff = getProtocolsFromTXT(packet, IPProtocols);

                                    // TCP
                                    if (strcasecmp(protocolBuff, "TCP") == 0) {
                                        char* portBuff = getTCPOrUDPPortsFromTXT(packet, TCPPorts);
                                        if (strcasecmp(portBuff, choice2) == 0 && findTCPPacketInList(TCPhead, frames) == false)
                                            insertTCPPacketToList(&TCPhead, getSrcPort(packet), getDstPort(packet), getTCPFlag(packet), frames);
                                    }

                                    // UDP
                                    else if (strcasecmp(protocolBuff, "UDP") == 0) {
                                        char* portBuff = getTCPOrUDPPortsFromTXT(packet, UDPPorts);
                                        if (strcasecmp(portBuff, choice2) == 0 && findUDPPacketInList(UDPhead, frames) == false)
                                            insertUDPPacketToList(&UDPhead, getSrcPort(packet), frames);
                                        }
                                    }

                                // ARP
                                else if (strcasecmp(ethertypeBuff, "ARP") == 0) {
                                    if (strcasecmp(ethertypeBuff, choice2) == 0 && findARPPacketInList(ARPhead, frames) == false)
                                        insertARPPacketToList(&ARPhead, frames, getARPsrcIP(packet), getARPdstIP(packet),
                                                              getSrcMAC(packet), getDstMAC(packet),
                                                              getARPOperationsFromTXT(packet, ARPOperations));
                                    }
                                }
                            }
                        frames = 0;
                        pcap_close(pcap_file);
                    }

                    // ARP [ 100 % ]
                    if (strcasecmp("ARP", choice2) == 0) {

                        struct ARPPacket *temp = ARPhead;
                        struct ARPPacket *temp2 = temp;
                        struct ARPPacket *temp3 = temp2;

                        int allARPComs = 0;
                        while (temp3 != NULL) {
                            allARPComs++;
                            temp3 = temp3->next;
                        }

                        int excludeFrames[allARPComs];
                        int exclude = 0;

                        // Search for pairs, save their framenumbers and print it
                        while (true) {
                            char* string = connectARPPairs(temp, temp2);
                            char* token;
                            char* rest = string;
                            char* stringArray[3];
                            int buffer = 0;
                            while ((token = strtok_r(rest, " ", &rest)))
                                stringArray[buffer++] = token;
                            int tempRequestFN = atoi(stringArray[0]);
                            int tempReplyFN = atoi(stringArray[1]);
                            if (debugMode)
                                printf("%d -> %d\n", tempRequestFN, tempReplyFN);

                            if (tempRequestFN == 0 || tempReplyFN == 0)
                                break;

                            else {
                                excludeFrames[exclude++] = tempRequestFN;
                                excludeFrames[exclude++] = tempReplyFN;

                                printf("Komunikacia c.%d", exclude/2);
                                printf("\n=============================================================\n");

                                if ((pcap_file = pcap_open_offline(file_name, pcap_file_error)) == NULL) {
                                    printf("Chyba pri otvoreni PCAP suboru.");
                                    exit(0);
                                }

                                while ((pcap_next_ex(pcap_file, &pcapHeader, &packet)) >= 0) {
                                    frames++;
                                    if (frames == tempRequestFN || frames == tempReplyFN) {
                                        char* frameTypeBuff = getFrameType(packet);
                                        char* ethertypeBuff = getEthertypesFromTXT(packet, ethertypes);
                                        char* ARPBuff = getARPOperationsFromTXT(packet, ARPOperations);
                                        char* ARPDSTIP = getARPdstIP(packet);
                                        char* ARPSRCIP = getARPsrcIP(packet);
                                        char* ARPSRCMAC = getSrcMAC(packet);
                                        char* ARPDSTMAC = getDstMAC(packet);

                                        // Request
                                        if (strcasecmp(ARPBuff, "Request") == 0) {
                                            printf("%s-%s, IP Adresa: %s, MAC Adresa: %s\n", ethertypeBuff, ARPBuff, ARPDSTIP, ARPDSTMAC);
                                            printf("Zdrojova IP: %s, Cielova IP: %s\n", ARPSRCIP, ARPDSTIP);
                                            printBasicInfo(frames, pcapHeader->caplen, pcapHeader->len);
                                            printf("%s\n", frameTypeBuff);
                                            printf("%s\n", ethertypeBuff);
                                            printf("Zdrojova MAC adresa: %s\n", getSrcMAC(packet));
                                            printf("Cielova MAC adresa: %s\n", getDstMAC(packet));
                                            printHexadecimal(pcapHeader->len, packet);
                                            printf("\n=============================================================\n");
                                        }

                                        // Reply
                                        else {
                                            printf("%s-%s, IP Adresa: %s, MAC Adresa: %s\n", ethertypeBuff, ARPBuff, ARPSRCIP, ARPSRCMAC);
                                            printf("Zdrojova IP: %s, Cielova IP: %s\n", ARPSRCIP, ARPDSTIP);
                                            printBasicInfo(frames, pcapHeader->caplen, pcapHeader->len);
                                            printf("%s\n", frameTypeBuff);
                                            printf("%s\n", ethertypeBuff);
                                            printf("Zdrojova MAC adresa: %s\n", getSrcMAC(packet));
                                            printf("Cielova MAC adresa: %s\n", getDstMAC(packet));
                                            printHexadecimal(pcapHeader->len, packet);
                                            printf("\n=============================================================\n");
                                            break;
                                        }
                                    }
                                }
                                frames = 0;
                                pcap_close(pcap_file);
                            }
                        }
                        if (debugMode)
                            printf("exclude: %d\n", exclude);

                        // Make difference operation from two arrays
                        if ((pcap_file = pcap_open_offline(file_name, pcap_file_error)) == NULL) {
                            printf("Chyba pri otvoreni PCAP suboru.");
                            exit(0);
                        }

                        while ((pcap_next_ex(pcap_file, &pcapHeader, &packet)) >= 0)
                            frames++;

                        pcap_close(pcap_file);

                        int buffer;
                        int bufferArraySet[frames];
                        int finalSet[frames - exclude];
                        for (buffer = 0; buffer < frames; buffer++) {
                            bufferArraySet[buffer] = buffer + 1;
                        }
                        frames = 0;

                        int kk = differenceSetOperation(excludeFrames, exclude, buffer, bufferArraySet, finalSet);
                        int finalSetSize = kk;

                        if (debugMode)
                            printf("finalSetSize: %d\n", finalSetSize);

                        // ARP Requests without Replies
                        if ((pcap_file = pcap_open_offline(file_name, pcap_file_error)) == NULL) {
                            printf("Chyba pri otvoreni PCAP suboru.");
                            exit(0);
                        }

                        printf("ARP Requesty bez Reply:");
                        printf("\n=============================================================\n");
                        int requestsWithoutReplies = 0;

                        while ((pcap_next_ex(pcap_file, &pcapHeader, &packet)) >= 0) {
                            frames++;
                            char* frameTypeBuff = getFrameType(packet);
                            char* ethertypeBuff = getEthertypesFromTXT(packet, ethertypes);
                            char* ARPBuff = getARPOperationsFromTXT(packet, ARPOperations);
                            for(kk = 0; kk < finalSetSize; kk++) {
                                if (strcasecmp(ethertypeBuff, "ARP") == 0 && strcasecmp(ARPBuff, "Request") == 0 && frames == finalSet[kk]) {
                                    requestsWithoutReplies++;
                                    char* ARPDSTIP = getARPdstIP(packet);
                                    char* ARPSRCIP = getARPsrcIP(packet);
                                    char* ARPSRCMAC = getSrcMAC(packet);
                                    char* ARPDSTMAC = getDstMAC(packet);
                                    printf("%s-%s, IP Adresa: %s, MAC Adresa: %s\n", ethertypeBuff, ARPBuff, ARPDSTIP, ARPDSTMAC);
                                    printf("Zdrojova IP: %s, Cielova IP: %s\n", ARPSRCIP, ARPDSTIP);
                                    printBasicInfo(frames, pcapHeader->caplen, pcapHeader->len);
                                    printf("%s\n", frameTypeBuff);
                                    printf("%s\n", ethertypeBuff);
                                    printf("Zdrojova MAC adresa: %s\n", getSrcMAC(packet));
                                    printf("Cielova MAC adresa: %s\n", getDstMAC(packet));
                                    printHexadecimal(pcapHeader->len, packet);
                                    printf("\n=============================================================\n");
                                }
                            }
                        }

                        if (requestsWithoutReplies == 0) {
                            printf("Subor neobsahoval ARP Requesty bez Reply.");
                            printf("\n=============================================================\n");
                        }

                        frames = 0;
                        pcap_close(pcap_file);

                        // ARP Replies without Requests
                        if ((pcap_file = pcap_open_offline(file_name, pcap_file_error)) == NULL) {
                            printf("Chyba pri otvoreni PCAP suboru.");
                            exit(0);
                        }

                        printf("ARP Reply bez Requestu:");
                        printf("\n=============================================================\n");
                        int repliesWithoutRequests = 0;

                        while ((pcap_next_ex(pcap_file, &pcapHeader, &packet)) >= 0) {
                            frames++;
                            char* frameTypeBuff = getFrameType(packet);
                            char* ethertypeBuff = getEthertypesFromTXT(packet, ethertypes);
                            char* ARPBuff = getARPOperationsFromTXT(packet, ARPOperations);
                            for(kk = 0; kk < finalSetSize; kk++) {
                                if (strcasecmp(ethertypeBuff, "ARP") == 0 && strcasecmp(ARPBuff, "Reply") == 0 && frames == finalSet[kk]) {
                                    repliesWithoutRequests++;
                                    char* ARPDSTIP = getARPdstIP(packet);
                                    char* ARPSRCIP = getARPsrcIP(packet);
                                    char* ARPSRCMAC = getSrcMAC(packet);
                                    char* ARPDSTMAC = getDstMAC(packet);
                                    printf("%s-%s, IP Adresa: %s, MAC Adresa: %s\n", ethertypeBuff, ARPBuff, ARPSRCIP, ARPSRCMAC);
                                    printf("Zdrojova IP: %s, Cielova IP: %s\n", ARPSRCIP, ARPDSTIP);
                                    printBasicInfo(frames, pcapHeader->caplen, pcapHeader->len);
                                    printf("%s\n", frameTypeBuff);
                                    printf("%s\n", ethertypeBuff);
                                    printf("Zdrojova MAC adresa: %s\n", getSrcMAC(packet));
                                    printf("Cielova MAC adresa: %s\n", getDstMAC(packet));
                                    printHexadecimal(pcapHeader->len, packet);
                                    printf("\n=============================================================\n");
                                }
                            }
                        }

                        if (repliesWithoutRequests == 0) {
                            printf("Subor neobsahoval ARP Reply bez Requestu.");
                            printf("\n=============================================================\n");
                        }

                        frames = 0;
                        pcap_close(pcap_file);
                        deleteARPPacketList(&ARPhead);
                        break;
                    }

                    // UDP
                    else if (strcasecmp("TFTP", choice2) == 0) {

                        struct UDPPacket *temp = UDPhead;
                        int TFTPComs = 0;

                        while (temp != NULL) {

                            if ((pcap_file = pcap_open_offline(file_name, pcap_file_error)) == NULL) {
                                printf("Chyba pri otvoreni PCAP suboru.");
                                exit(0);
                            }

                            TFTPComs++;
                            printf("\nKomunikacia c.%d", TFTPComs);
                            printf("\n=============================================================\n");
                            int completeComFrameCount = 0;
                            int printedCompleteComCount = 0;

                            while ((pcap_next_ex(pcap_file, &pcapHeader, &packet)) >= 0) {
                                frames++;
                                if (strcasecmp(temp -> srcPort, getSrcPort(packet)) == 0  && temp -> frameNumber <= frames || strcasecmp(temp -> srcPort, getDstPort(packet)) == 0  && temp -> frameNumber <= frames)
                                    completeComFrameCount++;

                            }
                            frames = 0;
                            pcap_close(pcap_file);

                            if ((pcap_file = pcap_open_offline(file_name, pcap_file_error)) == NULL) {
                                printf("Chyba pri otvoreni PCAP suboru.");
                                exit(0);
                            }

                            while ((pcap_next_ex(pcap_file, &pcapHeader, &packet)) >= 0) {
                                frames++;
                                if (strcasecmp(temp -> srcPort, getSrcPort(packet)) == 0  && temp -> frameNumber <= frames || strcasecmp(temp -> srcPort, getDstPort(packet)) == 0  && temp -> frameNumber <= frames) {
                                    printedCompleteComCount++;
                                    if (completeComFrameCount > 20 && (printedCompleteComCount <= 10 || printedCompleteComCount > completeComFrameCount - 10) || completeComFrameCount <= 20) {
                                        char* frameTypeBuff = getFrameType(packet);
                                        char* ethertypeBuff = getEthertypesFromTXT(packet, ethertypes);
                                        char* protocolBuff = getProtocolsFromTXT(packet, IPProtocols);
                                        char* portBuff = getTCPOrUDPPortsFromTXT(packet, UDPPorts);
                                        printBasicInfo(frames, pcapHeader->caplen, pcapHeader->len);
                                        printf("%s\n", frameTypeBuff);
                                        printf("Zdrojova MAC adresa: %s\n", getSrcMAC(packet));
                                        printf("Cielova MAC adresa: %s\n", getDstMAC(packet));
                                        printf("%s\n", ethertypeBuff);
                                        printf("zdrojova IP adresa: %s\n", getSrcIP(packet));
                                        printf("cielova IP adresa: %s\n", getDstIP(packet));
                                        printf("%s\n", protocolBuff);
                                        printf("%s\n", portBuff);
                                        printf("zdrojovy port: %s\n", getSrcPort(packet));
                                        printf("cielovy port: %s\n", getDstPort(packet));
                                        printHexadecimal(pcapHeader->len, packet);
                                        printf("\n=============================================================\n");
                                    }
                                }
                            }
                            frames = 0;
                            pcap_close(pcap_file);

                            temp = temp -> next;
                        }
                        deleteUDPPacketList(&UDPhead);
                        break;
                    }

                    // ICMP
                    else if (strcasecmp("ICMP", choice2) == 0) {

                        if ((pcap_file = pcap_open_offline(file_name, pcap_file_error)) == NULL) {
                            printf("Chyba pri otvoreni PCAP suboru.");
                            exit(0);
                        }

                        while ((pcap_next_ex(pcap_file, &pcapHeader, &packet)) >= 0) {
                            frames++;
                            char* frameTypeBuff = getFrameType(packet);
                            char* ethertypeBuff = getEthertypesFromTXT(packet, ethertypes);
                            char* protocolBuff = getProtocolsFromTXT(packet, IPProtocols);
                            char* portBuff = getICMPPortsFromTXT(packet, ICMPPorts);

                            if (strcasecmp(protocolBuff, "ICMP") == 0) {
                                printBasicInfo(frames, pcapHeader->caplen, pcapHeader->len);
                                printf("%s\n", frameTypeBuff);
                                printf("Zdrojova MAC adresa: %s\n", getSrcMAC(packet));
                                printf("Cielova MAC adresa: %s\n", getDstMAC(packet));
                                printf("%s\n", ethertypeBuff);
                                printf("zdrojova IP adresa: %s\n", getSrcIP(packet));
                                printf("cielova IP adresa: %s\n", getDstIP(packet));
                                printf("%s\n", protocolBuff);
                                printf("%s\n", portBuff);
                                printHexadecimal(pcapHeader->len, packet);
                                printf("\n=============================================================\n");
                            }

                        }
                        pcap_close(pcap_file);
                        frames = 0;
                        break;
                    }

                    // TCP
                    else {
                        struct TCPPacket *temp = TCPhead;
                        struct TCPPacket *temp2 = temp;
                        struct TCPPacket *temp3 = temp2;
                        struct TCPPacket *temp4 = TCPhead;
                        struct TCPPacket *temp5 = temp4;

                        char* firstCompleteComPort = "FAKE_EMPTY";
                        char* firstIncompleteComPort = "FAKE_EMPTY";

                        bool completeComFullfilled = false;
                        bool incompleteComFullfilled = false;

                        // Verify 3WHS and termination - find one complete and incomplete communication, save it's port
                        while (true) {
                            if (completeComFullfilled == true && incompleteComFullfilled == true)
                                break;

                            char* string = verify3WHS(temp, temp2, temp3);
                            char* token;
                            char* rest = string;
                            char* stringArray[3];
                            int buff = 0;
                            while ((token = strtok_r(rest, " ", &rest)))
                                stringArray[buff++] = token;
                            int tempFrameNumber = atoi(stringArray[0]);
                            char* tempPort = stringArray[1];

                            if (debugMode) {
                                printf("~~~~~~~~~~\n");
                                printf("[New loop]\n");
                                printf("start: %d Port: %s\n", tempFrameNumber, tempPort);
                            }

                            // 3WHS Success, looking for complete com
                            if (strcasecmp(tempPort, "0") && completeComFullfilled == false) {
                                char* potentionalEnd = verifyTermination(temp4, temp5, tempFrameNumber, tempPort);
                                if (debugMode) {
                                    printf("end: %s\n", potentionalEnd);
                                    printf("~~~~~~~~~~\n");
                                }


                                // 4WHS Success aka complete com
                                if (strcasecmp(potentionalEnd, "0")) {
                                    completeComFullfilled = true;
                                    firstCompleteComPort = tempPort;
                                    if (debugMode) {
                                        printf("[4WHS Success, first complete com]\n");
                                        printf("1st COMPLETE com [ %s ] = start: %d\tend: %s\n", tempPort, tempFrameNumber, potentionalEnd);
                                    }

                                    continue;
                                }

                                // 4WHS Fail at the first itaration
                                else if (strcasecmp(potentionalEnd, "0") == 0 && incompleteComFullfilled == false) {
                                    firstIncompleteComPort = tempPort;
                                    incompleteComFullfilled = true;
                                    if (debugMode) {
                                        printf("[4WHS Fail, incomplete com fullfilled, first loop]\n");
                                        printf("1st INCOMPLETE com [ %s ] = start: %d\tend: %s\n", tempPort, tempFrameNumber, potentionalEnd);
                                    }
                                    continue;
                                }
                            }

                            // 3WHS Success, looking for incomplete com
                            else if (strcasecmp(tempPort, "0") && completeComFullfilled == true) {

                                char* potentionalEnd = verifyTermination(temp4, temp5, tempFrameNumber, tempPort);
                                if (debugMode) {
                                    printf("\n[3WHS Success, complete com fullfilled]\n");
                                    printf("end %s\n", potentionalEnd);
                                    printf("~~~~~~~~~~\n");
                                }

                                if (strcasecmp(potentionalEnd, "0") == 0) {
                                    incompleteComFullfilled = true;
                                    firstIncompleteComPort = tempPort;
                                    if (debugMode) {
                                        printf("[4WHS Fail, incomplete com fullfilled]\n");
                                        printf("1st INCOMPLETE com [ %s ] = start: %d\tend: %s\n", tempPort, tempFrameNumber, potentionalEnd);
                                    }
                                    break;
                                }
                            }
                            // 3WHS Fail
                            else {
                                if (debugMode)
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
                            char* portBuff = getTCPOrUDPPortsFromTXT(packet, TCPPorts);
                            if (strcasecmp(portBuff, choice2) == 0 && (strcasecmp(getSrcPort(packet), firstCompleteComPort) == 0 || strcasecmp(getDstPort(packet), firstCompleteComPort) == 0))
                                completeComFrameCount++;
                        }
                        pcap_close(pcap_file);

                        if (completeComFrameCount != 0) {
                            printf("\n=============================================================\n");
                            printf("Prva kompletna %s komunikacia je pod portom %s, obsahuje %d ramcov", choice2, firstCompleteComPort, completeComFrameCount);
                            printf("\n=============================================================\n");
                        }

                        else {
                            printf("\n=============================================================\n");
                            printf("Subor neobsahoval ani jednu kompletnu %s komunikaciu", choice2);
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
                            char* ethertypeBuff = getEthertypesFromTXT(packet, ethertypes);
                            char* protocolBuff = getProtocolsFromTXT(packet, IPProtocols);
                            char* portBuff = getTCPOrUDPPortsFromTXT(packet, TCPPorts);

                            if (strcasecmp(portBuff, choice2) == 0 && (strcasecmp(getSrcPort(packet), firstCompleteComPort) == 0 || strcasecmp(getDstPort(packet), firstCompleteComPort) == 0)) {
                                printedCompleteComCount++;
                                if (completeComFrameCount > 20 && (printedCompleteComCount <= 10 || printedCompleteComCount > completeComFrameCount - 10) || completeComFrameCount <= 20) {
                                    printBasicInfo(frames, pcapHeader->caplen, pcapHeader->len);
                                    printf("%s\n", frameTypeBuff);
                                    printf("Zdrojova MAC adresa: %s\n", getSrcMAC(packet));
                                    printf("Cielova MAC adresa: %s\n", getDstMAC(packet));
                                    printf("%s\n", ethertypeBuff);
                                    printf("zdrojova IP adresa: %s\n", getSrcIP(packet));
                                    printf("cielova IP adresa: %s\n", getDstIP(packet));
                                    printf("%s\n", protocolBuff);
                                    printf("%s\n", portBuff);
                                    printf("zdrojovy port: %s\n", getSrcPort(packet));
                                    printf("cielovy port: %s\n", getDstPort(packet));
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
                            char* portBuff = getTCPOrUDPPortsFromTXT(packet, TCPPorts);
                            if (strcasecmp(portBuff, choice2) == 0 && (strcasecmp(getSrcPort(packet), firstIncompleteComPort) == 0 || strcasecmp(getDstPort(packet), firstIncompleteComPort) == 0))
                                incompleteComFrameCount++;
                        }
                        pcap_close(pcap_file);

                        if (incompleteComFrameCount != 0) {
                            printf("Prva nekompletna %s komunikacia je pod portom %s, obsahuje %d ramcov", choice2, firstIncompleteComPort, incompleteComFrameCount);
                            printf("\n=============================================================\n");
                        }

                        else {
                            printf("Subor neobsahoval ani jednu nekompletnu %s komunikaciu", choice2);
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
                            char* ethertypeBuff = getEthertypesFromTXT(packet, ethertypes);
                            char* protocolBuff = getProtocolsFromTXT(packet, IPProtocols);
                            char* portBuff = getTCPOrUDPPortsFromTXT(packet, TCPPorts);

                            if (strcasecmp(getSrcPort(packet), firstIncompleteComPort) == 0 || strcasecmp(getDstPort(packet), firstIncompleteComPort) == 0) {
                                printedIncompleteComCount++;
                                if (incompleteComFrameCount > 20 && (printedIncompleteComCount <= 10 || printedIncompleteComCount > incompleteComFrameCount - 10) || incompleteComFrameCount <= 20) {
                                    printBasicInfo(frames, pcapHeader->caplen, pcapHeader->len);
                                    printf("%s\n", frameTypeBuff);
                                    printf("Zdrojova MAC adresa: %s\n", getSrcMAC(packet));
                                    printf("Cielova MAC adresa: %s\n", getDstMAC(packet));
                                    printf("%s\n", ethertypeBuff);
                                    printf("zdrojova IP adresa: %s\n", getSrcIP(packet));
                                    printf("cielova IP adresa: %s\n", getDstIP(packet));
                                    printf("%s\n", protocolBuff);
                                    printf("%s\n", portBuff);
                                    printf("zdrojovy port: %s\n", getSrcPort(packet));
                                    printf("cielovy port: %s\n", getDstPort(packet));
                                    printHexadecimal(pcapHeader->len, packet);
                                    printf("\n=============================================================\n");
                                }
                            }
                        }

                        pcap_close(pcap_file);
                        deleteTCPPacketList(&TCPhead);
                        frames = 0;
                        break;
                    }
                }

                else {
                    printf("Bad luck\n");
                    break;
                }
            }

            default:
                break;
        }
    } while (choice != 0);

    return 0;
}