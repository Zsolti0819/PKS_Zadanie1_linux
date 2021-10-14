#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <pcap/pcap.h>

char***** bigBufferStringArray[2][30][30][30];

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

void insertTCPPacketToList(struct TCPPacket **headRef, char *srcPort, char *dstPort, char *flag, int frameNumber) {
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

void insertUDPPacketToList(struct UDPPacket **headRef, char *srcPort, int frameNumber) {
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

void insertARPPacketToList(struct ARPPacket **headRef, int frameNumber, char *srcIPAdress, char *dstIPAdress, char *srcMACAdress, char *dstMACAdress, char* opCode) {
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

char* getARPsrcIP (const u_char *packet) {
    char* ARPSRCIP;
    ARPSRCIP = malloc(sizeof(u_char) * 20);
    sprintf(ARPSRCIP, "%d.%d.%d.%d", packet[28], packet[29], packet[30], packet[31]);
    return ARPSRCIP;
}

char* getARPdstIP (const u_char *packet) {
    char* ARPDSTIP;
    ARPDSTIP = malloc(sizeof(u_char) * 20);
    sprintf(ARPDSTIP, "%d.%d.%d.%d", packet[38], packet[39], packet[40], packet[41]);
    return ARPDSTIP;
}

char* getARPsrcMAC (const u_char *packet) {
    char* ARPSRCMAC;
    ARPSRCMAC = malloc(sizeof(char) * 50);
    sprintf(ARPSRCMAC, "%.2X %.2X %.2X %.2X %.2X %.2X", packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);
    return ARPSRCMAC;
}

char* getARPdstMAC (const u_char *packet) {
    char* ARPDSTMAC;
    ARPDSTMAC = malloc(sizeof(char) * 50);
    sprintf(ARPDSTMAC, "%.2X %.2X %.2X %.2X %.2X %.2X", packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]);
    return ARPDSTMAC;
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
        if (strcasecmp(temp->srcIPAdress, data) == 0) {
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
    printf("\n0 - Koniec\n");
    printf("1 - Vypis vsetkych komunikacii\n");
    printf("2 - Filtrovanie podla protokolu (viacere moznosti)\n");
    printf("3 - Vypis komunikacii podla protokolu (viacere moznosti)\n");
    printf("=============================================================\n");
}

void seekToNextLine(void) {
    int c;
    while ((c = fgetc(stdin)) != EOF && c != '\n');
}

int differenceSetOperation(int *excludeFrames, int excludeSize, int yy, const int *bufferArraySet, int *finalSet) {
    int ii = 0;
    int jj = 0;
    int kk = 0;
    int flag = 0;

    for (ii = 0; ii < yy; ii++) {
        flag = 1;
        for (jj = 0; jj < excludeSize; jj++) {
            if (bufferArraySet[ii] == excludeFrames[jj]) {
                flag = 0;
                break;
            }
        }
        if (flag == 1) {
            finalSet[kk] = bufferArraySet[ii];
            kk++;
        }
    }
    return kk;
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

int getSearchCount(const struct pcap_pkthdr *pcapHeader, const u_char *packet, int frames, int count, char *frameTypeBuff, char *ethertype_buff, char *protocolBuff, char *portBuff) {
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
    return count;
}

void unitedARPPrint(const struct pcap_pkthdr *pcapHeader, const u_char *packet, int frames, char *frameTypeBuff, char *ethertypeBuff) {
    printBasicInfo(frames, pcapHeader->caplen, pcapHeader->len);
    printf("\n%s\n", frameTypeBuff);
    printf("%s", ethertypeBuff);
    printMACAddress(packet);
}

char* getSrcIP(const u_char* packet) {
    char* srcIPAddress;
    srcIPAddress = malloc(sizeof(u_char) * 20);
    sprintf(srcIPAddress, "%d.%d.%d.%d", packet[26], packet[27], packet[28], packet[29]);
    return srcIPAddress;
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

char* getARPOperation(const u_char* packet, FILE* ARPFile) {
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

char* get802_3SAP(const u_char* packet, FILE* _802_3File)
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

char* get802_Protocol(const u_char* packet, FILE* _802_3File, bool isJustLLC)
{
    int valueInTheFile = 0;
    int realValue1;
    int realValue2;

    if (isJustLLC == true) {
        realValue1 = packet[17];
        realValue2 = packet[18];
    }

    else {
        realValue1 = packet[22];
        realValue2 = packet[23];
    }

    rewind(_802_3File);
    char c;
    char _802_3ProtocolBuff[50] = {0 };
    int i = 0;

    while ((c = getc(_802_3File)) != '-') {
        if (c == '#') {
            fscanf(_802_3File, "%x ", &valueInTheFile);
            if (realValue1 == valueInTheFile && realValue2 == valueInTheFile) {
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

void openTxtFiles(FILE **_802_3, FILE **_802_3Protocol, FILE **ethertypes, FILE **IPProtocols, FILE **TCPPorts, FILE **UDPPorts, FILE **ICMPPorts, FILE **ARPOperation) {

    if (((*_802_3) = fopen("/home/zsolti/CLionProjects/PKS_Zadanie1_linux/txt/802_3SAPs.txt", "r")) == NULL) printf("Chyba pri otvoreni 802_3SAPs.txt suboru.\n");
    if (((*_802_3Protocol) = fopen("/home/zsolti/CLionProjects/PKS_Zadanie1_linux/txt/802_3Protocols.txt", "r")) == NULL) printf("Chyba pri otvoreni 802_3Protocols.txt suboru.\n");
    if (((*ethertypes) = fopen("/home/zsolti/CLionProjects/PKS_Zadanie1_linux/txt/ethertypes.txt", "r")) == NULL) printf("Chyba pri otvoreni ethertypes.txt suboru.\n");
    if (((*IPProtocols) = fopen("/home/zsolti/CLionProjects/PKS_Zadanie1_linux/txt/IPProtocols.txt", "r")) == NULL) printf("Chyba pri otvoreni IPProtocols.txt suboru.\n");
    if (((*TCPPorts) = fopen("/home/zsolti/CLionProjects/PKS_Zadanie1_linux/txt/TCPPorts.txt", "r")) == NULL) printf("Chyba pri otvoreni TCPPorts.txt suboru.\n");
    if (((*UDPPorts) = fopen("/home/zsolti/CLionProjects/PKS_Zadanie1_linux/txt/UDPPorts.txt", "r")) == NULL) printf("Chyba pri otvoreni UDPPorts.txt suboru.\n");
    if (((*ICMPPorts) = fopen("/home/zsolti/CLionProjects/PKS_Zadanie1_linux/txt/ICMPPorts.txt", "r")) == NULL) printf("Chyba pri otvoreni ICMPPorts.txt suboru.\n");
    if (((*ARPOperation) = fopen("/home/zsolti/CLionProjects/PKS_Zadanie1_linux/txt/ARPValues.txt", "r")) == NULL) printf("Chyba pri otvoreni ARPValues.txt suboru.\n");
}

void fillBigBufferStringArray() {
    int i, j, k, l;
    for (i = 0; i < 2; i++)
        for (j = 0; j < 30; j++)
            for (k = 0; k < 30; k++)
                for (l = 0; l < 30; l++)
                        strcpy((char *) &bigBufferStringArray[i][j][k][l], "-");

    strcpy((char *) &bigBufferStringArray[0][1][0][0], "Ethernet II");
    strcpy((char *) &bigBufferStringArray[0][1][0][0], "IPv4");

    strcpy((char *) &bigBufferStringArray[0][1][1][0], "TCP");
    strcpy((char *) &bigBufferStringArray[0][1][1][1], "ECHO");
    strcpy((char *) &bigBufferStringArray[0][1][1][2], "CHARGEN");
    strcpy((char *) &bigBufferStringArray[0][1][1][3], "FTP DATA");
    strcpy((char *) &bigBufferStringArray[0][1][1][4], "FTP CONTROL");
    strcpy((char *) &bigBufferStringArray[0][1][1][5], "SSH");
    strcpy((char *) &bigBufferStringArray[0][1][1][6], "TELNET");
    strcpy((char *) &bigBufferStringArray[0][1][1][7], "SMTP");
    strcpy((char *) &bigBufferStringArray[0][1][1][8], "DOMAIN");
    strcpy((char *) &bigBufferStringArray[0][1][1][9], "FINGER");
    strcpy((char *) &bigBufferStringArray[0][1][1][10], "HTTP");
    strcpy((char *) &bigBufferStringArray[0][1][1][11], "POP3");
    strcpy((char *) &bigBufferStringArray[0][1][1][12], "SUNRPC");
    strcpy((char *) &bigBufferStringArray[0][1][1][13], "NNTP");
    strcpy((char *) &bigBufferStringArray[0][1][1][14], "SMB");
    strcpy((char *) &bigBufferStringArray[0][1][1][15], "IMAP");
    strcpy((char *) &bigBufferStringArray[0][1][1][16], "BGP");
    strcpy((char *) &bigBufferStringArray[0][1][1][17], "LDAP");
    strcpy((char *) &bigBufferStringArray[0][1][1][18], "HTTPS");
    strcpy((char *) &bigBufferStringArray[0][1][1][19], "MICROSOFT DS");
    strcpy((char *) &bigBufferStringArray[0][1][1][20], "SOCKS");

    strcpy((char *) &bigBufferStringArray[0][1][2][0], "UDP");
    strcpy((char *) &bigBufferStringArray[0][1][2][1], "Echo");
    strcpy((char *) &bigBufferStringArray[0][1][2][2], "Chargen");
    strcpy((char *) &bigBufferStringArray[0][1][2][3], "Time");
    strcpy((char *) &bigBufferStringArray[0][1][2][4], "DNS");
    strcpy((char *) &bigBufferStringArray[0][1][2][5], "Bootpc DHCP");
    strcpy((char *) &bigBufferStringArray[0][1][2][6], "Bootpc DHCP");
    strcpy((char *) &bigBufferStringArray[0][1][2][7], "TFTP");
    strcpy((char *) &bigBufferStringArray[0][1][2][8], "NBNS");
    strcpy((char *) &bigBufferStringArray[0][1][2][9], "Netbios dgm");
    strcpy((char *) &bigBufferStringArray[0][1][2][10], "SNMP");
    strcpy((char *) &bigBufferStringArray[0][1][2][11], "SNMP trap");
    strcpy((char *) &bigBufferStringArray[0][1][2][12], "Isakmp");
    strcpy((char *) &bigBufferStringArray[0][1][2][13], "syslog");
    strcpy((char *) &bigBufferStringArray[0][1][2][14], "RIP");
    strcpy((char *) &bigBufferStringArray[0][1][2][15], "Traceroute");
    strcpy((char *) &bigBufferStringArray[0][1][2][16], "HSRP");
    strcpy((char *) &bigBufferStringArray[0][1][2][17], "MDNS");

    strcpy((char *) &bigBufferStringArray[0][1][3][0], "ICMP");
    strcpy((char *) &bigBufferStringArray[0][2][0][0], "ARP");

    strcpy((char *) &bigBufferStringArray[1][0][0][0], "802.3");
    strcpy((char *) &bigBufferStringArray[1][1][0][0], "LLC Sublayer Management or Individual");
    strcpy((char *) &bigBufferStringArray[1][2][0][0], "LLC Sublayer Management or Group");
    strcpy((char *) &bigBufferStringArray[1][3][0][0], "IP (DOD Internet Protocol)");
    strcpy((char *) &bigBufferStringArray[1][4][0][0], "PROWAY (IEC 955)");
    strcpy((char *) &bigBufferStringArray[1][5][0][0], "BPDU (Bridge PDU / 802.1 Spanning Tree)");
    strcpy((char *) &bigBufferStringArray[1][5][1][0], "STP");
    strcpy((char *) &bigBufferStringArray[1][6][0][0], "MMS (Manufacturing Message Service)");
    strcpy((char *) &bigBufferStringArray[1][7][0][0], "ISI IP");
    strcpy((char *) &bigBufferStringArray[1][8][0][0], "X.25 PLP (ISO 8208)");
    strcpy((char *) &bigBufferStringArray[1][9][0][0], "PROWAY (IEC 955) Active Station List Maintenance");
    strcpy((char *) &bigBufferStringArray[1][10][0][0], "SNAP");
    strcpy((char *) &bigBufferStringArray[1][10][1][0], "STP");
    strcpy((char *) &bigBufferStringArray[1][11][0][0], "IPX (Novell NetWare)");
    strcpy((char *) &bigBufferStringArray[1][12][0][0], "IPX (Novell NetWare)");
    strcpy((char *) &bigBufferStringArray[1][13][0][0], "LAN Management");
    strcpy((char *) &bigBufferStringArray[1][14][0][0], "ISO Network Layer Protocols");
    strcpy((char *) &bigBufferStringArray[1][15][0][0], "NULL SAP");
    strcpy((char *) &bigBufferStringArray[1][16][0][0], "Global DSAP");

}

char * verify3WHS(struct TCPPacket *temp, struct TCPPacket *temp2, struct TCPPacket *temp3) {
    while (temp != NULL) {
        if (strcasecmp(temp -> flag, "SYN") == 0 && temp -> isMarked == false) {
            while (temp2 != NULL) {
                if (temp -> isMarked == false && temp2 -> isMarked == false && temp -> frameNumber < temp2 -> frameNumber && strcasecmp(temp->srcPort, temp2->dstPort) == 0 && strcasecmp(temp->dstPort, temp2->srcPort) == 0  && strcasecmp(temp2->flag, "SYN, ACK") == 0) {
                    while (temp3 != NULL) {
                        if (temp -> isMarked == false && temp2 -> isMarked == false && temp3-> isMarked == false && temp2 -> frameNumber < temp3 -> frameNumber && strcasecmp(temp2->srcPort, temp3->dstPort) == 0 && strcasecmp(temp2->dstPort, temp3->srcPort) == 0 && strcasecmp(temp3->flag, "ACK") == 0) {
                            temp -> isMarked = true;
                            temp2 -> isMarked = true;
                            temp3 -> isMarked = true;

//                            printTCPPacket(temp);
//                            printTCPPacket(temp2);
//                            printTCPPacket(temp3);

                            char *_3WHSSYN = malloc(sizeof(u_char) * 20);
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
    char *no3WHS = malloc(sizeof(u_char) * 20);
    strcpy(no3WHS, "0 0");
    return no3WHS;
}

char * verifyTermination(struct TCPPacket *temp4, struct TCPPacket *temp5, int comStart, const char *clientsSourcePort) {
    while (temp4 != NULL) {
        if (comStart < temp4 -> frameNumber && temp4 -> isMarked == false && (strcasecmp(clientsSourcePort, temp4->dstPort) == 0 || strcasecmp(clientsSourcePort, temp4->srcPort) == 0 ) && strcasecmp(temp4->flag, "FIN") == 0) {

            if (strcasecmp(clientsSourcePort, temp4->dstPort) == 0) {
                while (temp5 != NULL) {
                    if (temp4->frameNumber < temp5->frameNumber && temp4->isMarked == false && temp5->isMarked == false && strcasecmp(clientsSourcePort, temp5->srcPort) == 0 && (strcasecmp(temp5->flag, "FIN") == 0 || strcasecmp(temp5->flag, "RST") == 0)) {
                        temp4 -> isMarked = true;
                        temp5 -> isMarked = true;

//                        printTCPPacket(temp4);
//                        printTCPPacket(temp5);

                        char *FINbyServer = malloc(sizeof(u_char) * 20);
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

//                        printTCPPacket(temp4);
//                        printTCPPacket(temp5);

                        char *FINbyClient = malloc(sizeof(u_char) * 20);
                        sprintf(FINbyClient, "%d", temp5 -> frameNumber);
                        return FINbyClient;
                    }
                    temp5 = temp5->next;
                }
            }
        }

        else if (comStart < temp4 -> frameNumber && temp4 -> isMarked == false && (strcasecmp(clientsSourcePort, temp4->dstPort) == 0 || strcasecmp(clientsSourcePort, temp4->srcPort) == 0 ) && strcasecmp(temp4->flag, "RST") == 0) {
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

char * connectARPPairs (struct ARPPacket *temp, struct ARPPacket *temp2) {
    while (temp != NULL) {
        if (strcasecmp(temp -> opCode, "Request") == 0 && temp->isMarked == false) {
            while (temp2 != NULL) {
                if (strcasecmp(temp2 -> opCode, "Reply") == 0  && temp2->isMarked == false && temp->frameNumber < temp2->frameNumber) {
                    if (strcmp(temp->srcMACAdress, temp2->dstMACAdress) == 0) {
                        temp->isMarked = true;
                        temp2->isMarked = true;

                        char *ARPPair = malloc(sizeof(u_char) * 20);
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

    char *noARPPair = malloc(sizeof(u_char) * 20);
    strcpy(noARPPair, "0 0");
    return noARPPair;
}

int main() {

    char* file_name = { "/home/zsolti/CLionProjects/PKS_Zadanie1_linux/vzorky_pcap_na_analyzu/trace-2.pcap" }; // sem vlozit subor
    char pcap_file_error[PCAP_ERRBUF_SIZE];
    pcap_t* pcap_file;

    FILE *_802_3;
    FILE *_802_3Protocol;
    FILE *ethertypes;
    FILE *IPProtocols;
    FILE *TCPPorts;
    FILE *UDPPorts;
    FILE *ICMPPorts;
    FILE *ARPOperation;
    openTxtFiles(&_802_3, &_802_3Protocol, &ethertypes, &IPProtocols, &TCPPorts, &UDPPorts, &ICMPPorts, &ARPOperation);
    fillBigBufferStringArray();

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
                        printf("\n%s ", frameTypeBuff);

                        char* _802_3Buff = get802_3SAP(packet, _802_3);

                        // Global DSAP == FF == RAW
                        if (strcasecmp(_802_3Buff, "Global DSAP") == 0) {
                            printf("RAW\n");
                            printf("%s", _802_3Buff);
                        }

                        // SNAP == AA == SNAP + LLC
                        else if (strcasecmp(_802_3Buff, "SNAP") == 0) {
                            printf("LLC + %s\n", _802_3Buff);
                            char *_802_3ProtocolBuff = get802_Protocol(packet, _802_3Protocol, false);
                            printf("%s", _802_3ProtocolBuff);

                        }

                        // LLC, ani jeden
                        else {
                            printf("LLC\n");
                            printf("%s", _802_3Buff);
                            char *_802_3ProtocolBuff = get802_Protocol(packet, _802_3Protocol, true);
                            printf("%s", _802_3ProtocolBuff);
                        }

                        printMACAddress(packet);
                    }

                    // Je Ethernet II
                    else if (strcasecmp(frameTypeBuff, "Ethernet II") == 0) {
                        char* ethertypeBuff = getEtherType(packet, ethertypes);

                        // Je ARP, vypiseme ARP-Request/Reply,IP, MAC
                        if (strcasecmp(ethertypeBuff, "ARP") == 0) {
                            char* ARPBuff = getARPOperation(packet, ARPOperation);
                            char *ARPDSTIP = getARPdstIP(packet);
                            char *ARPSRCIP = getARPsrcIP(packet);
                            char *ARPSRCMAC = getARPsrcMAC(packet);
                            char *ARPDSTMAC = getARPdstMAC(packet);

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

                            unitedARPPrint(pcapHeader, packet, frames, frameTypeBuff, ethertypeBuff);
                        }

                        // Je IP
                        else if (strcasecmp(ethertypeBuff, "ARP") != 0) {
                            printBasicInfo(frames, pcapHeader->caplen, pcapHeader->len);
                            printf("\n%s", frameTypeBuff);
                            printMACAddress(packet);
                            printf("%s\n", ethertypeBuff);
                            printIPAdresses(packet);
                            char* protocolBuff = getProtocol(packet, IPProtocols);
                            printf("%s\n", protocolBuff);

                            char* srcIPBuff = getSrcIP(packet);
                            if ((strcasecmp(ethertypeBuff, "IPv4") == 0) && findIPv4PacketInList(IPv4Head, srcIPBuff) == false) {
                                if (strcasecmp(protocolBuff, "TCP") == 0)
                                    insertIPv4PacketToList(&IPv4Head, getSrcIP(packet), true);
                                else
                                    insertIPv4PacketToList(&IPv4Head, getSrcIP(packet), false);
                            }

                            char* portBuff;
                            if (strcasecmp(protocolBuff, "TCP") == 0) {
                                portBuff = getTCPOrUDPPort(packet, TCPPorts);
                                printf("%s\n", portBuff);
                                printSrcPortAndDstPort(packet);
                            }

                            else if (strcasecmp(protocolBuff, "UDP") == 0) {
                                portBuff = getTCPOrUDPPort(packet, UDPPorts);
                                printf("%s\n", portBuff);
                                printSrcPortAndDstPort(packet);
                            }

                            else if (strcasecmp(protocolBuff, "ICMP") == 0) {
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
//                puts(choice2);

                int frametypeKey = -1;
                int ethertypeKey = -1;
                int protocolKey = -1;
                int portKey = -1;
                int count = 0;

                int i, j, k, l;
                for (i = 0; i < 2; i++)
                    for (j = 0; j < 30; j++)
                        for (k = 0; k < 30; k++)
                            for (l = 0; l < 30; l++)
                                if (strcasecmp(choice2, (const char *) &bigBufferStringArray[i][j][k][l]) == 0) {
                                    frametypeKey = i;
                                    ethertypeKey = j;
                                    protocolKey = k;
                                    portKey = l;
                                }

                if (frametypeKey == -1 || ethertypeKey == -1 || protocolKey == -1 || portKey == -1) {
                    printf("Taky protokol neexistuje alebo neviem ho najst\n");
                    break;
                }

                printf("bigBufferStringArray [%d] [%d] [%d] [%d] : %s\n", frametypeKey, ethertypeKey, protocolKey, portKey, (const char *) &bigBufferStringArray[frametypeKey][ethertypeKey][protocolKey][portKey]);

                while ((pcap_next_ex(pcap_file, &pcapHeader, &packet)) >= 0) {
                    frames++;

                    // Ethernet II
                    if (frametypeKey == 0) {
                        char* frameTypeBuff = getFrameType(packet);
                        char* ethertypeBuff = getEtherType(packet, ethertypes);
                        char* protocolBuff = getProtocol(packet, IPProtocols);

                        //TCP
                        if (frametypeKey == 0 && ethertypeKey == 1 && protocolKey == 1) {
                            char* portBuff = getTCPOrUDPPort(packet, TCPPorts);
                            if (strcasecmp(portBuff, (const char *) &bigBufferStringArray[frametypeKey][ethertypeKey][protocolKey][portKey]) == 0)
                                count = getSearchCount(pcapHeader, packet, frames, count, frameTypeBuff, ethertypeBuff, protocolBuff, portBuff);
                        }

                        // UDP
                        else if (frametypeKey == 0 && ethertypeKey == 1 && protocolKey == 2) {
                            char* portBuff = getTCPOrUDPPort(packet, UDPPorts);
                            if (strcasecmp(portBuff, (const char *) &bigBufferStringArray[frametypeKey][ethertypeKey][protocolKey][portKey]) == 0)
                                count = getSearchCount(pcapHeader, packet, frames, count, frameTypeBuff, ethertypeBuff, protocolBuff, portBuff);
                        }

                        // ICMP
                        else if (frametypeKey == 0 && ethertypeKey == 1 && protocolKey == 3) {
                            char* portBuff = getICMPPort(packet, ICMPPorts);
                            if (strcasecmp(protocolBuff, (const char *) &bigBufferStringArray[frametypeKey][ethertypeKey][protocolKey][0]) == 0)
                                count = getSearchCount(pcapHeader, packet, frames, count, frameTypeBuff, ethertypeBuff, protocolBuff, portBuff);
                        }
                    }

                    // 802.3
                    else if (frametypeKey == 1) {
                        char* frameTypeBuff = getFrameType(packet);
                        char* _802_3Buff = get802_3SAP(packet, _802_3);
                        char *_802_3ProtocolBuff;

                        // SNAP == AA == SNAP + LLC
                        if (frametypeKey == 1 && ethertypeKey == 10) {
                            if (strcasecmp(_802_3Buff, "SNAP") == 0)
                                _802_3ProtocolBuff = get802_Protocol(packet, _802_3Protocol, false);
                        }

                        // Not RAW, not SNAP + LLC, it is just LLC
                        else if (frametypeKey == 1 && ethertypeKey != 10 && ethertypeKey != 15) {
                            if (strcasecmp(_802_3Buff, "SNAP") && strcasecmp(_802_3Buff, "Global DSAP"))
                                _802_3ProtocolBuff = get802_Protocol(packet, _802_3Protocol, true);
                        }

                        else
                            _802_3ProtocolBuff = "EMPTY";

                        if (strcasecmp(frameTypeBuff, "802.3") == 0) {
                            printBasicInfo(frames, pcapHeader->caplen, pcapHeader->len);
                            printf("\n%s ", frameTypeBuff);

                            // SNAP == AA == SNAP + LLC
                            if (frametypeKey == 1 && ethertypeKey == 10) {
                                printf("SNAP + LLC\n%s\n", _802_3Buff);
                                _802_3ProtocolBuff = get802_Protocol(packet, _802_3Protocol, false);
                                printf("%s", _802_3ProtocolBuff);
                            }

                            // LLC, ani jeden
                            else if (frametypeKey == 1 && ethertypeKey != 10 && ethertypeKey != 16) {
                                printf("LLC\n");
                                printf("%s", _802_3Buff);
                                _802_3ProtocolBuff = get802_Protocol(packet, _802_3Protocol, true);
                                printf("%s", _802_3ProtocolBuff);
                            }

                            printMACAddress(packet);
                            printHexadecimal(pcapHeader->len, packet);
                            count++;
                            printf("\n=============================================================\n");
                        }
                    }
                }
                printf("Tento subor obsahoval %d protokolov typu %s.\n", count, (const char *) &bigBufferStringArray[frametypeKey][ethertypeKey][protocolKey][portKey]);
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

                    int frametypeKey = -1;
                    int ethertypeKey = -1;
                    int protocolKey = -1;
                    int portKey = -1;

                    int i, j, k, l;
                    for (i = 0; i < 2; i++)
                        for (j = 0; j < 30; j++)
                            for (k = 0; k < 30; k++)
                                for (l = 0; l < 30; l++)
                                    if (strcasecmp(choice2, (const char *) &bigBufferStringArray[i][j][k][l]) == 0) {
                                        frametypeKey = i;
                                        ethertypeKey = j;
                                        protocolKey = k;
                                        portKey = l;
                                    }

//                printf("bigBufferStringArray [%d] [%d] [%d] [%d] : %s\n", frametypeKey, ethertypeKey, protocolKey, portKey, (const char *) &bigBufferStringArray[frametypeKey][ethertypeKey][protocolKey][portKey]);

                    // If not ICMP, insert all frames to a list if meets port criteria
                    if (strcasecmp(choice2, "ICMP")) {
                        if ((pcap_file = pcap_open_offline(file_name, pcap_file_error)) == NULL) {
                            printf("Chyba pri otvoreni PCAP suboru.");
                            exit(0);
                        }
                        while ((pcap_next_ex(pcap_file, &pcapHeader, &packet)) >= 0) {
                            frames++;
                            // TCP
                            if (frametypeKey == 0 && ethertypeKey == 1 && protocolKey == 1) {
                                char *portBuff = getTCPOrUDPPort(packet, TCPPorts);
                                if (strcasecmp(portBuff, (const char *) &bigBufferStringArray[frametypeKey][ethertypeKey][protocolKey][portKey]) == 0 && findTCPPacketInList(TCPhead, frames) == false)
                                    insertTCPPacketToList(&TCPhead, getSrcPort(packet), getDstPort(packet), getTCPFlag(packet), frames);
                            }

                            // UDP
                            else if (frametypeKey == 0 && ethertypeKey == 1 && protocolKey == 2) {
                                char *portBuff = getTCPOrUDPPort(packet, UDPPorts);
                                if (strcasecmp(portBuff, (const char *) &bigBufferStringArray[frametypeKey][ethertypeKey][protocolKey][portKey]) == 0 && findUDPPacketInList(UDPhead, frames) == false)
                                    insertUDPPacketToList(&UDPhead, getSrcPort(packet), frames);
                            }

                            // ARP
                            else if (frametypeKey == 0 && ethertypeKey == 2 && protocolKey == 0) {
                                char *ethertypeBuff = getEtherType(packet, ethertypes);
                                if (strcasecmp(ethertypeBuff, (const char *) &bigBufferStringArray[frametypeKey][ethertypeKey][protocolKey][portKey]) == 0 && findARPPacketInList(ARPhead, frames) == false)
                                    insertARPPacketToList(&ARPhead, frames, getARPsrcIP(packet), getARPdstIP(packet), getARPsrcMAC(packet), getARPdstMAC(packet),
                                                          getARPOperation(packet, ARPOperation));
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

                        int ARPComNumber = 0;
                        bool flag = false;

                        // Search for pairs, save their framenumbers and print it
                        while (true) {
                            char *string = connectARPPairs(temp, temp2);
                            char* token;
                            char* rest = string;
                            char *stringArray[3];
                            int buffer = 0;
                            while ((token = strtok_r(rest, " ", &rest)))
                                stringArray[buffer++] = token;
                            int tempRequestFN = atoi(stringArray[0]);
                            int tempReplyFN = atoi(stringArray[1]);
//                            printf("%d -> %d\n", tempRequestFN, tempReplyFN);

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
                                        char *frameTypeBuff = getFrameType(packet);
                                        char *ethertypeBuff = getEtherType(packet, ethertypes);
                                        char *ARPBuff = getARPOperation(packet, ARPOperation);
                                        char *ARPDSTIP = getARPdstIP(packet);
                                        char *ARPSRCIP = getARPsrcIP(packet);
                                        char *ARPSRCMAC = getARPsrcMAC(packet);
                                        char *ARPDSTMAC = getARPdstMAC(packet);

                                        // Request
                                        if (strcasecmp(ARPBuff, "Request") == 0) {
                                            printf("%s-%s, IP Adresa: %s, MAC Adresa: %s\n", ethertypeBuff, ARPBuff, ARPDSTIP, ARPDSTMAC);
                                            printf("Zdrojova IP: %s, Cielova IP: %s\n", ARPSRCIP, ARPDSTIP);
                                        }

                                        // Reply
                                        else {
                                            printf("%s-%s, IP Adresa: %s, MAC Adresa: %s\n", ethertypeBuff, ARPBuff, ARPSRCIP, ARPSRCMAC);
                                            printf("Zdrojova IP: %s, Cielova IP: %s\n", ARPSRCIP, ARPDSTIP);
                                            unitedARPPrint(pcapHeader, packet, frames, frameTypeBuff, ethertypeBuff);
                                            printHexadecimal(pcapHeader->len, packet);
                                            printf("\n=============================================================\n");
                                            break;
                                        }

                                        unitedARPPrint(pcapHeader, packet, frames, frameTypeBuff, ethertypeBuff);
                                        printHexadecimal(pcapHeader->len, packet);
                                        printf("\n=============================================================\n");
                                    }
                                }
                                frames = 0;
                                pcap_close(pcap_file);
                            }
                        }

//                        printf("exclude: %d\n", exclude);

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

//                        printf("finalSetSize %d\n", finalSetSize);

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
                            char *frameTypeBuff = getFrameType(packet);
                            char *ethertypeBuff = getEtherType(packet, ethertypes);
                            char *ARPBuff = getARPOperation(packet, ARPOperation);
                            for(kk = 0; kk < finalSetSize; kk++) {
                                if (strcasecmp(ethertypeBuff, "ARP") == 0 && strcasecmp(ARPBuff, "Request") == 0 && frames == finalSet[kk]) {
                                    requestsWithoutReplies++;
                                    char *ARPDSTIP = getARPdstIP(packet);
                                    char *ARPSRCIP = getARPsrcIP(packet);
                                    char *ARPSRCMAC = getARPsrcMAC(packet);
                                    char *ARPDSTMAC = getARPdstMAC(packet);
                                    printf("%s-%s, IP Adresa: %s, MAC Adresa: %s\n", ethertypeBuff, ARPBuff, ARPDSTIP, ARPDSTMAC);
                                    printf("Zdrojova IP: %s, Cielova IP: %s\n", ARPSRCIP, ARPDSTIP);
                                    unitedARPPrint(pcapHeader, packet, frames, frameTypeBuff, ethertypeBuff);
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
                            char *frameTypeBuff = getFrameType(packet);
                            char *ethertypeBuff = getEtherType(packet, ethertypes);
                            char *ARPBuff = getARPOperation(packet, ARPOperation);
                            for(kk = 0; kk < finalSetSize; kk++) {
                                if (strcasecmp(ethertypeBuff, "ARP") == 0 && strcasecmp(ARPBuff, "Reply") == 0 && frames == finalSet[kk]) {
                                    repliesWithoutRequests++;
                                    char *ARPDSTIP = getARPdstIP(packet);
                                    char *ARPSRCIP = getARPsrcIP(packet);
                                    char *ARPSRCMAC = getARPsrcMAC(packet);
                                    char *ARPDSTMAC = getARPdstMAC(packet);
                                    printf("%s-%s, IP Adresa: %s, MAC Adresa: %s\n", ethertypeBuff, ARPBuff, ARPSRCIP, ARPSRCMAC);
                                    printf("Zdrojova IP: %s, Cielova IP: %s\n", ARPSRCIP, ARPDSTIP);
                                    unitedARPPrint(pcapHeader, packet, frames, frameTypeBuff, ethertypeBuff);
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

                            while ((pcap_next_ex(pcap_file, &pcapHeader, &packet)) >= 0) {
                                frames++;
                                char* frameTypeBuff = getFrameType(packet);
                                char* ethertypeBuff = getEtherType(packet, ethertypes);
                                char* protocolBuff = getProtocol(packet, IPProtocols);
                                char* portBuff = getTCPOrUDPPort(packet, UDPPorts);

                                if (strcasecmp(temp -> srcPort, getSrcPort(packet)) == 0  && temp -> frameNumber <= frames || strcasecmp(temp -> srcPort, getDstPort(packet)) == 0  && temp -> frameNumber <= frames) {
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
                            pcap_close(pcap_file);
                            frames = 0;
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
                            char *frameTypeBuff = getFrameType(packet);
                            char *ethertypeBuff = getEtherType(packet, ethertypes);
                            char *protocolBuff = getProtocol(packet, IPProtocols);
                            char *portBuff = getICMPPort(packet, ICMPPorts);

                            if (strcasecmp(protocolBuff, (const char *) &bigBufferStringArray[frametypeKey][ethertypeKey][protocolKey][portKey]) == 0) {
                                printBasicInfo(frames, pcapHeader->caplen, pcapHeader->len);
                                printf("\n%s", frameTypeBuff);
                                printMACAddress(packet);
                                printf("%s\n", ethertypeBuff);
                                printIPAdresses(packet);
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

                        char *firstCompleteComPort = "FAKE_EMPTY";
                        char *firstIncompleteComPort = "FAKE_EMPTY";

                        bool completeComFullfilled = false;
                        bool incompleteComFullfilled = false;

                        // Verify 3WHS and termination - find one complete and incomplete communication, save it's port
                        while (true) {
                            if (completeComFullfilled == true && incompleteComFullfilled == true)
                                break;

                            char *string = verify3WHS(temp, temp2, temp3);
                            char* token;
                            char* rest = string;
                            char *stringArray[3];
                            int buff = 0;
                            while ((token = strtok_r(rest, " ", &rest)))
                                stringArray[buff++] = token;
                            int tempFrameNumber = atoi(stringArray[0]);
                            char *tempPort = stringArray[1];
//                            printf("~~~~~~~~~~\n");
//                            printf("[New loop]\n");
//                            printf("start: %d Port: %s\n", tempFrameNumber, tempPort);

                            // 3WHS Success, looking for complete com
                            if (strcasecmp(tempPort, "0") && completeComFullfilled == false) {
                                char *potentionalEnd = verifyTermination(temp4, temp5, tempFrameNumber, tempPort);
//                                printf("end: %s\n", potentionalEnd);
//                                printf("~~~~~~~~~~\n");

                                // 4WHS Success aka complete com
                                if (strcasecmp(potentionalEnd, "0")) {
                                    completeComFullfilled = true;
                                    firstCompleteComPort = tempPort;
//                                    printf("[4WHS Success, first complete com]\n");
//                                    printf("1st COMPLETE com [ %s ] = start: %d\tend: %s\n", tempPort, tempFrameNumber, potentionalEnd);
                                    continue;
                                }

                                // 4WHS Fail at the first itaration
                                else if (strcasecmp(potentionalEnd, "0") == 0 && incompleteComFullfilled == false) {
                                    firstIncompleteComPort = tempPort;
                                    incompleteComFullfilled = true;
//                                    printf("[4WHS Fail, incomplete com fullfilled, first loop]\n");
//                                    printf("1st INCOMPLETE com [ %s ] = start: %d\tend: %s\n", tempPort, tempFrameNumber, potentionalEnd);
                                    continue;
                                }
                            }

                            // 3WHS Success, looking for incomplete com
                            else if (strcasecmp(tempPort, "0") && completeComFullfilled == true) {
//                                printf("\n[3WHS Success, complete com fullfilled]\n");
                                char *potentionalEnd = verifyTermination(temp4, temp5, tempFrameNumber, tempPort);
//                                printf("end %s\n", potentionalEnd);
//                                printf("~~~~~~~~~~\n");

                                if (strcasecmp(potentionalEnd, "0") == 0) {
                                    incompleteComFullfilled = true;
                                    firstIncompleteComPort = tempPort;
//                                    printf("[4WHS Fail, incomplete com fullfilled]\n");
//                                    printf("1st INCOMPLETE com [ %s ] = start: %d\tend: %s\n", tempPort, tempFrameNumber, potentionalEnd);
                                    break;
                                }
                            }
                                // 3WHS Fail
                            else {
//                                printf("[3WHS Fail, no complete com found]\n");
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
                            char* portBuff = getTCPOrUDPPort(packet, TCPPorts);
                            if (strcasecmp(portBuff, (const char *) &bigBufferStringArray[frametypeKey][ethertypeKey][protocolKey][portKey]) == 0 && (strcasecmp(getSrcPort(packet), firstCompleteComPort) == 0 || strcasecmp(getDstPort(packet), firstCompleteComPort) == 0))
                                completeComFrameCount++;
                        }
                        pcap_close(pcap_file);

                        if (completeComFrameCount != 0) {
                            printf("\n=============================================================\n");
                            printf("Prva kompletna %s komunikacia je pod portom %s, obsahuje %d ramcov", (const char *) bigBufferStringArray[frametypeKey][ethertypeKey][protocolKey][portKey], firstCompleteComPort, completeComFrameCount);
                            printf("\n=============================================================\n");
                        }

                        else {
                            printf("\n=============================================================\n");
                            printf("Subor neobsahoval ani jednu kompletnu %s komunikaciu", (const char *) bigBufferStringArray[frametypeKey][ethertypeKey][protocolKey][portKey]);
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
                            char* ethertypeBuff = getEtherType(packet, ethertypes);
                            char* protocolBuff = getProtocol(packet, IPProtocols);
                            char* portBuff = getTCPOrUDPPort(packet, TCPPorts);

                            if (strcasecmp(portBuff, (const char *) &bigBufferStringArray[frametypeKey][ethertypeKey][protocolKey][portKey]) == 0 && (strcasecmp(getSrcPort(packet), firstCompleteComPort) == 0 || strcasecmp(getDstPort(packet), firstCompleteComPort) == 0)) {
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
                            char* portBuff = getTCPOrUDPPort(packet, TCPPorts);
                            if (strcasecmp(portBuff, (const char *) &bigBufferStringArray[frametypeKey][ethertypeKey][protocolKey][portKey]) == 0 && (strcasecmp(getSrcPort(packet), firstIncompleteComPort) == 0 || strcasecmp(getDstPort(packet), firstIncompleteComPort) == 0))
                                incompleteComFrameCount++;
                        }
                        pcap_close(pcap_file);

                        if (incompleteComFrameCount != 0) {
                            printf("Prva nekompletna %s komunikacia je pod portom %s, obsahuje %d ramcov", (const char *) bigBufferStringArray[frametypeKey][ethertypeKey][protocolKey][portKey], firstIncompleteComPort, incompleteComFrameCount);
                            printf("\n=============================================================\n");
                        }

                        else {
                            printf("Subor neobsahoval ani jednu nekompletnu %s komunikaciu", (const char *) bigBufferStringArray[frametypeKey][ethertypeKey][protocolKey][portKey]);
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
                            char* ethertypeBuff = getEtherType(packet, ethertypes);
                            char* protocolBuff = getProtocol(packet, IPProtocols);
                            char* portBuff = getTCPOrUDPPort(packet, TCPPorts);

                            if (strcasecmp(getSrcPort(packet), firstIncompleteComPort) == 0 || strcasecmp(getDstPort(packet), firstIncompleteComPort) == 0) {
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
                        deleteTCPPacketList(&TCPhead);
                        frames = 0;
                        ethertypeKey = 0;
                        protocolKey = 0;
                        portKey = 0;
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