#include <stdio.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <ctype.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>

#define MAX_INPUT_SIZE 256
#define MAX_IP_SIZE 32
#define MAX_PORT_SIZE 5
#define BUFFERLENGTH 256

typedef struct IpRange
{
    char startIP[MAX_IP_SIZE];
    char endIP[MAX_IP_SIZE];
} IpRange;

typedef struct PortRange
{
    char startPort[MAX_PORT_SIZE];
    char endPort[MAX_PORT_SIZE];
} PortRange;

typedef struct Pair
{
    char IPAddress[MAX_IP_SIZE];
    char port[MAX_PORT_SIZE];
    struct Pair *next;
} Pair;

typedef struct FirewallRule
{
    IpRange IPAddresses;
    PortRange ports;
    Pair *pairs;
    struct FirewallRule *next;
} FirewallRule;

typedef struct Request
{
    char input[MAX_INPUT_SIZE];
    struct Request *next;
} Request;

typedef struct threadArgs
{
    FirewallRule **rules;
    Request **requests;
    int *newsockFD;
} threadArgs;

void error(char *msg)
{
    perror(msg);
    exit(1);
}

int isExecuted = 0;
pthread_mutex_t mut = PTHREAD_MUTEX_INITIALIZER;
pthread_rwlock_t rulesListLock = PTHREAD_RWLOCK_INITIALIZER;
pthread_rwlock_t requestsListLock = PTHREAD_RWLOCK_INITIALIZER;

char *readRes(int sockfd)
{
    size_t bufsize;
    int res;
    char *buffer;

    res = read(sockfd, &bufsize, sizeof(size_t));
    if (res != sizeof(size_t))
    {
        fprintf(stderr, "Reading number of bytes from socket failed\n");
        return NULL;
    }

    buffer = malloc(bufsize + 1);
    if (buffer)
    {
        buffer[bufsize] = '\0';
        res = read(sockfd, buffer, bufsize);
        if (res != bufsize)
        {
            fprintf(stderr, "Reading reply from socket\n");
            free(buffer);
            return NULL;
        }
    }

    return buffer;
}

int writeResult(int sockfd, char *buffer, size_t bufsize)
{
    int n;

    n = write(sockfd, &bufsize, sizeof(size_t));
    if (n < 0)
    {
        fprintf(stderr, "ERROR writing to result\n");
        return -1;
    }

    n = write(sockfd, buffer, bufsize);
    if (n != bufsize)
    {
        fprintf(stderr, "Couldn't write %ld bytes, wrote %d bytes\n", bufsize, n);
        return -1;
    }
    return 0;
}

void addRequest(Request **head, const char *input)
{
    Request *newRequest = (Request *)malloc(sizeof(Request));
    if (newRequest == NULL)
    {
        printf("Allocation of new request memory failed.\n");
        return;
    }
    strncpy(newRequest->input, input, MAX_INPUT_SIZE - 1);
    newRequest->input[MAX_INPUT_SIZE - 1] = '\0';
    newRequest->next = NULL;

    pthread_rwlock_wrlock(&requestsListLock);
    if (*head == NULL)
    {
        *head = newRequest;
    }
    else
    {
        Request *current = *head;
        while (current->next != NULL)
        {
            current = current->next;
        }
        current->next = newRequest;
    }
    pthread_rwlock_unlock(&requestsListLock);
}

void freeRequests(Request *head)
{
    Request *current = head;
    Request *nextRequest;

    while (current != NULL)
    {
        nextRequest = current->next;
        free(current);
        current = nextRequest;
    }
}

void freeRules(FirewallRule *head)
{
    FirewallRule *currentRule = head;
    FirewallRule *nextRule;

    while (currentRule != NULL)
    {
        nextRule = currentRule->next;

        Pair *currentPair = currentRule->pairs;
        while (currentPair != NULL)
        {
            Pair *nextPair = currentPair->next;
            free(currentPair);
            currentPair = nextPair;
        }

        free(currentRule);
        currentRule = nextRule;
    }
}

void listRequests(const Request *head)
{
    const Request *current = head;
    pthread_rwlock_rdlock(&requestsListLock);

    while (current != NULL)
    {
        printf("%s\n", current->input);
        current = current->next;
    }
    pthread_rwlock_unlock(&requestsListLock);
}

bool checkIP(const char *IPStr, IpRange *IPs)
{

    int dots = 0;
    const char *ptr = IPStr;
    char lastChar = '\0';

    while (*ptr)
    {

        if (*ptr == '.' && lastChar == '.')
        {
            return false;
        }

        char stringOctet[4] = {0};
        int i = 0;

        while (*ptr && *ptr != '.' && i < 3)
        {
            if (!isdigit(*ptr))
                return false;
            stringOctet[i++] = *ptr++;
        }

        if (i == 3 && *ptr != '.' && *ptr != '\0')
        {
            return false;
        }

        stringOctet[i] = '\0';

        int numOctet = atoi(stringOctet);
        if (numOctet < 0 || numOctet > 255)
        {
            return false;
        }

        if (*ptr == '.')
        {
            dots++;
            lastChar = '.';
            ptr++;
        }
        else
        {
            lastChar = *ptr;
        }
    }

    if (lastChar == '.' || IPStr[0] == '.' || dots != 3)
    {
        return false;
    }

    strcpy(IPs->startIP, IPStr);
    strcpy(IPs->endIP, IPStr);

    return true;
}

bool compareIPs(char *lowerIP, char *upperIP, bool included)
{

    unsigned int lowerOctet1, lowerOctet2, lowerOctet3, lowerOctet4;
    unsigned int upperOctet1, upperOctet2, upperOctet3, upperOctet4;

    sscanf(lowerIP, "%u.%u.%u.%u", &lowerOctet1, &lowerOctet2, &lowerOctet3, &lowerOctet4);
    sscanf(upperIP, "%u.%u.%u.%u", &upperOctet1, &upperOctet2, &upperOctet3, &upperOctet4);

    unsigned long long decLowerIP = (lowerOctet1 * 256 * 256 * 256) + (lowerOctet2 * 256 * 256) +
                                    (lowerOctet3 * 256) + (lowerOctet4);

    unsigned long long decUpperIP = (upperOctet1 * 256 * 256 * 256) + (upperOctet2 * 256 * 256) +
                                    (upperOctet3 * 256) + (upperOctet4);

    if ((included == false) && (decLowerIP == decUpperIP))
    {
        return false;
    }

    if (decLowerIP > decUpperIP)
    {
        return false;
    }
    else
    {
        return true;
    }
}

bool checkIPRange(const char *IPString, IpRange *IPs)
{

    if (IPString == NULL)
    {
        return false;
    }

    char IPCopy[256];
    size_t inputLen = strlen(IPString);
    if (inputLen >= sizeof(IPCopy))
    {
        return false;
    }
    memcpy(IPCopy, IPString, inputLen);
    IPCopy[inputLen] = '\0';

    char *IPSplit = strchr(IPCopy, '-');
    if (IPSplit == NULL)
    {
        // Single IP case
        return checkIP(IPCopy, IPs);
    }

    // Split the range of IPs
    *IPSplit = '\0';
    char *lowerIP = IPCopy;
    char *upperIP = IPSplit + 1;

    if (*lowerIP == '\0' || *upperIP == '\0' || strchr(upperIP, '-') != NULL)
    {
        return false;
    }

    IpRange tempLower, tempUpper;

    if (!checkIP(lowerIP, &tempLower) || !checkIP(upperIP, &tempUpper))
    {
        return false;
    }

    if (!compareIPs(lowerIP, upperIP, false))
    {
        return false;
    }

    // Copy validated results to output parameter
    strncpy(IPs->startIP, tempLower.startIP, sizeof(IPs->startIP) - 1);
    IPs->startIP[sizeof(IPs->startIP) - 1] = '\0';
    strncpy(IPs->endIP, tempUpper.endIP, sizeof(IPs->endIP) - 1);
    IPs->endIP[sizeof(IPs->endIP) - 1] = '\0';

    return true;
}

bool checkPort(const char *portStr, PortRange *ports)
{

    if (portStr == NULL || *portStr == '\0')
    {
        return false;
    }

    if (portStr[0] == '0' && portStr[1] != '\0')
    {
        return false;
    }

    for (int i = 0; portStr[i] != '\0'; i++)
    {
        if (!isdigit((unsigned char)portStr[i]))
        {
            return false;
        }
    }

    int intPort = atoi(portStr);

    if (intPort < 0 || intPort > 65535)
    {
        return false;
    }

    strcpy(ports->startPort, portStr);
    strcpy(ports->endPort, portStr);

    return true;
}

bool isValidPort(const char *portStr)
{

    if (portStr == NULL || *portStr == '\0')
    {
        return false;
    }

    if (portStr[0] == '0' && portStr[1] != '\0')
    {
        return false;
    }

    for (int i = 0; portStr[i] != '\0'; i++)
    {
        if (!isdigit((unsigned char)portStr[i]))
        {
            return false;
        }
    }

    int intPort = atoi(portStr);

    if (intPort < 0 || intPort > 65535)
    {
        return false;
    }

    return true;
}

bool checkPortRange(const char *portStr, PortRange *ports)
{

    if (portStr == NULL)
    {
        return false;
    }

    char portCopy[256];
    size_t inputLen = strlen(portStr);
    if (inputLen >= sizeof(portCopy))
    {
        return false;
    }
    memcpy(portCopy, portStr, inputLen);
    portCopy[inputLen] = '\0';

    char *portSplit = strchr(portCopy, '-');
    if (portSplit == NULL)
    {
        // Single port case
        return checkPort(portCopy, ports);
    }

    // Split the range by the ports
    *portSplit = '\0';
    char *lowerPort = portCopy;
    char *upperPort = portSplit + 1;

    // Check for invalid formats
    if (*lowerPort == '\0' || *upperPort == '\0' || strchr(upperPort, '-') != NULL)
    {
        return false;
    }

    PortRange tempLower, tempUpper;

    // Validate both ports
    if (!checkPort(lowerPort, &tempLower) || !checkPort(upperPort, &tempUpper))
    {
        return false;
    }

    // Compare numerical values
    int lower = atoi(lowerPort);
    int upper = atoi(upperPort);
    if (lower >= upper)
    {
        return false;
    }

    // Copy validated results to output parameter
    strncpy(ports->startPort, tempLower.startPort, sizeof(ports->startPort) - 1);
    ports->startPort[sizeof(ports->startPort) - 1] = '\0';
    strncpy(ports->endPort, tempUpper.endPort, sizeof(ports->endPort) - 1);
    ports->endPort[sizeof(ports->endPort) - 1] = '\0';

    return true;
}

bool parseRule(const char *input, IpRange *IPs, PortRange *ports)
{

    if (input == NULL)
    {
        return false;
    }

    // skip command and space
    char *tmp = strdup(input + 2);
    if (tmp == NULL)
    {
        return false;
    }

    // Find first space
    char *space = strchr(tmp, ' ');
    if (space == NULL)
    {
        free(tmp);
        return false;
    }

    // End of IP or IPRange
    *space = '\0';

    if (!checkIPRange(tmp, IPs))
    {
        // Check if it's a single IP
        if (!checkIP(tmp, IPs))
        {
            free(tmp);
            return false;
        }
        // Copy the single IP to both start and end IP
        strcpy(IPs->endIP, IPs->startIP);
    }

    // Start of Port or PortRange
    char *portStr = space + 1;

    // Check if there is any ports
    if (*portStr == '\0')
    {
        free(tmp);
        return false;
    }

    // Check for additional spaces
    if (strchr(portStr, ' ') != NULL)
    {
        free(tmp);
        return false;
    }

    if (!checkPortRange(portStr, ports))
    {
        // Check if it's a single port
        if (!checkPort(portStr, ports))
        {
            free(tmp);
            return false;
        }
        // Copy the single port to both start and end port
        strcpy(ports->endPort, ports->startPort);
    }

    free(tmp);
    return true;
}

bool addRule(FirewallRule **head, const IpRange *IPs, const PortRange *ports)
{

    FirewallRule *newRule = (FirewallRule *)malloc(sizeof(FirewallRule));
    if (newRule == NULL)
    {
        printf("Allocation of new rule memory failed.\n");
        return false;
    }

    // Copy the IP and port ranges
    memcpy(&newRule->IPAddresses, IPs, sizeof(IpRange));
    memcpy(&newRule->ports, ports, sizeof(PortRange));
    newRule->pairs = NULL;
    newRule->next = NULL;

    pthread_rwlock_wrlock(&rulesListLock);
    // Add the new rule to the list
    if (*head == NULL)
    {
        *head = newRule;
    }
    else
    {
        FirewallRule *current = *head;
        while (current->next != NULL)
        {
            current = current->next;
        }
        current->next = newRule;
    }

    pthread_rwlock_unlock(&rulesListLock);
    printf("Rule added\n");
    return true;
}

bool checkRule(FirewallRule **head, IpRange *IP, PortRange *port)
{

    bool validRule = false;

    pthread_rwlock_wrlock(&rulesListLock);

    // if list is empty
    if (*head == NULL)
    {
        pthread_rwlock_unlock(&rulesListLock);
        return false;
    }

    FirewallRule *currentRule = *head;
    // for each rule
    while (currentRule != NULL)
    {

        // if the ip lies in the range of acceptable IPs
        if (compareIPs(IP->startIP, currentRule->IPAddresses.endIP, true) &&
            compareIPs(currentRule->IPAddresses.startIP, IP->startIP, true) &&
            (atoi(port->startPort) <= atoi(currentRule->ports.endPort)) &&
            (atoi(currentRule->ports.startPort) <= atoi(port->startPort)))
        {

            // create new pair
            Pair *newPair = (Pair *)malloc(sizeof(Pair));
            if (newPair == NULL)
            {
                printf("Allocation of new pair memory failed.\n");
                pthread_rwlock_unlock(&rulesListLock);
                return false;
            }

            memcpy(newPair->IPAddress, IP->startIP, strlen(IP->startIP) + 1);
            memcpy(newPair->port, port->startPort, strlen(port->startPort) + 1);
            newPair->next = NULL;

            newPair->next = currentRule->pairs;
            currentRule->pairs = newPair;

            validRule = true;
            break;
        }
        currentRule = currentRule->next;
    }

    pthread_rwlock_unlock(&rulesListLock);
    return validRule;
}

bool deleteRule(FirewallRule **head, const IpRange *IPs, const PortRange *ports)
{

    // if list is empty
    if (*head == NULL)
    {
        return false;
    }

    pthread_rwlock_wrlock(&rulesListLock);

    bool ruleDeleted = false;

    FirewallRule *currentRule = *head;
    FirewallRule *prevRule = NULL;
    FirewallRule *nextRule;

    // for each rule
    while (currentRule != NULL)
    {
        nextRule = currentRule->next;

        // if this is the rule to be deleted
        if ((strcmp(currentRule->IPAddresses.startIP, IPs->startIP) == 0) &&
            (strcmp(currentRule->IPAddresses.endIP, IPs->endIP) == 0) &&
            (atoi(currentRule->ports.startPort) == atoi(ports->startPort)) &&
            (atoi(currentRule->ports.endPort) == atoi(ports->endPort)))
        {

            Pair *currentPair = currentRule->pairs;

            // for each pair
            while (currentPair != NULL)
            {
                Pair *nextPair = currentPair->next;
                free(currentPair);
                currentPair = nextPair;
            }

            if (prevRule == NULL)
            {
                *head = nextRule;
            }
            else
            {
                prevRule->next = nextRule;
            }

            free(currentRule);
            currentRule = NULL;
            ruleDeleted = true;
            break;
        }
        prevRule = currentRule;
        currentRule = nextRule;
    }

    pthread_rwlock_unlock(&rulesListLock);
    return ruleDeleted;
}

void listRules(FirewallRule **head)
{

    pthread_rwlock_rdlock(&rulesListLock);
    FirewallRule *currentRule = *head;

    // for each rule
    while (currentRule != NULL)
    {

        if (strcmp(currentRule->IPAddresses.startIP, currentRule->IPAddresses.endIP) == 0)
        {
            if (strcmp(currentRule->ports.startPort, currentRule->ports.endPort) == 0)
            {
                printf("Rule: %s %s\n", currentRule->IPAddresses.startIP,
                       currentRule->ports.startPort);
            }
            else
            {
                printf("Rule: %s %s-%s\n", currentRule->IPAddresses.startIP,
                       currentRule->ports.startPort, currentRule->ports.endPort);
            }
        }
        else
        {
            if (strcmp(currentRule->ports.startPort, currentRule->ports.endPort) == 0)
            {
                printf("Rule: %s-%s %s\n", currentRule->IPAddresses.startIP,
                       currentRule->IPAddresses.endIP, currentRule->ports.startPort);
            }
            else
            {
                printf("Rule: %s-%s %s-%s\n", currentRule->IPAddresses.startIP,
                       currentRule->IPAddresses.endIP, currentRule->ports.startPort,
                       currentRule->ports.endPort);
            }
        }

        Pair *currentPair = currentRule->pairs;
        while (currentPair != NULL)
        {
            printf("Query: %s %s\n", currentPair->IPAddress, currentPair->port);
            currentPair = currentPair->next;
        }

        currentRule = currentRule->next;
    }

    pthread_rwlock_unlock(&rulesListLock);
}

void parseInput(const char *input, Request **requests, FirewallRule **rules)
{

    char command = input[0];
    IpRange IPs;
    PortRange ports;

    switch (command)
    {
    case 'R':
        listRequests(*requests);
        break;
    case 'A':
        if (parseRule(input, &IPs, &ports))
        {
            addRule(rules, &IPs, &ports);
        }
        else
        {
            printf("Invalid rule\n");
        }
        break;
    case 'C':
        if (parseRule(input, &IPs, &ports))
        {
            if (checkRule(rules, &IPs, &ports))
            {
                printf("Connection accepted\n");
            }
            else
            {
                printf("Connection rejected\n");
            }
        }
        else
        {
            printf("Illegal IP address or port specified\n");
        }
        break;
    case 'D':
        if (parseRule(input, &IPs, &ports))
        {
            if (deleteRule(rules, &IPs, &ports))
            {
                printf("Rule deleted\n");
            }
            else
            {
                printf("Rule not found\n");
            }
        }
        else
        {
            printf("Rule invalid\n");
        }
        break;
    case 'L':
        listRules(rules);
        break;
    default:
        printf("Illegal request\n");
        break;
    }
}

// client server mode

void listClientRequests(Request *head, int newsockfd)
{
    pthread_rwlock_rdlock(&requestsListLock);
    Request *current = head;

    // first pass for memory allocaton
    int strLength = 0;
    while (current != NULL)
    {
        strLength += strlen(current->input) + 1;
        current = current->next;
    }

    char *reqStr = (char *)malloc(strLength + 1);
    if (reqStr == NULL)
    {
        printf("Allocation of new memeory failed.\n");
        pthread_rwlock_unlock(&requestsListLock);
        exit(1);
    }

    // second pass to fill buffer
    current = head;
    char *ptr = reqStr;
    while (current != NULL)
    {
        strcpy(ptr, current->input);
        ptr += strlen(current->input) + 1;
        *ptr = '\n';
        ptr += 1;
        current = current->next;
    }

    *ptr = '\0';

    int n = writeResult(newsockfd, reqStr, strLength);
    if (n < 0)
    {
        error("ERROR writing to socket");
    }

    free(reqStr);
    pthread_rwlock_unlock(&requestsListLock);
}

bool addClientRule(FirewallRule **head, const IpRange *IPs, const PortRange *ports, int newsockfd)
{

    pthread_rwlock_wrlock(&rulesListLock);
    FirewallRule *newRule = (FirewallRule *)malloc(sizeof(FirewallRule));
    if (newRule == NULL)
    {
        pthread_rwlock_unlock(&rulesListLock);
        printf("Allocation of new rule memory failed.\n");
        return false;
    }

    // Copy the IP and port ranges
    memcpy(&newRule->IPAddresses, IPs, sizeof(IpRange));
    memcpy(&newRule->ports, ports, sizeof(PortRange));
    newRule->pairs = NULL;
    newRule->next = NULL;

    // Add the new rule to the list
    if (*head == NULL)
    {
        *head = newRule;
    }
    else
    {
        FirewallRule *current = *head;
        while (current->next != NULL)
        {
            current = current->next;
        }
        current->next = newRule;
    }

    pthread_rwlock_unlock(&rulesListLock);
    int n = writeResult(newsockfd, "Rule added", 11);
    if (n < 0)
    {
        error("ERROR writing to socket");
    }

    return true;
}

void listClientRules(FirewallRule **head, int newsockfd)
{

    pthread_rwlock_rdlock(&rulesListLock);

    FirewallRule *currentRule = *head;
    Pair *currentPair;
    int n;

    const int maxRuleLength = 64;
    const int maxPairLength = 32;
    int numRules = 0;
    int numPairs = 0;

    // calc how many rules and pairs
    while (currentRule != NULL)
    {
        numRules++;

        currentPair = currentRule->pairs;
        while (currentPair != NULL)
        {
            numPairs++;
            currentPair = currentPair->next;
        }

        currentRule = currentRule->next;
    }

    int strLength = (numRules * maxRuleLength + 1) + (numPairs * maxPairLength + 1) + 1;
    char *rulesStr = (char *)malloc(strLength);
    if (rulesStr == NULL)
    {
        printf("Allocation of new memeory failed.\n");
        pthread_rwlock_unlock(&rulesListLock);
        exit(1);
    }

    char *ptr = rulesStr;
    currentRule = *head;

    // for each rule
    while (currentRule != NULL)
    {
        if (strcmp(currentRule->IPAddresses.startIP, currentRule->IPAddresses.endIP) == 0)
        {
            if (strcmp(currentRule->ports.startPort, currentRule->ports.endPort) == 0)
            {
                ptr += snprintf(ptr, maxRuleLength, "Rule: %s %s\n",
                                currentRule->IPAddresses.startIP,
                                currentRule->ports.startPort);
            }
            else
            {
                ptr += snprintf(ptr, maxRuleLength, "Rule: %s %s-%s\n", currentRule->IPAddresses.startIP,
                                currentRule->ports.startPort,
                                currentRule->ports.endPort);
            }
        }
        else
        {
            if (strcmp(currentRule->ports.startPort, currentRule->ports.endPort) == 0)
            {
                ptr += snprintf(ptr, maxRuleLength, "Rule: %s-%s %s\n", currentRule->IPAddresses.startIP,
                                currentRule->IPAddresses.endIP,
                                currentRule->ports.startPort);
            }
            else
            {
                ptr += snprintf(ptr, maxRuleLength, "Rule: %s-%s %s-%s\n",
                                currentRule->IPAddresses.startIP,
                                currentRule->IPAddresses.endIP,
                                currentRule->ports.startPort,
                                currentRule->ports.endPort);
            }
        }

        currentPair = currentRule->pairs;
        while (currentPair != NULL)
        {
            ptr += snprintf(ptr, maxPairLength, "Query: %s %s\n", currentPair->IPAddress, currentPair->port);
            currentPair = currentPair->next;
        }
        currentRule = currentRule->next;
    }

    n = writeResult(newsockfd, rulesStr, strLength);
    if (n < 0)
    {
        error("ERROR writing to socket");
    }

    free(rulesStr);
    pthread_rwlock_unlock(&rulesListLock);
}

void parseClientInput(const char *input, Request **requests, FirewallRule **rules, int newsockfd)
{

    char command = input[0];
    IpRange IPs;
    PortRange ports;
    int n;

    switch (command)
    {
    case 'R':
        listClientRequests(*requests, newsockfd);
        break;
    case 'A':
        if (parseRule(input, &IPs, &ports))
        {
            addClientRule(rules, &IPs, &ports, newsockfd);
        }
        else
        {
            n = writeResult(newsockfd, "Invalid rule", 12);
            if (n < 0)
            {
                error("ERROR writing to socket");
            }
        }
        break;
    case 'C':
        if (parseRule(input, &IPs, &ports))
        {
            if (checkRule(rules, &IPs, &ports))
            {
                printf("Connection accepted\n");
                n = writeResult(newsockfd, "Connection accepted", 19);
                if (n < 0)
                {
                    error("ERROR writing to socket");
                }
            }
            else
            {
                printf("Connection rejected\n");
                n = writeResult(newsockfd, "Connection rejected", 19);
                if (n < 0)
                {
                    error("ERROR writing to socket");
                }
            }
        }
        else
        {
            n = writeResult(newsockfd, "Illegal IP address or port specified", 36);
            if (n < 0)
            {
                error("ERROR writing to socket");
            }
        }
        break;
    case 'D':
        if (parseRule(input, &IPs, &ports))
        {
            if (deleteRule(rules, &IPs, &ports))
            {
                n = writeResult(newsockfd, "Rule deleted", 12);
                if (n < 0)
                {
                    error("ERROR writing to socket");
                }
            }
            else
            {
                n = writeResult(newsockfd, "Rule not found", 14);
                if (n < 0)
                {
                    error("ERROR writing to socket");
                }
            }
        }
        else
        {
            n = writeResult(newsockfd, "Rule invalid", 12);
            if (n < 0)
            {
                error("ERROR writing to socket");
            }
        }
        break;
    case 'L':
        listClientRules(rules, newsockfd);
        break;
    default:
        n = writeResult(newsockfd, "Illegal request", 15);
        if (n < 0)
        {
            error("ERROR writing to socket");
        }
        break;
    }
}

void *processRequest(void *args)
{
    threadArgs *data = (threadArgs *)args;
    int *newsockfd = data->newsockFD;
    Request **requests = data->requests;
    FirewallRule **rules = data->rules;
    int tmp;
    char *buffer;

    buffer = readRes(*newsockfd);
    if (!buffer)
    {
        fprintf(stderr, "ERROR reading from socket\n");
    }
    else
    {
        pthread_mutex_lock(&mut); /* lock exclusive access to variable isExecuted */
        tmp = isExecuted;

        addRequest(requests, buffer);
        parseClientInput(buffer, requests, rules, *newsockfd);

        isExecuted = tmp + 1;
        pthread_mutex_unlock(&mut); /* release the lock */

        buffer = realloc(buffer, BUFFERLENGTH);
    }

    free(buffer);
    close(*newsockfd); /* important to avoid memory leak */
    free(newsockfd);
    free(data);

    pthread_exit(NULL); /*exit value not used */
}

int main(int argc, char **argv)
{

    setvbuf(stdout, NULL, _IONBF, 0);

    FirewallRule *rules = NULL;
    Request *requests = NULL;

    char *line = NULL;
    size_t size;
    int res;

    int sockfd, portno;
    struct sockaddr_in6 serv_addr;
    int result;

    if (strcmp(argv[1], "-i") == 0)
    {
        while (1)
        {
            res = getline(&line, &size, stdin);
            if (res != -1)
            {
                if (line[res - 1] == '\n')
                {
                    line[res - 1] = '\0';
                }
                addRequest(&requests, line);
                parseInput(line, &requests, &rules);
            }
        }
    }
    else if (isValidPort(argv[1]))
    {

        sockfd = socket(AF_INET6, SOCK_STREAM, 0);
        if (sockfd < 0)
        {
            error("ERROR opening socket");
        }

        bzero((char *)&serv_addr, sizeof(serv_addr));
        portno = atoi(argv[1]);
        serv_addr.sin6_family = AF_INET6;
        serv_addr.sin6_addr = in6addr_any;
        serv_addr.sin6_port = htons(portno);

        /* bind it */
        if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
        {
            error("ERROR on binding");
        }

        /* ready to accept connections */
        listen(sockfd, 5);

        /* now wait in an endless loop for connections and process them */
        while (1)
        {

            pthread_t server_thread;     /* thread information */
            pthread_attr_t pthread_attr; /* attributes for newly created thread */
            int *newsockfd;
            struct sockaddr_in6 cli_addr;
            socklen_t clilen;

            clilen = sizeof(cli_addr);
            newsockfd = malloc(sizeof(int));
            if (!newsockfd)
            {
                fprintf(stderr, "Memory allocation failed!\n");
                exit(1);
            }

            threadArgs *args = malloc(sizeof(threadArgs));
            if (!args)
            {
                fprintf(stderr, "Memory allocation failed!\n");
                exit(1);
            }
            args->rules = &rules;
            args->requests = &requests;
            args->newsockFD = newsockfd;

            /* waiting for connections */
            *newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, &clilen);
            if (*newsockfd < 0)
            {
                error("ERROR on accept");
            }

            if (pthread_attr_init(&pthread_attr))
            {
                fprintf(stderr, "Creating initial thread attributes failed!\n");
                exit(1);
            }

            if (pthread_attr_setdetachstate(&pthread_attr, PTHREAD_CREATE_DETACHED))
            {
                fprintf(stderr, "setting thread attributes failed!\n");
                exit(1);
            }

            result = pthread_create(&server_thread, &pthread_attr, processRequest, (void *)args);
            if (result != 0)
            {
                fprintf(stderr, "Thread creation failed!\n");
                exit(1);
            }
        }
    }
    else
    {
        error("Incorrect server call");
    }

    free(line);
    pthread_rwlock_destroy(&requestsListLock);
    pthread_rwlock_destroy(&rulesListLock);
    freeRequests(requests);
    freeRules(rules);
    return 0;
}
