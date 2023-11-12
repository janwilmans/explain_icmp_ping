/*
 * Copyright (c) 2023 Jan Wilmans, MIT License
 */

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

// the reason for this method is that bzero() is not standard C11 and I really
// do not like the fact that messing up the order of arguments to 'memset' to zero out memory
// can cause serious bugs. I would like memset_explicit even more, but C23 isn't available to me at this like
void zero_inititialize(void * data, int size)
{
    memset(data, 0, size);
}

// this will convert any binary data into a readable ascii form
// unprintable ascii characters are coverted to dots
const char * to_hex_string(const void * object, int size)
{
    const char * data = (const char *)object;
    static char buffer[1024];
    char * write_pointer = &buffer[0];
    for (int i = 0; i < size; ++i)
    {
        int bytes_written = sprintf(write_pointer, "%02X ", (uint8_t)data[i]);
        write_pointer += bytes_written;
    }

    *write_pointer = ';';
    ++write_pointer;

    for (int i = 0; i < size; ++i)
    {
        char c = data[i];
        if (c < 32)
        {
            *write_pointer = '.';
            ++write_pointer;
            continue;
        }
        *write_pointer = c;
        ++write_pointer;
    }
    *write_pointer = '\0';
    return &buffer[0];
}

// lookup the dns-name of associated with an ipaddress
bool reverse_dns_lookup(const char * ipaddress, char * name_out, int size)
{
    struct sockaddr_in addr;
    zero_inititialize(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(ipaddress);

    char buffer[NI_MAXHOST];
    if (getnameinfo((struct sockaddr *)&addr, sizeof(struct sockaddr_in), buffer, sizeof(buffer), NULL, 0, NI_NAMEREQD))
    {
        printf("Could not resolve reverse lookup of hostname\n");
        return false;
    }

    strncpy(name_out, &buffer[0], size);
    return true;
}

// you can choose to send more or less dummy payload data
#define ICMP_PAYLOAD_LENGTH (64 - sizeof(struct icmphdr))
struct ping_pkt
{
    struct icmphdr hdr;
    char payload[ICMP_PAYLOAD_LENGTH];
};

unsigned short calculate_checksum(const struct ping_pkt * packet)
{
    const unsigned short * view = (const unsigned short *)packet;
    size_t size = sizeof(struct ping_pkt);

    unsigned int sum = 0;
    for (; size > 1; size -= 2)
    {
        sum += *view++;
    }
    if (size == 1)
    {
        sum += *(unsigned char *)view;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return ~sum;
}

const char * dns_lookup_and_store_address(const char * address, struct sockaddr_in * sock_addr)
{
    static char buffer[1024];

    zero_inititialize(&buffer, sizeof(buffer));
    const uint16_t port = 0;
    struct hostent * host_entity = gethostbyname(address);
    if (host_entity == NULL)
    {
        printf("gethostbyname for '%s' failed.\n", address);
        return NULL;
    }
    const char * name = inet_ntoa(*(struct in_addr *)host_entity->h_addr_list[0]);
    strncpy(buffer, name, sizeof(buffer));
    if (sock_addr != NULL)
    {
        sock_addr->sin_family = host_entity->h_addrtype;
        sock_addr->sin_port = htons(port);
        sock_addr->sin_addr.s_addr = *(long *)host_entity->h_addr_list[0];
    }
    return &buffer[0];
}

int set_ttl(int socket_fd, int ttl)
{
    return setsockopt(socket_fd, SOL_IP, IP_TTL, &ttl, sizeof(ttl));
}

int set_receive_timeout(int socket_fd, int timeout_ms)
{
    int seconds = timeout_ms / 1000;
    int useconds = (timeout_ms - (seconds * 1000)) * 1000;
    struct timeval tv_out;
    zero_inititialize(&tv_out, sizeof(tv_out));
    tv_out.tv_sec = seconds;
    tv_out.tv_usec = useconds;
    return setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &tv_out, sizeof(tv_out));
}

void initialize_icmp_packet(struct ping_pkt * icmp_packet)
{
    zero_inititialize(icmp_packet, sizeof(*icmp_packet));
    icmp_packet->hdr.type = ICMP_ECHO;
    icmp_packet->hdr.un.echo.id = getpid();
    icmp_packet->hdr.un.echo.sequence = 0;

    // the payload is arbitrary, it can be any data but it is good practice to
    // send something recognizable like a string.
    // its important to make sure to calculate the checksum _after_ filling the payload.
    for (size_t i = 0; i < ICMP_PAYLOAD_LENGTH; ++i)
    {
        icmp_packet->payload[i] = (char)('0' + i);
    }
    icmp_packet->hdr.checksum = calculate_checksum(icmp_packet);
}

int icmp_send(int socket_fd, struct sockaddr_in * address, const void * data, size_t size)
{
    return sendto(socket_fd, data, size, 0, (struct sockaddr *)address, sizeof(*address));
}

int icmp_receive(int socket_fd, char * buffer, int buffer_size)
{
    return recvfrom(socket_fd, buffer, buffer_size, 0, NULL, NULL);
}

// when sending icmp ping packets using raw sockets verifing the echo.id is required
// otherwise you maybe looking at unrelated ping replys
bool verify_reply(const struct ping_pkt * sent, const struct ping_pkt * received, int expected_id)
{
    if (received->hdr.type != ICMP_ECHOREPLY)
    {
        return false;
    }
    if (received->hdr.code != 0)
    {
        return false;
    }
    if (received->hdr.un.echo.id != expected_id)
    {
        return false;
    }
    if (memcmp(&sent->payload[0], &received->payload[0], ICMP_PAYLOAD_LENGTH) != 0)
    {
        return false;
    }
    return true;
}

double get_difference_ms(const struct timespec * t1, const struct timespec * t2)
{
    double ns = (t2->tv_nsec - t1->tv_nsec) / 1000000.0;
    double ms = (t2->tv_sec - t1->tv_sec) * 1000.0;
    return ms + ns;
}

int icmp_ping(const char * address, int timeout_ms, double * duration_ms)
{
    struct sockaddr_in sock_addr;
    zero_inititialize(&sock_addr, sizeof(sock_addr));
    const char * name = dns_lookup_and_store_address(address, &sock_addr);
    if (name == NULL)
    {
        return -1;
    }
    int socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (socket_fd < 0)
    {
        printf("descriptor for icmp_socket to '%s' could not be created. (requires root)\n", address);
        return -1;
    }

    if (set_ttl(socket_fd, 64) != 0)
    {
        printf("ttl for icmp_socket to '%s' could not be set.\n");
        close(socket_fd);
        return -1;
    }
    if (set_receive_timeout(socket_fd, timeout_ms) != 0)
    {
        printf("timeout for icmp_socket to '%s' could not be set.\n");
        close(socket_fd);
        return -1;
    }

    const uint16_t my_icmp_id = getpid();
    const int ip_header_length = 20;
    const int raw_icmp_response_length = ip_header_length + sizeof(struct ping_pkt);

    struct ping_pkt packet;
    initialize_icmp_packet(&packet);

    // printf("  send %d bytes with id %d.\n", sizeof(packet), packet.hdr.un.echo.id);
    // printf("  %s\n", to_hex_string(&packet, sizeof(packet)));

    struct timespec start_timestamp;
    struct timespec stop_timestamp;
    clock_gettime(CLOCK_MONOTONIC, &start_timestamp);

    icmp_send(socket_fd, &sock_addr, &packet, sizeof(packet));

    bool done = false;
    while (!done)
    {
        char buffer[1024];
        int data_received = icmp_receive(socket_fd, &buffer[0], raw_icmp_response_length);

        // if (data_received > 0)
        // {
        //     printf("R: %s\n", to_hex_string(&buffer, data_received));
        // }
        clock_gettime(CLOCK_MONOTONIC, &stop_timestamp);
        *duration_ms = get_difference_ms(&start_timestamp, &stop_timestamp);
        if (*duration_ms > timeout_ms)
        {
            done = true;
        }
        if (data_received == raw_icmp_response_length)
        {
            const struct ping_pkt * data = (const struct ping_pkt *)&buffer[ip_header_length];
            if (verify_reply(&packet, data, my_icmp_id))
            {
                close(socket_fd);
                return 1;
            }
            printf("  warning unrelated message received of %d bytes with id %d.\n", data_received, data->hdr.un.echo.id);
            continue;
        }
        if (data_received > 0)
        {
            printf("  warning unrelated message received of %d bytes.\n", data_received);
        }
    }
    close(socket_fd);
    return -2;
}

int main(int argc, char * argv[])
{
    if (argc < 2)
    {
        printf("usage: ping_test <host>\n\n");
        return -1;
    }

    const char * host = argv[1];
    const char * address = dns_lookup_and_store_address(host, NULL);

    char name[1024];
    zero_inititialize(&name[0], sizeof(name));
    reverse_dns_lookup(address, name, sizeof(name));
    printf("PING %s. (%s)\n", address, name);

    int status_code = 0;
    const int timeout_ms = 2500;
    for (int i = 0; i < 4; ++i)
    {
        double duration = 0.0;
        int result = icmp_ping(host, timeout_ms, &duration);
        if (result == -2)
        {
            printf("ping from %s timed out, no response after %dms.\n", address, timeout_ms);
            status_code = -2;
            continue;
        }
        if (result > 0)
        {
            printf("ping from %s: time=%.2fms.\n", address, duration);
        }
    }
    return status_code;
}
