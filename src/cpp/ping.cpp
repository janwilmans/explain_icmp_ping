/*
 * Copyright (c) 2023 Jan Wilmans, MIT License
 */

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <fmt/chrono.h>
#include <fmt/core.h>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

#include "network.h"

using double_milliseconds = std::chrono::duration<double, std::milli>;

std::string to_hex_string(std::string_view data)
{
    std::string result;
    for (auto c : data)
    {
        result += fmt::format("{0:02X} ", c);
    }

    result += ';';
    for (auto c : data)
    {
        if (c < 32)
        {
            result += '.';
            continue;
        }
        result += c;
    }
    return result;
}

namespace icmp_ns {
// you can choose to send more or less dummy payload data
static const int icmp_payload_length = 64 - sizeof(struct icmphdr);
struct ping_pkt
{
    struct icmphdr hdr;
    char payload[icmp_payload_length];
};

[[nodiscard]] unsigned short calculate_checksum(const ping_pkt & packet)
{
    auto * view = reinterpret_cast<const unsigned short *>(&packet);
    auto size = sizeof(ping_pkt);

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
class icmp_socket
{
public:
    explicit icmp_socket(std::string address) :
        m_address(address)
    {
        dns_lookup_and_store_address();
        m_socket_fd = ::socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (m_socket_fd < 0)
        {
            throw std::runtime_error(fmt::format("descriptor for icmp_socket to '{}' could not be "
                                                 "created. (requires root)",
                                                 m_address));
        }
    }

    ~icmp_socket()
    {
        ::close(m_socket_fd);
    }

    void dns_lookup_and_store_address()
    {
        const uint16_t port = 0;
        hostent * host_entity = gethostbyname(m_address.data());
        if (host_entity == NULL)
        {
            throw std::runtime_error(fmt::format("gethostbyname for '{}' failed.", m_address));
        }
        m_name = inet_ntoa(*(struct in_addr *)host_entity->h_addr);

        m_sockaddr_in.sin_family = host_entity->h_addrtype;
        m_sockaddr_in.sin_port = htons(port);
        m_sockaddr_in.sin_addr.s_addr = *(long *)host_entity->h_addr;
    }

    template <typename T>
    bool set_socket_option(int level, int option, const T value)
    {
        return setsockopt(m_socket_fd, level, option, &value, sizeof(value)) == 0;
    }

    void set_TTL(const int ttl)
    {
        if (!set_socket_option(SOL_IP, IP_TTL, ttl))
        {
            throw std::runtime_error(fmt::format("could not set TTL to '{}'", ttl));
        }
    }

    void set_receive_timeout(std::chrono::milliseconds timeout)
    {
        int total_ms = timeout.count();
        int seconds = total_ms / 1000;
        int useconds = (total_ms - (seconds * 1000)) * 1000;
        timeval tv_out{};
        tv_out.tv_sec = seconds;
        tv_out.tv_usec = useconds;
        if (!set_socket_option(SOL_SOCKET, SO_RCVTIMEO, tv_out))
        {
            throw std::runtime_error(fmt::format("could not set receive timeout to '{}'ms", total_ms));
        }
    }

    [[nodiscard]] std::vector<char> receive(size_t bytes)
    {
        m_receive_buffer.resize(bytes);
        auto bytes_received = recvfrom(m_socket_fd, &m_receive_buffer[0], m_receive_buffer.size(), 0, nullptr, nullptr);
        if (bytes_received <= 0)
        {
            return {}; // return empty meaning, we received no reply within the timeout
        }
        m_receive_buffer.resize(bytes_received);
        return m_receive_buffer;
    }

    void send(const void * data, size_t size) const
    {
        auto result = ::sendto(m_socket_fd, data, size, 0, (sockaddr *)&m_sockaddr_in, sizeof(m_sockaddr_in));
        if (result <= 0)
        {
            throw std::runtime_error(fmt::format("could not send packet to '{}'", m_address));
        }
    }

    template <typename T>
    [[nodiscard]] T get_received_data(size_t offset) const
    {
        T result;
        std::memcpy(&result, &m_receive_buffer[offset], sizeof(T));
        return result;
    }

    template <typename T>
    void send_object(const T & object) const
    {
        send(&object, sizeof(object));
    }

    [[nodiscard]] int get_fd() const { return m_socket_fd; }
    [[nodiscard]] std::string get_name() const { return m_name; }
    [[nodiscard]] sockaddr_in get_sockadd_in() const { return m_sockaddr_in; }

    sockaddr_in m_sockaddr_in{};
    int m_socket_fd;
    std::string m_address;
    std::string m_name;
    std::vector<char> m_receive_buffer;
};

[[nodiscard]] ping_pkt make_icmp_packet()
{
    ping_pkt icmp_packet = {};
    icmp_packet.hdr.type = ICMP_ECHO;
    icmp_packet.hdr.un.echo.id = getpid();
    icmp_packet.hdr.un.echo.sequence = 0;

    // the payload is arbitrary, it can be any data but it is good practice to send some recognizable string.
    // its important to make sure to calculate the checksum _after_ filling the payload.
    for (size_t i = 0; i < icmp_payload_length; ++i)
    {
        icmp_packet.payload[i] = static_cast<char>('0' + i);
    }
    icmp_packet.hdr.checksum = calculate_checksum(icmp_packet);
    return icmp_packet;
}

// when sending icmp ping packets using raw sockets verifing the echo.id is
// required otherwise you maybe looking at unrelated ping replys
[[nodiscard]] bool verify_reply(const ping_pkt & sent, const ping_pkt & received, int expected_id)
{
    if (received.hdr.type != ICMP_ECHOREPLY)
    {
        return false;
    }
    if (received.hdr.code != 0)
    {
        return false;
    }
    if (received.hdr.un.echo.id != expected_id)
    {
        return false;
    }
    if (memcmp(&sent.payload[0], &received.payload[0], icmp_payload_length) != 0)
    {
        return false;
    }
    return true;
}

[[nodiscard]] std::optional<double_milliseconds> ping(const std::string & address, std::chrono::milliseconds timeout)
{
    auto deadline = std::chrono::steady_clock::now() + timeout;
    icmp_socket socket(address);
    socket.set_TTL(64);
    socket.set_receive_timeout(timeout);
    const uint16_t my_icmp_id = getpid();
    const int ip_header_length = 20;
    const int raw_icmp_response_length = ip_header_length + sizeof(ping_pkt);

    auto packet = make_icmp_packet();
    // fmt::print("  send {} bytes with id {}.\n", sizeof(packet),
    // packet.hdr.un.echo.id); fmt::print("  {}\n", vic::to_hex_string(&packet, 1));
    auto start_timepoint = std::chrono::steady_clock::now();
    socket.send_object(packet);

    while (std::chrono::steady_clock::now() < deadline)
    {
        auto data_received = socket.receive(raw_icmp_response_length);
        auto end_timepoint = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<double_milliseconds>(
            end_timepoint - start_timepoint);

        if (data_received.size() == raw_icmp_response_length)
        {
            auto data = socket.get_received_data<ping_pkt>(ip_header_length);
            if (verify_reply(packet, data, my_icmp_id))
            {
                return duration;
            }
            fmt::print("  warning unrelated message received of {} bytes with id {}.\n", data_received.size(), data.hdr.un.echo.id);
            continue;
        }
        fmt::print("  warning unrelated message received of {} bytes.\n", data_received.size());
    }

    return {}; // timeout, no response received
}

} // namespace icmp_ns

int main(int argc, char * argv[])
{
    using namespace std::chrono_literals;
    if (argc < 2)
    {
        fmt::print("usage: ping_test <address>\n\n");
        return -1;
    }

    auto address = dns_lookup(argv[1]);
    fmt::print("PING {} ({}).\n", address, reverse_dns_lookup(address));

    const auto timeout = 2500ms;
    for (int i = 0; i < 4; ++i)
    {
        auto duration = icmp_ns::ping(address, timeout);
        if (duration)
        {
            fmt::print("ping from {}: time={:.2f}ms.\n", address, duration->count());
        }
        else
        {
            fmt::print("ping from {} timed out, no response after {}.\n", address, timeout);
        }
    }
}
