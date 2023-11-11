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
#include <filesystem>
#include <fmt/chrono.h>
#include <fmt/core.h>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

std::string dns_lookup(const std::string & hostname)
{
    auto * host_entity = gethostbyname(hostname.data());
    if (host_entity == nullptr)
    {
        // no ipaddress found for hostname
        return {};
    }
    auto addr = *reinterpret_cast<in_addr *>(host_entity->h_addr_list[0]);
    return inet_ntoa(addr);
}

std::string reverse_dns_lookup(const std::string & ipaddress)
{
    sockaddr_in address = {};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr(ipaddress.data());

    char buffer[NI_MAXHOST];
    auto result = getnameinfo(reinterpret_cast<sockaddr *>(&address), sizeof(sockaddr_in), buffer, sizeof(buffer), nullptr, 0, NI_NAMEREQD);
    if (result != 0)
    {
        // could not resolve reverse lookup hostname
        return {};
    }
    return buffer;
}

std::vector<std::string> get_physical_networkcard_names()
{
    namespace fs = std::filesystem;

    std::vector<std::string> result;
    for (const auto & entry : fs::directory_iterator("/sys/class/net/"))
    {
        auto path = entry.path();
        if (fs::exists(path / "device/vendor"))
        {
            result.push_back(path.stem());
        }
    }
    return result;
}