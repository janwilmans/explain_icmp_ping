/*
 * Copyright (c) 2023 Jan Wilmans, MIT License
 */

#include <string>
#include <vector>

std::string dns_lookup(const std::string & hostname);
std::string reverse_dns_lookup(const std::string & ipaddress);
std::vector<std::string> get_physical_networkcard_names();