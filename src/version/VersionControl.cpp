#include <filesystem>
#include <iostream>
#include <fstream>
#include "version/VersionControl.hpp"

void VCS::init()
{
    std::cout << "no versions found, initializing version control";
    try {
        std::filesystem::create_directory(_version_path);
        std::filesystem::create_directory(_staging_path);
        std::filesystem::create_directory(_commit_path);
    } catch (const std::filesystem::filesystem_error& e) {
        std::cerr << "Error creating directories: " << e.what() << std::endl;
    }
}

bool VCS::isFileTracked()
{
    return std::filesystem::exists(_version_path) &&
           std::filesystem::exists(_staging_path) &&
           std::filesystem::exists(_commit_path);;
}

std::set<std::pair<std::filesystem::path, VCS::CommitInfo>, VCS::CommitComparator> VCS::sort_commit_folders()
{
    std::set<std::pair<std::filesystem::path, VCS::CommitInfo>, VCS::CommitComparator> commit_folders;
    for (const auto& entry : std::filesystem::directory_iterator(_commit_path)) {
        if (!std::filesystem::is_directory(entry.path())) {
            continue;
        }
        CommitInfo info(entry.path().string());
        commit_folders.insert({entry.path(), info});
    }
    return commit_folders;
}

void VCS::add()
{
    std::cout << "Adding changes to Staging in " << _staging_path.string();
    std::filesystem::copy_file(_db_path, _staging_path / "1.db", std::filesystem::copy_options::overwrite_existing);
}

void VCS::commit(const std::string commit_msg)
{
    if (_commits.empty()) {
        std::filesystem::path new_commit_path = _commit_path / "commit_0";
        std::filesystem::create_directory(new_commit_path);
        std::filesystem::copy_file(_staging_path / "1.db", new_commit_path / "1.db");
        CommitInfo info(new_commit_path.string());
        info.serialize_commit(new_commit_path.string(), commit_msg);
        _commits.insert({new_commit_path, info});
        return;
    }
    std::string last_commit_str= _commits.rbegin()->first.string();
    int last_commit = std::stoi(last_commit_str.substr(last_commit_str.find_last_of("_") + 1));
    std::filesystem::path new_commit_path = _commit_path / ("commit_" + std::to_string(last_commit + 1));
    std::filesystem::create_directory(new_commit_path);
    std::filesystem::copy_file(_staging_path / "1.db", new_commit_path / "1.db");
    CommitInfo info(new_commit_path.string());
    info.serialize_commit(new_commit_path.string(), commit_msg);
    _commits.insert({new_commit_path, info});
}

void VCS::CommitInfo::serialize_commit(const std::string commit_path, const std::string commit_msg)
{
    _commit_msg = commit_msg;
    _commit_time = std::to_string(std::time(nullptr));
    _commit_number = std::stoi(commit_path.substr(commit_path.find_last_of("_") + 1));

    std::filesystem::path commit_file = std::filesystem::path(commit_path) / "commit_info.info";
    std::ofstream out(commit_file.string(), std::ios::binary);

    out.write(reinterpret_cast<const char*>(&_commit_number), sizeof(_commit_number));

    uint32_t msgSize = _commit_msg.size();
    out.write(reinterpret_cast<const char*>(&msgSize), sizeof(msgSize));
    out.write(_commit_msg.data(), msgSize);

    uint32_t timeSize = _commit_time.size();
    out.write(reinterpret_cast<const char*>(&timeSize), sizeof(timeSize));
    out.write(_commit_time.data(), timeSize);
    out.close();
}

void VCS::CommitInfo::deserialize_commit(const std::string commit_path)
{
    std::filesystem::path commit_file = std::filesystem::path(commit_path) / "commit_info.info";
    std::ifstream in(commit_file.string(), std::ios::binary);

    in.read(reinterpret_cast<char*>(&_commit_number), sizeof(_commit_number));

    uint32_t msgSize;
    in.read(reinterpret_cast<char*>(&msgSize), sizeof(msgSize));
    _commit_msg.resize(msgSize);
    in.read(_commit_msg.data(), msgSize);

    uint32_t timeSize;
    in.read(reinterpret_cast<char*>(&timeSize), sizeof(timeSize));
    _commit_time.resize(timeSize);
    in.read(_commit_time.data(), timeSize);
    in.close();
}
