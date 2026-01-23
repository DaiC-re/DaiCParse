#include <filesystem>
#include <iostream>
#include <fstream>
#include "version/VersionControl.hpp"

void VCS::init(std::vector<Binary::Function> list)
{
    std::cout << "no versions found, initializing version control\n";
    try {
        std::filesystem::create_directory(_version_path);
        std::filesystem::create_directory(_staging_path);
        std::filesystem::create_directory(_commit_path);
        std::filesystem::create_directory(_current_path);
    } catch (const std::filesystem::filesystem_error& e) {
        std::cerr << "Error creating directories: " << e.what() << std::endl;
    }
}

void VCS::copy_current_db()
{
    std::filesystem::copy_file(_db_path, _current_path / "1.db",
            std::filesystem::copy_options::overwrite_existing);
}

void VCS::copy_last_commit_db()
{
    if (!_commits.empty()) {
        auto lcommit = _commits.begin();
        Commit *last_commit = *lcommit;
        std::filesystem::copy_file(last_commit->_path / "1.db", _current_path / "1.db");
    }
}

bool VCS::isFileTracked()
{
    std::cout << "tracking files\n";
    return std::filesystem::exists(_version_path) &&
           std::filesystem::exists(_current_path) &&
           std::filesystem::exists(_staging_path) &&
           std::filesystem::exists(_commit_path);;
}

std::set<VCS::Commit *> VCS::sort_commit_folders()
{
    std::set<VCS::Commit*> commit_folders;
    for (const auto& entry : std::filesystem::directory_iterator(_commit_path)) {
        if (!std::filesystem::is_directory(entry.path())) {
            continue;
        }
        Commit *commit = new Commit(entry.path().string());
        commit_folders.insert(commit);
    }
    return commit_folders;
}

void VCS::add(std::vector<Binary::Function> renamed_func_list)
{
    std::cout << "Adding changes to Staging in " << _staging_path.string() << std::endl;

    if (_staging == nullptr) {
        std::filesystem::path new_commit_path = _staging_path / "commit_0";
        std::filesystem::create_directory(new_commit_path);
        _staging = new Commit(new_commit_path);
        _staging->set_fn_list(renamed_func_list);
        _staging->serialize_commit(new_commit_path.string(), "");
        return;
    }
    _staging->set_fn_list(renamed_func_list);
    _staging->serialize_commit(_staging->_path.string(), "");
}

void VCS::commit(const std::string commit_msg)
{
    if (_staging && !_commits.empty()) {
        auto rit = _commits.rbegin();
        Commit *last_commit = *rit;
        int last_commit_id = last_commit->_info->get_commit_number();
        std::filesystem::path new_commit_path = _commit_path / ("commit_" + std::to_string(last_commit_id + 1));
        std::filesystem::create_directory(new_commit_path);
        Commit *commit = new Commit(new_commit_path, _staging, last_commit_id + 1);
        commit->serialize_commit(commit->_path.string(), commit_msg);
        _commits.insert(commit);
    } else {
        std::filesystem::path new_commit_path = _commit_path / ("commit_1");
        std::filesystem::create_directory(new_commit_path);
        Commit *commit = new Commit(new_commit_path, _staging, 1);
        commit->serialize_commit(commit->_path.string(), commit_msg);
        _commits.insert(commit);
    }
    _staging->_fn.clear();
}

void VCS::CommitInfo::serialize_commit(const std::string commit_path, const std::string commit_msg, std::ostream &out)
{
    _commit_msg = commit_msg;
    _commit_time = std::to_string(std::time(nullptr));
    _commit_number = std::stoi(commit_path.substr(commit_path.find_last_of("_") + 1));

    out.write(reinterpret_cast<const char*>(&_commit_number), sizeof(_commit_number));

    uint32_t msgSize = _commit_msg.size();
    out.write(reinterpret_cast<const char*>(&msgSize), sizeof(msgSize));
    out.write(_commit_msg.data(), msgSize);

    uint32_t timeSize = _commit_time.size();
    out.write(reinterpret_cast<const char*>(&timeSize), sizeof(timeSize));
    out.write(_commit_time.data(), timeSize);
}

void VCS::CommitInfo::deserialize_commit(const std::string commit_path, std::istream &in)
{
    in.read(reinterpret_cast<char*>(&_commit_number), sizeof(_commit_number));

    uint32_t msgSize;
    in.read(reinterpret_cast<char*>(&msgSize), sizeof(msgSize));
    _commit_msg.resize(msgSize);
    in.read(_commit_msg.data(), msgSize);

    uint32_t timeSize;
    in.read(reinterpret_cast<char*>(&timeSize), sizeof(timeSize));
    _commit_time.resize(timeSize);
    in.read(_commit_time.data(), timeSize);
}

void VCS::Commit::serialize_commit(const std::string commit_path, const std::string commit_msg)
{
    std::filesystem::path commit_file = std::filesystem::path(commit_path) / "commit_info.info";
    std::ofstream out(commit_file.string(), std::ios::binary);
    this->_info->serialize_commit(commit_path, commit_msg, out);

    uint32_t fnSize = _fn.size();
    out.write(reinterpret_cast<const char*>(&fnSize), sizeof(fnSize));
    for (auto &fn: this->_fn) {
        out.write(reinterpret_cast<const char*>(&fn.function_id), sizeof(fn.function_id));

        uint32_t fnNameSize = fn.new_name.size();
        out.write(reinterpret_cast<const char*>(&fnNameSize), sizeof(fnNameSize));
        out.write(fn.new_name.data(), fnNameSize);
    }
    out.close();
}

void VCS::Commit::deserialize_commit(const std::string commit_path)
{
    std::filesystem::path commit_file = std::filesystem::path(commit_path) / "commit_info.info";
    std::ifstream in(commit_file.string(), std::ios::binary);
    this->_info->deserialize_commit(commit_path, in);
    uint32_t fnSize;
    in.read(reinterpret_cast<char*>(&fnSize), sizeof(fnSize));
    for (uint32_t i = 0; i < fnSize; i++) {
        renamedFn fn;
        in.read(reinterpret_cast<char*>(&fn.function_id), sizeof(fn.function_id));

        uint32_t fnNameSize;
        in.read(reinterpret_cast<char*>(&fnNameSize), sizeof(fnNameSize));

        fn.new_name.resize(fnNameSize);
        in.read(fn.new_name.data(), fnNameSize);
        _fn.push_back(fn);
    }

    in.close();
}
