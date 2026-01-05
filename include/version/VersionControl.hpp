#pragma once

#include <string>
#include <set>
#include <filesystem>
#include <fstream>
#include <iostream>
#include "binary/binary.hpp"

class VCS {
   public:
    class CommitInfo {
       public:
        CommitInfo(const std::string commit_path)
            : _commit_path(commit_path) {};
        ~CommitInfo() {};

        std::string get_commit_path() const { return _commit_path; };
        std::string get_commit_msg() const { return _commit_msg; };
        std::string get_commit_time() const { return _commit_time; };

        void serialize_commit(const std::string commit_path, const std::string commit_msg, std::ostream &o);
        void deserialize_commit(const std::string commit_path, std::istream &i);
       private:
        std::string _commit_path;
        std::string _commit_msg;
        std::string _commit_time;
        int _commit_number;
    };

    struct renamedFn {
        size_t function_id;
        std::string new_name;
    };

    class Commit {
       public:
        Commit(std::filesystem::path path): _info(path.string()) {
            _path = path;
        };
        Commit(const std::string staging_path): _info(staging_path){
            _path = staging_path;

        }
        ~Commit() {};
        std::filesystem::path _path;
        CommitInfo _info;

        std::vector<renamedFn> _fn;

        enum Status {
            STAGING = 0,
            COMMITTED = 1
        };

        Status status = STAGING;

        void set_fn_list(std::vector<Binary::Function> renamed_list) {
            for (auto &func: renamed_list) {
                renamedFn fn;
            }

        }
        void serialize_commit(const std::string commit_path, const std::string commit_msg);
        void deserialize_commit(const std::string commit_path);
    };

    struct CommitComparator {
        bool operator()(const VCS::Commit & lhs, const VCS::Commit & rhs) const {
            return lhs._path.string() < rhs._path.string();
        }
    };

    VCS(const std::string project_path, std::vector<Binary::Function> list)
        : _version_path(std::filesystem::path(project_path) / ".daic"),
          _staging_path(_version_path / "staging"),
          _commit_path(_version_path / "commits"),
          _current_path(_version_path / "current")
    {
        _db_path = std::filesystem::path(project_path) / "1.db";
        if (isFileTracked()) {
            std::cout << "Version control system found\n";
        } else {
            init(list);
        }
        _commits = sort_commit_folders();
    };
    ~VCS() {};

    void add(std::vector<Binary::Function>);
    void commit(const std::string);
    std::set<VCS::Commit*> _commits;

    std::filesystem::path getCurrentPath() { return _current_path;};
    void serializeCurrentList(std::vector<Binary::Function> list) {
        std::ofstream out(std::format("{}/functions.db", _current_path.string(), std::ios::binary));
        if (!out)
            throw std::runtime_error("Failed to open file for writing");
        size_t func_size = list.size();
        out.write(reinterpret_cast<const char*>(&func_size), sizeof(func_size));
        for (auto &func: list) {
            func.serialize(out);
        }
    }
    std::vector<Binary::Function> deserializeCurrentList() {
        std::ifstream in(std::format("{}/functions.db", _current_path.string()), std::ios::binary);
        std::vector<Binary::Function> list;
        if (!in) {
            return list;
        }
        size_t func_size;
        in.read(reinterpret_cast<char*>(&func_size), sizeof(func_size));
        for (size_t i = 0; i != func_size; i++) {
            Binary::Function func;
            func.deserialize(in);
            list.push_back(func);
        }
        return list;
    }

   private:
    std::filesystem::path _version_path;;
    std::filesystem::path _staging_path;
    std::filesystem::path _commit_path;
    std::filesystem::path _current_path;
    std::filesystem::path _db_path;

    void init(std::vector<Binary::Function>);
    bool isFileTracked();
    void copy_current_db();
    void copy_last_commit_db();
    std::set<VCS::Commit*> sort_commit_folders();
};
