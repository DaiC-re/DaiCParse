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
        CommitInfo(const std::filesystem::path path, int id)
            : _commit_path(path.string()) {
            _commit_number = id;
        };
        CommitInfo(const std::string commit_path)
            : _commit_path(commit_path) {};
        ~CommitInfo() {};

        std::string get_commit_path() const { return _commit_path; };
        std::string get_commit_msg() const { return _commit_msg; };
        std::string get_commit_time() const { return _commit_time; };
        int get_commit_number() const { return _commit_number;};

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
        Commit(std::filesystem::path path): _path(path) {
            _info = new CommitInfo(_path.string());
        }
        Commit(const std::string staging_path): _path(staging_path){
            _info = new CommitInfo(_path.string());
        }
        Commit(std::filesystem::path path, Commit *staging, int id): _path(path) {
            _info = new CommitInfo(_path.string(), id);
            _fn = staging->_fn;
        }
        ~Commit() { delete _info;};
        std::filesystem::path _path;
        CommitInfo *_info;

        std::vector<renamedFn> _fn;

        void set_fn_list(std::vector<Binary::Function> renamed_list) {
            for (auto &func: renamed_list) {
                renamedFn fn;
                fn.function_id = func.getId();
                fn.new_name = func.getName();
                _fn.push_back(fn);
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
            deserialize_commits();
        } else {
            init(list);
        }
        //_commits = sort_commit_folders();
    };
    ~VCS() {};

    void add(std::vector<Binary::Function>);
    void commit(const std::string);
    std::set<VCS::Commit*> _commits;
    VCS::Commit *_staging = nullptr;

    void deserialize_commits() {
        std::filesystem::path new_commit_path = _staging_path / "commit_0";
        _staging = new Commit(new_commit_path);
        _staging->deserialize_commit(_staging->_path.string());
        for (const auto &dir: std::filesystem::directory_iterator(_commit_path)) {
            VCS::Commit *commit = new VCS::Commit(dir.path());
            commit->deserialize_commit(commit->_path.string());
            _commits.insert(commit);
        }
    }

    VCS::Commit *get_staging_commit() {
        for (auto &commit: _commits) {
            if (commit->_info->get_commit_number() == 0)
                return commit;
        }
        return nullptr;
    }

    std::filesystem::path getCurrentPath() { return _current_path;};

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
