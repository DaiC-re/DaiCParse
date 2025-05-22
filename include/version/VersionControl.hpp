#pragma once

#include <string>
#include <set>
#include <filesystem>
#include <iostream>

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

        void serialize_commit(const std::string commit_path, const std::string commit_msg);
        void deserialize_commit(const std::string commit_path);
       private:
        std::string _commit_path;
        std::string _commit_msg;
        std::string _commit_time;
        int _commit_number;
    };

    struct CommitComparator {
        bool operator()(const std::pair<std::filesystem::path, CommitInfo>& lhs, const  std::pair<std::filesystem::path, CommitInfo>& rhs) const {
            return lhs.first.string() < rhs.first.string();
        }
    };

    VCS(const std::string project_path)
        : _version_path(std::filesystem::path(project_path) / ".daic"),
          _staging_path(_version_path / "staging"),
          _commit_path(_version_path / "commits")
    {
        if (isFileTracked()) {
            std::cout << "Version control system found";
        } else {
            init();
        }
        _db_path = std::filesystem::path(project_path) / "1.db";
        _commits = sort_commit_folders();
    };
    ~VCS() {};

    void add();
    void commit(const std::string);
    std::set<std::pair<std::filesystem::path, CommitInfo>, CommitComparator> _commits;


   private:
    std::filesystem::path _version_path;;
    std::filesystem::path _staging_path;
    std::filesystem::path _commit_path;
    std::filesystem::path _db_path;

    void init();
    bool isFileTracked();
    std::set<std::pair<std::filesystem::path, CommitInfo>, CommitComparator> sort_commit_folders();
};
