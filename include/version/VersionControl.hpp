#pragma once

#include <string>
#include <set>
#include <filesystem>

class VCS {
   public:
    VCS(const std::string project_path)
        : _version_path(std::filesystem::path(project_path) / ".daic"),
          _staging_path(_version_path / "staging"),
          _commit_path(_version_path / "commits")
    {
        if (isFileTracked()) {
            return;
        } else {
            init();
        }
        _db_path = std::filesystem::path(project_path) / "1.db";
        _commits = sort_commit_folders();
    };
    ~VCS() {};

    void add();
    void commit(const std::string);
    std::set<std::filesystem::path> _commits;

    class CommitInfo {
       public:
        CommitInfo(const std::string commit_path)
            : _commit_path(commit_path) {};
        ~CommitInfo() {};

        void serialize_commit(const std::string commit_path, const std::string commit_msg);
        void deserialize_commit(const std::string commit_path);
       private:
        std::string _commit_path;
        std::string _commit_msg;
        std::string _commit_time;
        int _commit_number;
    };

   private:
    std::filesystem::path _version_path;;
    std::filesystem::path _staging_path;
    std::filesystem::path _commit_path;
    std::filesystem::path _db_path;

    void init();
    bool isFileTracked();
    std::set<std::filesystem::path> sort_commit_folders();
};
