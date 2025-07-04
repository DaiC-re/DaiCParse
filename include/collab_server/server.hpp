#pragma once

#include <string>
#include <vector>
#include <mutex>

class CollabServer
{
    public:
        struct statusRes {
            bool code;
            std::string message;
        };

        CollabServer() {}
        ~CollabServer();
        statusRes startServerThread(int port);
        statusRes connect_to_peer(const std::string& ip, int port);
        void send_file_to_peers(std::string file_path, std::string project_name);
        bool get_is_online() {
            return _is_online;
        }
        int get_server_fd() {
            return _server_fd;
        }

    private:
        void send_message_to_peers(const std::string& message, int sender_fd);
        void handle_peer(int peer_fd);
        void check_peers_connection();
        statusRes start_server(int port);
        std::vector<int> _peers;
        std::mutex _peers_mutex;
        int _server_fd;
        bool _is_online;
};
