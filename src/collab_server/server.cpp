#include "collab_server/server.hpp"

#include <iostream>
#include <thread>
#include <fstream>
#include <sstream>
#include <arpa/inet.h>
#include <filesystem>

// todo: remove logs

CollabServer::~CollabServer() {
    close(_server_fd);
}

CollabServer::statusRes CollabServer::connect_to_peer(const std::string& ip, int port) {
    int peer_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (peer_fd < 0)
        return { false, "Error: Failed to create client socket" };

    sockaddr_in peer_addr;
    peer_addr.sin_family = AF_INET;
    peer_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &peer_addr.sin_addr);

    if (connect(peer_fd, (struct sockaddr *) &peer_addr, sizeof(peer_addr)) < 0)
        return { false, "Error: Failed to connect to peer" };

    std::lock_guard<std::mutex> lock(_peers_mutex);
    _peers.push_back(peer_fd);

    std::thread handle_peer_thread([this, peer_fd]() {
        this->handle_peer(peer_fd);
    });
    handle_peer_thread.detach();

    _is_online = true;
    return { true, "Successfully connected to" + ip + ":" + std::to_string(port) };
}

void CollabServer::send_file_to_peers(std::string file_path) {
    std::ifstream text(file_path);
    std::stringstream buffer;

    buffer << "DaicFile " << file_path << '\n' << text.rdbuf();
    std::string str = buffer.str();

    send_message_to_peers(str, _server_fd);
}

void CollabServer::send_message_to_peers(const std::string &message, int sender_peer_fd) {
    std::lock_guard<std::mutex> lock(_peers_mutex);
    std::cout << "Sending to " << _peers.size() << " peers" << std::endl;

    for (auto peer_fd : _peers) {
        if (peer_fd != sender_peer_fd) {
            std::cout << "Sending to peer " << peer_fd << std::endl;
            send(peer_fd, message.c_str(), message.size(), 0);
        }
    }
}

void CollabServer::handle_peer(int peer_fd) {
    std::vector<char> buffer(512000); // temp
    std::cout << "Peer connected: " << peer_fd << std::endl;

    _is_online = true;
    while (true) {
        std::fill(buffer.begin(), buffer.end(), 0);
        int bytes_received = recv(peer_fd, buffer.data(), buffer.size(), 0);

        if (bytes_received < 1) {
            std::cout << "Peer disconnected: " << peer_fd << "\n";
            std::lock_guard<std::mutex> lock(_peers_mutex);
            close(peer_fd);
            break;
        }
        std::string message(buffer.data(), bytes_received);

        if (message.starts_with("DaicFile")) {
            std::string first_line = message.substr(0, message.find("\n"));
            std::string file_name = first_line.substr(first_line.find_last_of("/") + 1);
            std::string file_content = message.substr(first_line.size() + 1);

            std::cout << "Received file: " << file_name << std::endl;

            const std::filesystem::path tmp_dir_path = std::filesystem::temp_directory_path() / "DaiC";
            const std::filesystem::path file_tmp_path = tmp_dir_path / file_name;

            std::filesystem::create_directory(tmp_dir_path);
            std::fstream s {file_tmp_path, s.binary | s.trunc | s.in | s.out};
            s.write(file_content.c_str(), file_content.size());
            s.seekp(0);
        }
    }
}

void CollabServer::check_peers_connection() {
    while (true) {
        sockaddr_in peer_addr;
        socklen_t peer_len = sizeof(peer_addr);
        int peer_fd = accept(_server_fd, (struct sockaddr *) &peer_addr, &peer_len);

        std::lock_guard<std::mutex> lock(_peers_mutex);
        _peers.push_back(peer_fd);

        std::thread handle_peer_thread([this, peer_fd]() {
            this->handle_peer(peer_fd);
        });
        handle_peer_thread.detach();
    }
}

CollabServer::statusRes CollabServer::start_server(int port) {
    _server_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (_server_fd < 0)
        return { false, "Error: Failed to create server socket" };

    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(_server_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0)
        return { false, "Error: Failed to bind server socket" };

    if (listen(_server_fd, 5) < 0)
        return { false, "Error: Failed to listen on server socket" };

    return { true, "Success: Server created" };
}

CollabServer::statusRes CollabServer::startServerThread(int port) {
    statusRes status = start_server(port);

    if (!status.code)
        return status;

    std::thread server_thread([this]() {
        this->check_peers_connection();
    });
    server_thread.detach();

    return status;
}
