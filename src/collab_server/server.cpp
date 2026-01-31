#include "collab_server/server.hpp"

#include <iostream>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <QHostAddress>
#include <QByteArray>

CollabServer::CollabServer(QObject* parent)
    : QObject(parent), _server(nullptr), _is_online(false)
{
}

CollabServer::~CollabServer() {
    std::lock_guard<std::mutex> lock(_peers_mutex);
    for (auto& peer : _peers) {
        if (peer && peer->state() == QTcpSocket::ConnectedState) {
            peer->disconnectFromHost();
        }
    }
    if (_server) {
        _server->close();
    }
}

CollabServer::statusRes CollabServer::connect_to_peer(const std::string& ip, int port) {
    auto peer_socket = std::make_unique<QTcpSocket>();

    connect(peer_socket.get(), &QTcpSocket::connected, this, &CollabServer::on_peer_connected);
    connect(peer_socket.get(), &QTcpSocket::disconnected, this, &CollabServer::on_peer_disconnected);
    connect(peer_socket.get(), &QTcpSocket::readyRead, this, &CollabServer::on_peer_ready_read);
    connect(peer_socket.get(), &QTcpSocket::errorOccurred, this, [this]() { on_peer_error(); });

    peer_socket->connectToHost(QString::fromStdString(ip), port);

    if (!peer_socket->waitForConnected(5000)) {
        return { false, "Error: Failed to connect to peer" };
    }

    {
        std::lock_guard<std::mutex> lock(_peers_mutex);
        _peers.push_back(std::move(peer_socket));
    }

    _is_online = true;
    return {true, "Successfully connected to " + ip + ":" + std::to_string(port)};
}

void CollabServer::send_file_to_peers(std::string file_path, std::string project_name) {
    std::ifstream text(file_path);
    std::stringstream buffer;
    size_t pos = file_path.find_last_of("/\\");
    std::string new_file_path = file_path.substr(0, pos + 1) + project_name + "_" + file_path.substr(pos + 1);

    buffer << "DaicFile " << new_file_path << '\n' << text.rdbuf();
    std::string str = buffer.str();

    send_message_to_peers(str, nullptr);
}

void CollabServer::send_message_to_peers(const std::string &message, QTcpSocket* sender_socket) {
    std::lock_guard<std::mutex> lock(_peers_mutex);
    std::cout << "Sending to " << _peers.size() << " peers" << std::endl;

    QByteArray data(message.c_str(), message.size());

    for (auto& peer : _peers) {
        if (peer && peer.get() != sender_socket && peer->state() == QTcpSocket::ConnectedState) {
            std::cout << "Sending to peer" << std::endl;
            peer->write(data);
            peer->flush();
        }
    }
}

void CollabServer::on_peer_connected() {
    std::cout << "Peer connected" << std::endl;
    _is_online = true;
}

void CollabServer::on_peer_disconnected() {
    std::cout << "Peer disconnected" << std::endl;
    std::lock_guard<std::mutex> lock(_peers_mutex);
    _peers.erase(
        std::remove_if(_peers.begin(), _peers.end(),
            [](const std::unique_ptr<QTcpSocket>& peer) {
                return !peer || peer->state() != QTcpSocket::ConnectedState;
            }),
        _peers.end()
    );

    if (_peers.empty()) {
        _is_online = false;
    }
}

void CollabServer::on_peer_ready_read() {
    QTcpSocket* peer_socket = qobject_cast<QTcpSocket*>(sender());
    if (!peer_socket) return;

    QByteArray data = peer_socket->readAll();
    std::string message(data.constData(), data.size());

    if (message.find("DaicFile") == 0) {
        std::string first_line = message.substr(0, message.find("\n"));
        std::string file_name = first_line.substr(first_line.find_last_of("/\\") + 1);
        std::string file_content = message.substr(first_line.size() + 1);

        std::cout << "Received file: " << file_name << std::endl;

        const std::filesystem::path tmp_dir_path = std::filesystem::temp_directory_path() / "DaiC";
        const std::filesystem::path file_tmp_path = tmp_dir_path / file_name;

        std::filesystem::create_directory(tmp_dir_path);
        std::fstream s {file_tmp_path, std::ios::binary | std::ios::trunc | std::ios::in | std::ios::out};
        s.write(file_content.c_str(), file_content.size());
        s.seekp(0);
    }

    handle_peer_data(peer_socket, message);
}

void CollabServer::on_peer_error() {
    QTcpSocket* peer_socket = qobject_cast<QTcpSocket*>(sender());
    if (peer_socket) {
        std::cout << "Peer error: " << peer_socket->errorString().toStdString() << std::endl;
    }
}

void CollabServer::handle_peer_data(QTcpSocket* peer_socket, const std::string& message) {
    // This function is a placeholder for handling peer data
    // Implement custom logic here as needed
}

void CollabServer::on_new_connection() {
    QTcpSocket* peer_socket = _server->nextPendingConnection();
    if (!peer_socket) return;

    auto peer = std::make_unique<QTcpSocket>();
    peer.reset(peer_socket);

    connect(peer.get(), &QTcpSocket::connected, this, &CollabServer::on_peer_connected);
    connect(peer.get(), &QTcpSocket::disconnected, this, &CollabServer::on_peer_disconnected);
    connect(peer.get(), &QTcpSocket::readyRead, this, &CollabServer::on_peer_ready_read);
    connect(peer.get(), &QTcpSocket::errorOccurred, this, [this]() { on_peer_error(); });

    {
        std::lock_guard<std::mutex> lock(_peers_mutex);
        _peers.push_back(std::move(peer));
    }

    _is_online = true;
    std::cout << "New peer connected" << std::endl;
}

CollabServer::statusRes CollabServer::start_server(int port) {
    _server = std::make_unique<QTcpServer>();

    connect(_server.get(), &QTcpServer::newConnection, this, &CollabServer::on_new_connection);

    if (!_server->listen(QHostAddress::Any, port)) {
        return { false, "Error: Failed to listen on server socket" };
    }

    return { true, "Success: Server created on port " + std::to_string(port) };
}

CollabServer::statusRes CollabServer::startServerThread(int port) {
    statusRes status = start_server(port);

    if (!status.code)
        return status;

    // Note: Qt signal/slot mechanism handles threading automatically through the event loop
    // No explicit thread creation needed

    return status;
}
