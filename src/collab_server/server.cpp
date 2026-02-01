#include "collab_server/server.hpp"

#include <iostream>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <QHostAddress>
#include <QByteArray>
#include <QDataStream>

CollabServer::CollabServer(QObject* parent)
    : QObject(parent), _server(nullptr), _is_online(false)
{
}

CollabServer::~CollabServer() {
    std::lock_guard<std::mutex> lock(_peers_mutex);
    for (auto& peer_state : _peers) {
        if (peer_state.socket && peer_state.socket->state() == QTcpSocket::ConnectedState) {
            peer_state.socket->disconnectFromHost();
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
        PeerState peer_state;
        peer_state.socket = std::move(peer_socket);
        _peers.push_back(std::move(peer_state));
    }

    _is_online = true;
    return {true, "Successfully connected to " + ip + ":" + std::to_string(port)};
}

void CollabServer::send_file_to_peers(std::string file_path, std::string project_name) {
    std::ifstream text(file_path, std::ios::binary);
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

    for (auto& peer_state : _peers) {
        if (peer_state.socket && peer_state.socket.get() != sender_socket && 
            peer_state.socket->state() == QTcpSocket::ConnectedState) {
            std::cout << "Sending to peer" << std::endl;
            send_message_internal(peer_state.socket.get(), message);
        }
    }
}

void CollabServer::send_message_internal(QTcpSocket* socket, const std::string& message) {
    QByteArray packet;
    QDataStream stream(&packet, QIODevice::WriteOnly);
    stream.setVersion(QDataStream::Qt_6_0);
    
    // Write message length as header
    stream << static_cast<quint32>(message.size());
    // Write message data
    packet.append(message.c_str(), message.size());
    
    socket->write(packet);
    socket->flush();
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
            [](const PeerState& peer_state) {
                return !peer_state.socket || peer_state.socket->state() != QTcpSocket::ConnectedState;
            }),
        _peers.end()
    );

    if (_peers.empty()) {
        _is_online = false;
    }
}

bool CollabServer::try_process_message(PeerState& peer_state) {
    if (peer_state.expected_message_length == 0) {
        // Try to read the message length header
        if (peer_state.buffer.size() < static_cast<int>(sizeof(quint32))) {
            return false; // Need more data for the header
        }
        
        QDataStream stream(&peer_state.buffer, QIODevice::ReadOnly);
        stream.setVersion(QDataStream::Qt_6_0);
        stream >> peer_state.expected_message_length;
    }
    
    // Check if we have the complete message
    if (peer_state.buffer.size() < static_cast<int>(sizeof(quint32) + peer_state.expected_message_length)) {
        return false;
    }
    
    // Extract the message data
    std::string message(peer_state.buffer.constData() + sizeof(quint32), peer_state.expected_message_length);
    
    // Remove processed data from buffer
    peer_state.buffer.remove(0, sizeof(quint32) + peer_state.expected_message_length);
    peer_state.expected_message_length = 0;
    
    // Process the message
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
        s.close();
    }

    handle_peer_data(peer_state.socket.get(), message);
    
    return true;
}

void CollabServer::on_peer_ready_read() {
    QTcpSocket* peer_socket = qobject_cast<QTcpSocket*>(sender());
    if (!peer_socket) return;

    std::lock_guard<std::mutex> lock(_peers_mutex);
    
    // Find the peer state for this socket
    auto peer_it = std::find_if(_peers.begin(), _peers.end(),
        [peer_socket](const PeerState& ps) { return ps.socket.get() == peer_socket; });
    
    if (peer_it == _peers.end()) return;
    
    // Append new data to the buffer
    peer_it->buffer.append(peer_socket->readAll());
    
    while (try_process_message(*peer_it)) {
    }
}

void CollabServer::on_peer_error() {
    QTcpSocket* peer_socket = qobject_cast<QTcpSocket*>(sender());
    if (peer_socket) {
        std::cout << "Peer error: " << peer_socket->errorString().toStdString() << std::endl;
    }
}

void CollabServer::handle_peer_data(QTcpSocket* peer_socket, const std::string& message) {
}

void CollabServer::on_new_connection() {
    QTcpSocket* peer_socket = _server->nextPendingConnection();
    if (!peer_socket) return;

    connect(peer_socket, &QTcpSocket::connected, this, &CollabServer::on_peer_connected);
    connect(peer_socket, &QTcpSocket::disconnected, this, &CollabServer::on_peer_disconnected);
    connect(peer_socket, &QTcpSocket::readyRead, this, &CollabServer::on_peer_ready_read);
    connect(peer_socket, &QTcpSocket::errorOccurred, this, [this]() { on_peer_error(); });

    {
        std::lock_guard<std::mutex> lock(_peers_mutex);
        PeerState peer_state;
        peer_state.socket = std::make_unique<QTcpSocket>();
        peer_state.socket.reset(peer_socket);
        _peers.push_back(std::move(peer_state));
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

    return status;
}
