#pragma once

#include <string>
#include <vector>
#include <mutex>
#include <memory>
#include <QTcpServer>
#include <QTcpSocket>
#include <QObject>

class CollabServer : public QObject
{
    Q_OBJECT

    public:
        struct statusRes {
            bool code;
            std::string message;
        };

        CollabServer(QObject* parent = nullptr);
        ~CollabServer();
        statusRes startServerThread(int port);
        statusRes connect_to_peer(const std::string& ip, int port);
        void send_file_to_peers(std::string file_path, std::string project_name);
        bool get_is_online() const {
            return _is_online;
        }

    private slots:
        void on_new_connection();
        void on_peer_connected();
        void on_peer_disconnected();
        void on_peer_ready_read();
        void on_peer_error();

    private:
        void send_message_to_peers(const std::string& message, QTcpSocket* sender_socket);
        void handle_peer_data(QTcpSocket* peer_socket, const std::string& message);
        statusRes start_server(int port);

        std::unique_ptr<QTcpServer> _server;
        std::vector<std::unique_ptr<QTcpSocket>> _peers;
        std::mutex _peers_mutex;
        bool _is_online;
};
