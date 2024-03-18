/*
 * Copyright (c) 2015, Freescale Semiconductor, Inc.
 * Copyright 2016 NXP
 * Copyright 2021 ACRIOS Systems s.r.o.
 * All rights reserved.
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(erpc_tcp, LOG_LEVEL_DBG);

#include "erpc_tcp_transport_zephyr.hpp"
#include <cstdio>
#include <string>

#include <zephyr/kernel.h>
#include <errno.h>
#include <zephyr/posix/netdb.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/select.h>

using namespace erpc;

////////////////////////////////////////////////////////////////////////////////
// Code
////////////////////////////////////////////////////////////////////////////////
#define ERPC_TCP_STACKSIZE	2048
#define ERPC_TCP_PRIORITY	5
const char* task_name = "erpc_tcp";

K_THREAD_STACK_DEFINE(tcp_stack, ERPC_TCP_STACKSIZE);

TCPTransport::TCPTransport(bool isServer) :
m_isServer(isServer), 
m_host(NULL),
m_port(0),
m_socket(-1),
m_serverThread(serverThreadStub, ERPC_TCP_PRIORITY, ERPC_TCP_STACKSIZE, task_name), 
m_runServer(true)
{
	m_serverThread.setStackPointer(tcp_stack);
}

TCPTransport::TCPTransport(const char *host, uint16_t port, bool isServer) :
m_isServer(isServer), 
m_host(host),
m_port(port),
m_socket(-1),
m_serverThread(serverThreadStub, ERPC_TCP_PRIORITY, ERPC_TCP_STACKSIZE, task_name), 
m_runServer(true)
{
	m_serverThread.setStackPointer(tcp_stack);
}

TCPTransport::~TCPTransport(void) {}

void TCPTransport::configure(const char *host, uint16_t port)
{
	m_host = host;
	m_port = port;
}

erpc_status_t TCPTransport::open(void)
{
	erpc_status_t status;

	if (m_isServer)
	{
		m_runServer = true;
		m_serverThread.start(this);
		status = kErpcStatus_Success;
	}
	else
	{
		status = connectClient();
	}

	return status;
}

erpc_status_t TCPTransport::connectClient(void)
{
	erpc_status_t status = kErpcStatus_Success;
	struct addrinfo hints = {};
	char portString[8];
	struct addrinfo *res0;
	int result, set;
	int sock = -1;
	struct addrinfo *res;


	if (m_socket != -1)
	{
		LOG_DBG("%s", "socket already connected");
	}
	else
	{
		// Fill in hints structure for getaddrinfo.
		hints.ai_flags = AI_NUMERICSERV;
		hints.ai_family = PF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;

		// Convert port number to a string.
		result = snprintf(portString, sizeof(portString), "%d", m_port);
		if (result < 0)
		{
			LOG_ERR("snprintf failed");
			status = kErpcStatus_Fail;
		}

		if (status == kErpcStatus_Success)
		{
			// Perform the name lookup.
			result = getaddrinfo(m_host, portString, &hints, &res0);
			if (result != 0)
			{
				// TODO check EAI_NONAME
				LOG_ERR("gettaddrinfo failed");
				status = kErpcStatus_UnknownName;
			}
		}

		if (status == kErpcStatus_Success)
		{
			// Iterate over result addresses and try to connect. Exit the loop on the first successful
			// connection.
			for (res = res0; res; res = res->ai_next)
			{
				// Create the socket.
				sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

				if (sock < 0)
				{
					continue;
				}

				// Attempt to connect.
				if (connect(sock, res->ai_addr, res->ai_addrlen) < 0)
				{
					::close(sock);
					sock = -1;
					continue;
				}

				// Exit the loop for the first successful connection.
				break;
			}

			// Free the result list.
			freeaddrinfo(res0);

			// Check if we were able to open a connection.
			if (sock < 0)
			{
				// TODO check EADDRNOTAVAIL:
				LOG_ERR("connecting failed");
				status = kErpcStatus_ConnectionFailure;
			}
		}

		if (status == kErpcStatus_Success)
		{
			set = 1;
			if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (void *)&set, sizeof(int)) < 0)
			{
				::close(sock);
				LOG_ERR("setsockopt failed");
				status = kErpcStatus_Fail;
			}
		}

		if (status == kErpcStatus_Success)
		{
// On some systems (BSD) we can disable SIGPIPE on the socket. For others (Linux), we have to
// ignore SIGPIPE.
#if defined(SO_NOSIGPIPE)

			// Disable SIGPIPE for this socket. This will cause write() to return an EPIPE statusor if the
			// other side has disappeared instead of our process receiving a SIGPIPE.
			set = 1;
			if (setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, (void *)&set, sizeof(int)) < 0)
			{
				::close(sock);
				LOG_ERR("setsockopt failed");
				status = kErpcStatus_Fail;
			}
		}

		if (status == kErpcStatus_Success)
		{
#else
			// globally disable the SIGPIPE signal
			//signal(SIGPIPE, SIG_IGN);
#endif // defined(SO_NOSIGPIPE)
			m_socket = sock;
		}
	}

	return status;
}

erpc_status_t TCPTransport::close(bool stopServer)
{
	if (m_isServer && stopServer)
	{
		m_runServer = false;
	}

	if (m_socket != -1)
	{
		::close(m_socket);
		m_socket = -1;
	}

	return kErpcStatus_Success;
}

erpc_status_t TCPTransport::underlyingReceive(uint8_t *data, uint32_t size)
{
	ssize_t length;
	erpc_status_t status = kErpcStatus_Success;

	// Block until we have a valid connection.
	while (m_socket < 0)
	{
		k_msleep(10);
	}

	while (size > 0U)
	{
		length = read(m_socket, data, size);

		if (length > 0)
		{
			size -= length;
			data += length;
		}
		else if (length == 0)
		{
			LOG_ERR("Connection closed by peer");
			close(false); // Angenommen, diese Methode setzt m_socket korrekt zurück.
			return kErpcStatus_ConnectionClosed;
		}
		else // length < 0
		{
			if (errno == EAGAIN || errno == EWOULDBLOCK)
			{
				// Non-blocking mode: kein Daten verfügbar, später nochmal versuchen.
				continue;
			}
			else if (errno == EINTR)
			{
				// Leseversuch wurde durch ein Signal unterbrochen; erneut versuchen.
				continue;
			}
			else
			{
				LOG_ERR("Receive failed: %s", strerror(errno));
				return kErpcStatus_ReceiveFailed;
			}
		}
	}

	return status;
}

erpc_status_t TCPTransport::underlyingSend(const uint8_t *data, uint32_t size)
{
    if (m_socket < 0)
    {
        LOG_ERR("Invalid socket descriptor");
        return kErpcStatus_ConnectionFailure;
    }

    ssize_t result;
    while (size > 0)
    {
        result = write(m_socket, data, size);
        if (result > 0)
        {
            data += result;
            size -= result;
        }
        else if (result < 0)
        {
            if (errno == EPIPE)
            {
                LOG_ERR("Broken pipe - closing client socket");
                close(false); // Angenommen, diese Funktion schließt den Socket und setzt m_socket auf -1.
                return kErpcStatus_ConnectionClosed;
            }
            else if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                LOG_DBG("Resource temporarily unavailable - retrying");
                continue;
            }
            else
            {
                LOG_ERR("Send failed: %s", strerror(errno));
                return kErpcStatus_SendFailed;
            }
        }
        else // result == 0
        {
            LOG_ERR("No data sent, connection may be closed");
            return kErpcStatus_SendFailed;
        }
    }

    return kErpcStatus_Success;
}

void TCPTransport::serverThread(void)
{
    int yes = 1;
    int serverSocket;
    int result;
    struct sockaddr incomingAddress;
    socklen_t incomingAddressLength;
    int incomingSocket;
    struct sockaddr_in serverAddress;

    LOG_DBG("Starting server thread");

    // Create socket.
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket < 0)
    {
        LOG_ERR("Failed to create server socket");
        return; // Direkte Beendigung, da Socket-Erstellung fehlgeschlagen ist
    }

    // Fill in address struct.
    memset(&serverAddress, 0, sizeof(serverAddress));
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = INADDR_ANY;
    serverAddress.sin_port = htons(m_port);

    // Turn on reuse address option.
    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0)
    {
        LOG_ERR("Setsockopt SO_REUSEADDR failed");
        close(serverSocket);
        return; // Keine Fortsetzung bei Fehlschlag
    }

    // Bind socket to address.
    if (bind(serverSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
    {
        LOG_ERR("Bind failed");
        close(serverSocket);
        return; // Keine Fortsetzung bei Fehlschlag
    }

    // Listen for connections.
    if (listen(serverSocket, 1) < 0)
    {
        LOG_ERR("Listen failed");
        close(serverSocket);
        return; // Keine Fortsetzung bei Fehlschlag
    }

    LOG_DBG("Listening for connections on port: %u", m_port);

    while (m_runServer)
    {
        fd_set readfds;
        struct timeval tv;
        FD_ZERO(&readfds);
        FD_SET(serverSocket, &readfds);
        tv.tv_sec = 5; // Beispiel: Warte bis zu 5 Sekunden.
        tv.tv_usec = 0;

        int retval = select(serverSocket + 1, &readfds, NULL, NULL, &tv);

        if (retval == -1)
        {
            LOG_ERR("Select error, shutting down server...");
            break; // Beendet die Schleife bei kritischem Fehler
        }
        else if (retval)
        {
            incomingAddressLength = sizeof(struct sockaddr);
            incomingSocket = accept(serverSocket, &incomingAddress, &incomingAddressLength);
            if (incomingSocket >= 0)
                {
					LOG_DBG("connection accepted");
                    // Successfully accepted a connection.
                    m_socket = incomingSocket;
                    // should be inherited from accept() socket but it's not always ...
                    yes = 1;
                    setsockopt(m_socket, IPPROTO_TCP, TCP_NODELAY, (void *)&yes, sizeof(yes));
                }
            else
            {
                LOG_ERR("Accept failed");
            }
        }
        else
        {
            // Timeout, prüfen ob der Server herunterfahren soll
            if (!m_runServer)
            {
                LOG_DBG("Server shutdown initiated");
                break;
            }
        }
    }

    LOG_DBG("Exiting server thread");
    close(serverSocket);
}

void TCPTransport::serverThreadStub(void *arg)
{
	TCPTransport *This = reinterpret_cast<TCPTransport *>(arg);

	if (This != NULL)
	{
		This->serverThread();
	}
}
