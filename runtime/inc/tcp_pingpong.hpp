#pragma once

#include <thread>
#include <queue>
#include <mutex>
#include <memory>
#include <condition_variable>
#include <future>
#include <chrono>

#include <stdio.h>
#include <string.h>

#ifdef _WIN64
#include <WinSock2.h>
#include <WS2tcpip.h>

#pragma comment(lib, "ws2_32.lib")
#endif

#ifdef __linux__
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
typedef int SOCKET;
#define SD_RECEIVE SHUT_RD
#define SD_BOTH SHUT_RDWR
#define closesocket close
#endif

using namespace std::chrono_literals;

namespace tcp_pingpong
{
	class tcp_queue
	{
	protected:
		std::mutex m_mutex;
		std::condition_variable m_cv;
		std::queue<std::shared_ptr<char>> m_queue;
		std::thread m_worker;
		std::promise<bool> m_completion_promise;
		size_t m_data_size;
		bool m_run;
		SOCKET m_socket;
		virtual void loop() {};
	public:
		tcp_queue() {}
		~tcp_queue() {}

		void start(SOCKET socket_fd, size_t data_size)
		{
			m_socket = socket_fd;
			m_data_size = data_size;
			m_run = true;
			std::thread t(&tcp_queue::loop, this);
			std::swap(m_worker, t);
		}

		void stop() 
		{
			m_run = false;
			std::future<bool> completion_future = m_completion_promise.get_future();
			while(completion_future.wait_for(0ms) != std::future_status::ready)
				m_cv.notify_all();
			m_worker.join();
		}

		virtual void process() {};
	};

	class tcp_send_queue : public tcp_queue
	{
	private:
		void loop()
		{
			for (;;)
			{
				std::shared_ptr<char> data = nullptr;
				bool to_send = false;
				bool to_block = false;

				std::unique_lock<std::mutex> lock(m_mutex);
				
				if(m_queue.empty())
				{
					m_cv.wait(lock);

					if (!m_queue.empty())
					{
						data = m_queue.front();
						m_queue.pop();
						to_send = true;
					}
					else
					{
						to_send = false;
						if (!m_run)
						{
							lock.unlock();
							m_completion_promise.set_value(true);
							return;
						}
					}
				}
				else
				{
					data = m_queue.front();
					m_queue.pop();
					to_send = true;
				}

				lock.unlock();

				if (to_send)
				{
					int status = ::send(m_socket, data.get(), (int)m_data_size, 0);

					if (status != m_data_size)
					{
						throw std::system_error
						{
							static_cast<int>(errno),
							std::system_category(),
							"Error send on socket"
						};
					}
				}
			}
		}
	public:
		tcp_send_queue() {}
		~tcp_send_queue() {}

		void process(char* data)
		{
			std::shared_ptr<char> m_data{ new char[m_data_size] };
			memcpy(m_data.get(), data, m_data_size);
			std::lock_guard<std::mutex> lock(m_mutex);
			m_queue.push(m_data);
			m_cv.notify_all();
		}
	};

	class tcp_recv_queue : public tcp_queue
	{
	private:
		void loop()
		{
			for (;;)
			{
				if (!m_run)
				{
					m_completion_promise.set_value(true);
					return;
				}

				std::shared_ptr<char> data{ new char[m_data_size] };

				int status = 0, received = 0;
				
				for (;;)
				{
					status = ::recv(m_socket, data.get() + received, (int)m_data_size - received, 0);

					if (status == -1)
					{
						throw std::system_error
						{
						static_cast<int>(errno),
						std::system_category(),
						"Error recv on socket"
						};
					}

					if (status == 0)
					{
						m_completion_promise.set_value(true);
						return;
					}

					received += status;

					if (received == m_data_size)
					{
						std::lock_guard<std::mutex> lock(m_mutex);
						m_queue.push(data);
						break;
					}

					if (!m_run)
					{
						m_completion_promise.set_value(true);
						return;
					}
				}
			}
		}
	public:
		tcp_recv_queue() {}
		~tcp_recv_queue() {}

		void process(char* data, bool& status)
		{
			std::lock_guard<std::mutex> lock(m_mutex);
			if (m_queue.empty())
			{
				status = false;
				return;
			}
			else
			{
				status = true;
				std::shared_ptr<char> pop_data = m_queue.front();
				m_queue.pop();
				::memcpy(data, pop_data.get(), m_data_size);
			}
		}
	};

	class tcp_queue_pair
	{
	protected:
		tcp_send_queue m_sq;
		tcp_recv_queue m_rq;
	public:
		tcp_queue_pair() {}
		~tcp_queue_pair() {}

		void start(SOCKET socket_fd, size_t send_size, size_t recv_size)
		{
			m_sq.start(socket_fd, send_size);
			m_rq.start(socket_fd, recv_size);
		}
		void stop()
		{
			m_sq.stop();
			m_rq.stop();
		}
		void push(char* data)
		{
			m_sq.process(data);
		}
		void pop(char* data, bool& status)
		{
			m_rq.process(data, status);
		}
	};

	class tcp_client : public tcp_queue_pair
	{
	private:
		SOCKET m_socket;
	public:
		tcp_client() {}
		~tcp_client() {}
		void connect(const char* serv_addr, short int serv_port, size_t send_size, size_t recv_size)
		{
			struct sockaddr_in serv_sockaddr_in;
			m_socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

			if (m_socket == -1)
			{
				throw std::system_error
				{
					static_cast<int>(errno),
					std::system_category(),
					"Error creating socket"
				};
			}

			serv_sockaddr_in.sin_family = AF_INET;
			inet_pton(AF_INET, serv_addr, &serv_sockaddr_in.sin_addr);
			serv_sockaddr_in.sin_port = htons(serv_port);

			int status = ::connect(m_socket, (const sockaddr*)&serv_sockaddr_in, sizeof(struct sockaddr_in));

			if (status != 0)
			{
				throw std::system_error
				{
					static_cast<int>(errno),
					std::system_category(),
					"Error connecting socket"
				};
			}

			start(m_socket, send_size, recv_size);
		}

		void disconnect()
		{
			int status = ::shutdown(m_socket, SD_BOTH);

			if (status != 0)
			{
				throw std::system_error
				{
					static_cast<int>(errno),
					std::system_category(),
					"Error closing socket"
				};
			}

			stop();

			status = ::closesocket(m_socket);

			if (status != 0)
			{
				throw std::system_error
				{
					static_cast<int>(errno),
					std::system_category(),
					"Error closing socket"
				};
			}
		}
	};

	class tcp_server : public tcp_queue_pair
	{
	private:
		SOCKET m_socket;
		SOCKET m_listen;
		socklen_t m_cli_len;
		struct sockaddr_in m_serv_addr;
		struct sockaddr_in m_cli_addr;
		short int port;
	public:
		tcp_server() {}
		~tcp_server() {}

		void listen()
		{
			m_listen = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

			if (m_listen == -1)
			{
				throw std::system_error
				{
					static_cast<int>(errno),
					std::system_category(),
					"Error creating listen socket"
				};
			}

			::memset(&m_serv_addr, 0, sizeof(struct sockaddr_in));

			m_serv_addr.sin_family = AF_INET;
			m_serv_addr.sin_port = 0;
			m_serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);

			int status = ::bind(m_listen, (const sockaddr*)&m_serv_addr, sizeof(struct sockaddr_in));

			if (status != 0)
			{
				throw std::system_error
				{
					static_cast<int>(errno),
					std::system_category(),
					"Error binding listen socket"
				};
			}

			socklen_t len = sizeof(struct sockaddr_in);
			status = ::getsockname(m_listen, (sockaddr*)&m_serv_addr, &len);

			if (status != 0)
			{
				throw std::system_error
				{
					static_cast<int>(errno),
					std::system_category(),
					"Error getsockname listen socket"
				};
			}

			fprintf(stdout, "Server is listening on port number %hu\n", ntohs(m_serv_addr.sin_port));
			status = ::listen(m_listen, 10);

			if (status != 0)
			{
				throw std::system_error
				{
					static_cast<int>(errno),
					std::system_category(),
					"Error listen on socket"
				};
			}
		}

		void accept(size_t send_size, size_t recv_size)
		{
			m_cli_len = sizeof(m_cli_addr);

			m_socket = ::accept(m_listen, (sockaddr*)&m_cli_addr, &m_cli_len);

			if (m_socket == -1)
			{
				throw std::system_error
				{
					static_cast<int>(errno),
					std::system_category(),
					"Error accept socket"
				};
			}

			start(m_socket, send_size, recv_size);
		}

		void disconnect()
		{
			int status = ::shutdown(m_socket, SD_RECEIVE);

			if (status != 0)
			{
				throw std::system_error
				{
					static_cast<int>(errno),
					std::system_category(),
					"Error closing socket"
				};
			}

			stop();

			status = ::closesocket(m_socket);

			if (status != 0)
			{
				throw std::system_error
				{
					static_cast<int>(errno),
					std::system_category(),
					"Error closing socket"
				};
			}

			status = ::closesocket(m_listen);

			if (status != 0)
			{
				throw std::system_error
				{
					static_cast<int>(errno),
					std::system_category(),
					"Error closing listen socket"
				};
			}
		}
	};
}