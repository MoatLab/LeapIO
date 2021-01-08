#pragma once
//#include <libpmemlog.h>
#include <memory>
#include <map>
#include <set>
//#include <shared_mutex>
#include <algorithm>
#include <unordered_set>
//#include <atomic>
#include <stdio.h>
#include <string.h>
#if defined (__GNUC__) || defined(__linux) || defined(__linux__) || defined(LINUX) || defined(__unix__) || defined(UNIX) || defined(Linux) || defined(linux)
#include <sys/uio.h>
#endif

#ifdef _WIN64
struct iovec
{
	void  *iov_base;    /* Starting address */
	size_t iov_len;     /* Number of bytes to transfer */
};
#endif
namespace snapshot_nvme
{
	static const size_t max_atomic = 32;
	static const size_t block_size = 4096;
	struct snvme_pmem_metadata
	{
		unsigned long long version;
		size_t num_blocks;
	};

	struct snvme_pmem_block_metadata
	{
		union
		{
			snvme_pmem_metadata metadata;
			unsigned char raw[block_size];
		};
	};

	struct snvme_pmem_block
	{
		unsigned char data[block_size];
	};

	struct snvme_pmem_logentry
	{
		snvme_pmem_block_metadata metadata;
		snvme_pmem_block blocks[max_atomic];
	};

	class snvme_pmem_mementry
	{
	private:
		unsigned long long m_version;
		struct iovec* m_raw;
		int m_count;
		off_t m_offset;

		// store this in the log for easier flushing
		uint16_t m_vqp_id;
		uint16_t m_cid;

	public:
		snvme_pmem_mementry(struct iovec* data, int count, off_t offset, unsigned long long version, uint16_t vqp_id, uint16_t cid)
		{
			m_version = version;
			m_offset = offset;
			m_count = 0;
			m_raw = new struct iovec[max_atomic];
			for (int i = 0; i < count; i++)
			{
				size_t num_blocks = data[i].iov_len / block_size;
				for (int j = 0; j < num_blocks; j++)
				{
					m_raw[m_count].iov_base = new char[block_size];
					m_raw[m_count].iov_len = block_size;
					::memcpy(m_raw[m_count++].iov_base, (char*)data[i].iov_base + j * block_size, block_size);
				}
			}

			// store vqp id and cid of this vQP entry
			m_vqp_id = vqp_id;
			m_cid = cid;
		}

		~snvme_pmem_mementry()
		{
			for (int i = 0; i < m_count; i++)
			{
				delete[] (char*)m_raw[i].iov_base;
			}

			delete[] m_raw;
		}

		void get_count(int& count) { count = m_count; };

		void get_block(bool& found, off_t offset, char*& data)
		{
			found = false;
			if (offset >= m_offset && offset < m_offset + m_count * block_size)
			{
				found = true;
			}

			if (found && data != NULL)
			{
				::memcpy(data, m_raw[(offset - m_offset) / block_size].iov_base, block_size);
			}
		}

		void get_offset(off_t& offset)
		{
			offset = m_offset;
		}

		void get_raw(struct iovec*& raw)
		{
			::memcpy(raw, m_raw, sizeof(struct iovec) * m_count);
		}

		void get_version(unsigned long long& version) const { version = m_version; }

		// getters to return info about log req
		void get_vqp_id(uint16_t& vqp_id)
		{
			vqp_id = m_vqp_id;
		}

		void get_cid(uint16_t& cid)
		{
			cid = m_cid;
		}
	};

	struct snvme_pmementry_compare
	{
		bool operator() (const std::shared_ptr<snvme_pmem_mementry>& lhs,
			const std::shared_ptr<snvme_pmem_mementry>& rhs) const
		{
			unsigned long long lhs_version, rhs_version;
			lhs->get_version(lhs_version);
			rhs->get_version(rhs_version);
			return lhs_version < rhs_version;
		}
	};

	class snvme_pmem
	{
	private:
		//std::atomic<unsigned long long> m_current_version;
		unsigned long long m_current_version;

		std::set<std::shared_ptr<snvme_pmem_mementry>, snvme_pmementry_compare> m_versions;
		//std::shared_mutex m_lock;
	public:
		snvme_pmem() { m_current_version = 0; }
		~snvme_pmem() {}

		void add_version(struct iovec* data, int count, off_t offset, uint16_t vqp_id, uint16_t cid)
		{
			//m_lock.lock();
			unsigned long long my_version = m_current_version++;
			m_versions.insert(std::make_shared<snvme_pmem_mementry>(data, count, offset, my_version, vqp_id, cid));
			//m_lock.unlock();
		}

		void peek_oldest_version(bool& done, struct iovec*& data, int& count, off_t& offset, uint16_t& vqp_id, uint16_t& cid)
		{
			//m_lock.lock();
			int given_count = count;
			auto it = m_versions.begin();

			if (it == m_versions.end())
			{
				done = false;
				count = 0;
				//m_lock.unlock();
				return;
			}

			done = true;
			(*it)->get_count(count);

			if (given_count < count)
			{
				//m_lock.unlock();
				return;
			}

			(*it)->get_raw(data);
			(*it)->get_offset(offset);

			// stnovako: get vqp_id and cid of pending log entry
			(*it)->get_vqp_id(vqp_id);
			(*it)->get_cid(cid);

			//m_lock.unlock();
		}

		void pop_oldest_version()
		{
			//m_lock.lock();
			auto it = m_versions.begin();
			m_versions.erase(it);
			//m_lock.unlock();
		}

		void read_latest_versions(struct iovec* data, int count, off_t offset)
		{
			//m_lock.lock_shared();

			for (int i = 0; i < count; i++)
			{
				off_t current = offset + i * block_size;

				for (auto it = m_versions.rbegin(); it != m_versions.rend(); ++it)
				{
					bool found;
					char* location = (char*)data[i].iov_base;
					(*it)->get_block(found, current, location);

					if (found)
					{
						data[i].iov_len = 0;
						break;
					}
				}
			}

			//m_lock.unlock_shared();
		}
	};
}
