#include <stdio.h>
#include <stdlib.h>
#include <unordered_map>

#include "abc.h"

#define LBA_SIZE 4096

//#define DEBUG_ABC
#ifdef DEBUG_ABC
#define abc_debug(f_, ...)printf((f_), ##__VA_ARGS__);
#else
#define abc_debug(fmt, args...)
#endif

using namespace std;

/* data cache. can be registered with RDMA for zero copy */
uint8_t *cache_data;

struct cache_entry
{
	uint8_t *data;
	unsigned long lba;
	bool valid;
	struct cache_entry *next;
	struct cache_entry *prev;
};

static unsigned long cache_size_lba = 0;
static unsigned long current_lba = 0;
static unordered_map<unsigned long, struct cache_entry *> cache_map;

static struct cache_entry *head = NULL;
static struct cache_entry *tail = NULL;

void abc_init(unsigned long size)
{
    abc_debug("abc_init\n");

    cache_data = (uint8_t *)malloc(size);
    cache_size_lba = size / 1024 / 4;

    abc_debug("allocated: %lu LBAs; base addr %lu\n",
            cache_size_lba, (unsigned long)cache_data);
}

void abc_deinit()
{
    free(cache_data);
}

void abc_print_list()
{
    struct cache_entry *entry = tail;

    abc_debug("Printing all LBAs: ");
    fflush(stdout);

    while (entry != NULL) {
        abc_debug("%lu ", entry->lba);
        fflush(stdout);
        entry = entry->next;
    }

    abc_debug("\n");

    entry = head;
    abc_debug("Printing all LBAs in reverse: ");
    fflush(stdout);

    while (entry != NULL) {
        abc_debug("%lu ", entry->lba);
        fflush(stdout);
        entry = entry->prev;
    }

    abc_debug("\n");
}

bool abc_is_block_cached(unsigned long lba, uint8_t **addr)
{
    //abc_print_list();

    if (cache_map.find(lba) != cache_map.end()) {
        abc_debug("CACHE HIT\n");
        struct cache_entry *entry = cache_map[lba];
        if (entry->prev != NULL) {
            entry->prev->next = entry->next;
            if (entry->next != NULL)
                entry->next->prev = entry->prev;
            else
                head = entry->prev;

            entry->next = tail;
            entry->prev = NULL;
            tail->prev = entry;
        }

        /* set new tail */
        tail = entry;

        *addr = cache_map[lba]->data;

        return true;
    }

    abc_debug("CACHE MISS\n");

    return false;
}

/* get block entry for this lba */
void abc_get_block_entry(unsigned long lba, uint8_t **addr)
{
    //abc_print_list();

    abc_debug("abc_get_block_entry\n");

    if (current_lba < cache_size_lba) {
        abc_debug("caching block number: %lu\n", current_lba);

        /* cache not consumed */
        if (head == NULL) {
            abc_debug("first element to cache\n");

            /* first element to cache */
            head = (cache_entry *)malloc(sizeof(cache_entry));

            head->next = NULL;
            head->prev = NULL;

            head->data = &cache_data[current_lba * LBA_SIZE];
            tail = head;

        } else {
            abc_debug("non-first element to cache\n");

            head->next = (cache_entry *)malloc(sizeof(cache_entry));
            struct cache_entry *tmp = head;
            head = head->next;
            head->prev = tmp;

            head->next = NULL;
            head->data = &cache_data[current_lba * LBA_SIZE];
        }

        /* returning address of the head data */
        *addr = head->data;
        head->lba = lba;
        head->valid = false;
        cache_map.insert(make_pair(lba, head));

        current_lba += 1;
    } else {
        abc_debug("reusing least recently used block\n");

        struct cache_entry *new_head = head->prev;

        head->next = tail;
        head->prev = NULL;
        tail->prev = head;

        tail = head;
        head = new_head;
        head->next = NULL;

        /* returning address of the tail data */
        *addr = tail->data;

        /* remove old lba from map and insert new one */
        cache_map.erase(tail->lba);
        tail->lba = lba;
        tail->valid = false;
        cache_map.insert(make_pair(lba, tail));
    }
}

/* content copied into the cache, set valid */
void abc_set_valid(unsigned long lba)
{
    if (cache_map.find(lba) == cache_map.end()) {
        abc_debug("error: element not found in cache\n");
    } else {
        cache_map[lba]->valid = true;
    }
}
