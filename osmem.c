// SPDX-License-Identifier: BSD-3-Clause

#include "osmem.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include "block_meta.h"

#define MMAP_THRESHOLD (128 * 1024)
#define INITIAL_HEAP_SIZE (128 * 1024)
struct block_meta *head;
struct block_meta *last_block;
void *preallocated_heap;
size_t remaining_heap_size;


void initialize_heap(void)
{
	preallocated_heap = sbrk(INITIAL_HEAP_SIZE);
	DIE(preallocated_heap == (void *) -1, "sbrk");
	remaining_heap_size = INITIAL_HEAP_SIZE;
}
void split_block(struct block_meta *the_block, size_t aligned_size)
{
	size_t remaining_size = the_block->size - aligned_size;

	if (remaining_size >= ((sizeof(struct block_meta)+7)&~7) + 1) {
		struct block_meta *new_block = (struct block_meta *)((char *)the_block + aligned_size);

		new_block->size = remaining_size;
		new_block->status = STATUS_FREE;
		new_block->next = the_block->next;
		if (the_block->next != NULL)
			the_block->next->prev = new_block;
		the_block->next = new_block;
		new_block->prev = the_block;
		if (new_block->next == NULL)
			last_block = new_block;
		the_block->size = aligned_size;
	}
}
void coalesce_blocks(void)
{
	struct block_meta *current = head;

	while (current != NULL) {
		if (current->status == STATUS_FREE) {
			struct block_meta *next = current->next;

			while (next != NULL && next->status == STATUS_FREE) {
				current->size += next->size;
				current->next = next->next;
				if (next->next != NULL)
					next->next->prev = current;
				next = current->next;
			}
		}
		if (current->next == NULL)
			last_block = current;
		current = current->next;
	}
}
void *find_best_block(size_t size)
{
	struct block_meta *current = head;

	struct block_meta *best_fit = NULL;

	size_t best_fit_diff = (size_t) -1;

	while (current != NULL) {
		if (current->status == STATUS_FREE && current->size >= size) {
			size_t internal_fragmentation = current->size - size;

			if (internal_fragmentation < best_fit_diff) {
				best_fit_diff = internal_fragmentation;
				best_fit = current;
			}
		}
		current = current->next;
	}
	if (best_fit != NULL)
		best_fit->status = STATUS_ALLOC;
	return (void *)(best_fit);
}

void *os_malloc(size_t size)
{
	/* TODO: Implement os_malloc */
	if (size == 0)
		return NULL;
	if (preallocated_heap == NULL && size < MMAP_THRESHOLD)
		initialize_heap();
	size_t aligned_size = (size + sizeof(struct block_meta) + 7) & ~7;

	struct block_meta *best_fit = find_best_block(aligned_size);

	if (best_fit != NULL) {
		split_block(best_fit, aligned_size);
		best_fit->status = STATUS_ALLOC;
		return (void *)(best_fit + 1);
	}
	void *ptr;

	struct block_meta *block;

	if (aligned_size < MMAP_THRESHOLD) {
		if (remaining_heap_size < aligned_size) {
			if (last_block->status == STATUS_FREE) {
				size_t the_size = aligned_size - last_block->size;

				ptr = sbrk(the_size);
				DIE(ptr == (void *) -1, "sbrk");
				last_block->size += the_size;
				last_block->status = STATUS_ALLOC;
				return (void *)(last_block + 1);
			}
			ptr = sbrk(aligned_size);
			DIE(ptr == (void *)-1, "sbrk");
		} else {
			ptr = preallocated_heap;
			preallocated_heap += aligned_size;
			remaining_heap_size -= aligned_size;
		}
		block = (struct block_meta *) ptr;
		block->size = aligned_size;
		block->status = STATUS_ALLOC;
	} else {
		ptr = mmap(NULL, aligned_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		DIE(ptr == MAP_FAILED, "mmap");
		block = (struct block_meta *) ptr;
		block->size = aligned_size;
		block->status = STATUS_MAPPED;
	}
	if (head == NULL) {
		block->prev = NULL;
		block->next = NULL;
		head = block;
		last_block = head;
	} else {
		block->next = NULL;
		last_block->next = block;
		block->prev = last_block;
		last_block = block;
	}
	return (void *)(block + 1);
}
void os_free(void *ptr)
{
	if (ptr == NULL)
		return;
	struct block_meta *block = (struct block_meta *)ptr - 1;

	if (block->status != STATUS_ALLOC && block->status != STATUS_MAPPED)
		return;
	if (block->status == STATUS_ALLOC) {
		block->status = STATUS_FREE;
		coalesce_blocks();
	} else {
		if (block == head) {
			head = NULL;
			last_block = NULL;
			long rez = munmap(block, block->size);

			DIE(rez == -1, "munmap");
			return;
		}
		if (block == last_block && block->prev != NULL)
			last_block = block->prev;
		if (block->prev != NULL)
			block->prev->next = block->next;
		if (block->next != NULL)
			block->next->prev = block->prev;
		long rez = munmap(block, block->size);

		DIE(rez == -1, "munmap");
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	if (nmemb == 0 || size == 0)
		return NULL;
	size_t total_size = nmemb * size;

	size_t page_size = getpagesize();

	size_t aligned_size = (total_size + sizeof(struct block_meta) + 7) & ~7;

	if (preallocated_heap == NULL && aligned_size < page_size)
		initialize_heap();
	struct block_meta *best_fit = find_best_block(aligned_size);

	if (best_fit != NULL) {
		split_block(best_fit, aligned_size);
		best_fit->status = STATUS_ALLOC;
		void *allocated_memory = (void *)(best_fit + 1);

		memset(allocated_memory, 0, total_size);
		return allocated_memory;
	}
	void *ptr;

	struct block_meta *block;

	if (aligned_size < page_size) {
		if (remaining_heap_size < aligned_size) {
			if (last_block->status == STATUS_FREE) {
				size_t the_size = aligned_size - last_block->size;

				ptr = sbrk(the_size);
				DIE(ptr == (void *)-1, "sbrk");
				last_block->size += the_size;
				last_block->status = STATUS_ALLOC;
				void *allocated_memory = (void *)(last_block + 1);

				memset(allocated_memory, 0, total_size);
				return allocated_memory;
			}
			ptr = sbrk(aligned_size);
			DIE(ptr == (void *)-1, "sbrk");
		} else {
			ptr = preallocated_heap;
			preallocated_heap += aligned_size;
			remaining_heap_size -= aligned_size;
		}
		block = (struct block_meta *)ptr;
		block->size = aligned_size;
		block->status = STATUS_ALLOC;

	} else {
		ptr = mmap(NULL, aligned_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		DIE(ptr == MAP_FAILED, "mmap");
		block = (struct block_meta *)ptr;
		block->size = aligned_size;
		block->status = STATUS_MAPPED;
	}
	if (head == NULL) {
		block->prev = NULL;
		block->next = NULL;
		head = block;
		last_block = head;
	} else {
		block->next = NULL;
		last_block->next = block;
		block->prev = last_block;
		last_block = block;
	}
	void *allocated_memory = (void *)(block + 1);

	memset(allocated_memory, 0, total_size);
	return allocated_memory;
}

void *os_realloc(void *ptr, size_t size)
{
	if (size == 0) {
		os_free(ptr);
		return NULL;
	}
	if (ptr == NULL)
		return os_malloc(size);
	struct block_meta *old_block = (struct block_meta *)ptr - 1;

	if (old_block->status == STATUS_FREE)
		return NULL;
	size_t aligned_size = (size + sizeof(struct block_meta) + 7) & ~7;

	if (old_block->status == STATUS_MAPPED) {
		void *new_ptr = os_malloc(size);

		memmove(new_ptr, ptr, (old_block->size < size ? old_block->size : size));
		os_free(ptr);
		return new_ptr;
	}
	if (aligned_size <= old_block->size) {
		size_t remaining_size = old_block->size - aligned_size;

		if (remaining_size >= (sizeof(struct block_meta) + 1)) {
			split_block(old_block, aligned_size);
			old_block->size = aligned_size;
			old_block->status = STATUS_ALLOC;
			return (void *)(old_block + 1);
		}
		old_block->status = STATUS_ALLOC;
		return ptr;
	}
	if (old_block->next != NULL && old_block->next->status == STATUS_FREE) {
		struct block_meta *next_block = old_block->next;

		size_t combined_size = old_block->size + next_block->size;

		if (combined_size >= aligned_size) {
			old_block->next = next_block->next;
			if (next_block->next != NULL)
				next_block->next->prev = old_block;
			old_block->size = combined_size;
			old_block->status = STATUS_ALLOC;
			if (old_block->next == NULL)
				last_block = old_block;
			if (combined_size - aligned_size >= sizeof(struct block_meta) + 1) {
				split_block(old_block, aligned_size);
				old_block->size = aligned_size;
				old_block->status = STATUS_ALLOC;
			}
			return (void *)(old_block + 1);
		}
	}
	if (old_block == last_block) {
		size_t the_size = aligned_size - last_block->size;

		ptr = sbrk(the_size);
		DIE(ptr == (void *) -1, "sbrk");
		last_block->size += the_size;
		last_block->status = STATUS_ALLOC;
		return (void *)(last_block + 1);
	}
	if (aligned_size >= MMAP_THRESHOLD)
		os_free(ptr);
	else
		old_block->status = STATUS_FREE;
	void *new_ptr = os_malloc(size);

	coalesce_blocks();
	if (new_ptr != NULL) {
		size_t copy_size = old_block->size;

		if (copy_size > 0 && new_ptr != ptr)
			memmove(new_ptr, ptr, copy_size);
		return new_ptr;
	}
	return NULL;
}
