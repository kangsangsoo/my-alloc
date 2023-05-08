#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#pragma GCC optimize("O3")
extern void debug(const char *fmt, ...);
extern void *sbrk(intptr_t increment);

#define TOPCHUNK_SIZE 0x8000
#define SMALL_BIN_SIZE 0xa0
// #define SMALL_BIN_SIZE_LOG 7
#define SMALL_BIN_NUM SMALL_BIN_SIZE >> 4
#define LARGE_BIN_NUM 21
#define USED 0
#define UNUSED 1

struct SmallChunk {
    size_t size;
    size_t fw;
};

struct LargeChunk {
    size_t size;
    size_t fw;
    size_t bw;
};

size_t max_size;
size_t limit;
size_t topchunk;
struct SmallChunk* small_bins[SMALL_BIN_NUM];
// e.g. small_chunks[0x2]의 사이즈는 0x20
struct LargeChunk* large_bins[LARGE_BIN_NUM];
// large_chunks는 SMALL_BIN_SIZE_LOG부터 시작하면
// e.g. large_chunks[0x10]에 들어가는 청크의 사이즈는 [1<<0x10, 1<<0x11)

// 스몰 청크는 병합하지 않는다.
// 라지 청크는 병합이 가능하다.

#define size_normalization(size) (((size + 0x10) | 0xf) + 1)
// size_t size_normalization(size_t size) {
//     // myalloc에 요청한 사이즈를 정규화한다.
//     return size = (size + 0x10 | 0xf) + 1;
// }

#define find_msb(size)  { \
                            size_t i = 0; \
                            size_t res = 0; \
                            while(size) { \
                                if(size & 1) res = i; \
                                i++; \
                                size >>= 1; \
                            } \
                            size = res; \
                        } 
// size_t find_msb(size_t size) {
//     size_t i = 0;
//     size_t res = 0;
//     while(size) {
//         if(size & 1) res = i;
//         i++;
//         size >>= 1;
//     }
//     return res;
// }

#define find_lsb(size)  { \
                        size = size & -size; \
                        }
// size_t find_lsb(size_t size) {
//     size = size & -size;
// }

#define set_chunk_size_and_flag(chunk, size, flag) { \
                                    size = (size | 0xf) ^ 0xf; \
                                    *(size_t*)chunk = (size | flag); \
                                    *(size_t*)((uint8_t*)chunk + size - sizeof(size_t)) = (size | flag); \
                                    }
// void set_chunk_size(void* chunk, size_t size) {
//     // 헤더
//     *(size_t*)chunk = size;
//     // 푸터
//     *(size_t*)((uint8_t*)chunk + size - sizeof(size_t)) = size;
// }

#define return_ptr(chunk)   return (uint8_t*)chunk + sizeof(size_t);
// void get_return_ptr(void* chunk, void* return_ptr) {
//     *(size_t*)return_ptr = (uint8_t*)chunk + 0x8;
// }

#define set_chunk_fw(_chunk, _fw) { \
                                ((struct LargeChunk*)_chunk)->fw = _fw; \
                                }
// void set_chunk_fw(void* chunk, size_t fw) {
//     ((struct LargeChunk*)chunk)->fw = fw;
// }

#define set_chunk_bw(_chunk, _bw) { \
                                ((struct LargeChunk*)_chunk)->bw = _bw; \
                                }
// void set_chunk_bw(void* chunk, size_t bw) {
//     ((struct LargeChunk*)chunk)->bw = bw;
// } 

#define pop_singly_linked_list(bin, next_chunk) { \
                                                *(size_t*)bin = (size_t*)next_chunk; \
                                                }
// void set_next_singly_linked_list(void** bin, void* next_chunk) {
//     *(size_t*)bin = (size_t*)next_chunk;
// }

#define pop_doubly_linked_list(bin, next_chunk) { \
                                                *(size_t*)bin = (size_t*)next_chunk; \
                                                if(next_chunk != NULL) ((struct LargeChunk*)next_chunk)->bw = NULL; \
                                                }
// void set_next_doubly_linked_list(void** bin, void* next_chunk) {
//     *(size_t*)bin = (size_t*)next_chunk;
//     ((struct LargeChunk*)next_chunk)->bw = NULL;
// }

#define push_singly_linked_list(bin, new_chunk) { \
                                                void* cur_chunk = *(size_t*)(bin); \
                                                *(size_t*)(bin) = new_chunk; \
                                                if(new_chunk != NULL) ((struct SmallChunk*)new_chunk)->fw = cur_chunk; \
                                                }
// void push_singly_linked_list(void** bin, void* new_chunk) {
//     void* cur_chunk = *(size_t*)(bin);
//     *(size_t*)(bin) = new_chunk;
//     ((struct SmallChunk*)new_chunk)->fw = cur_chunk;
// }

#define push_doubly_linked_list(bin, new_chunk) { \
                                                void* cur_chunk = *(size_t*)(bin); \
                                                *(size_t*)(bin) = new_chunk; \
                                                if(new_chunk != NULL) ((struct LargeChunk*)new_chunk)->fw = cur_chunk; \
                                                if(cur_chunk != NULL) ((struct LargeChunk*)cur_chunk)->bw = new_chunk; \
                                                }
// void push_doubly_linked_list(void** bin, void* new_chunk) {
//     void* cur_chunk = *(size_t*)(bin);
//     *(size_t*)(bin) = new_chunk;
//     ((struct LargeChunk*)new_chunk)->fw = cur_chunk;
//     ((struct LargeChunk*)cur_chunk)->bw = new_chunk;
// }

#define delete_doubly_linked_list(chunk)    { \
                                            void* fw_chunk = ((struct LargeChunk*)chunk)->fw; \
                                            void* bw_chunk = ((struct LargeChunk*)chunk)->bw; \
                                            if(fw_chunk != NULL) ((struct LargeChunk*)fw_chunk)->bw = bw_chunk; \
                                            if(bw_chunk != NULL) ((struct LargeChunk*)bw_chunk)->fw = fw_chunk; \
                                            else { \
                                                size_t idx = *(size_t *)chunk; find_msb(idx); \
                                                large_bins[idx] = fw_chunk; \
                                            } \
                                            }                                           
// void delete_doubly_linked_list(void* chunk) { // chunk
//     void* fw_chunk = ((struct LargeChunk*)chunk)->fw;
//     void* bw_chunk = ((struct LargeChunk*)chunk)->bw;

//     // debug("delete %p\n", chunk);
//     // debug("fw_chunk(??): %p\n", fw_chunk);
//     // debug("bw_chunk(??): %p\n", bw_chunk);

//     // debug("before: ");
//     // debug_large_bin(12);
//     if(fw_chunk != NULL) ((struct LargeChunk*)fw_chunk)->bw = bw_chunk;
//     if(bw_chunk != NULL) ((struct LargeChunk*)bw_chunk)->fw = fw_chunk;
//     else {
//         // bin에서 내용을 지우고 갱신해줘야 함
//         size_t idx = *(size_t *)chunk; find_msb(idx);
//         large_bins[idx] = fw_chunk;
//     }
//     // debug("after: ");
//     // debug_large_bin(12);
// }

void debug_large_bin(size_t idx) {
    struct LargeChunk* start = large_bins[idx];
    while(start) {
        debug("%p(%p) -> ", start, start->size);
        start = start->fw;
    }
    debug("\n");
}

#define get_forward_chunk(chunk) (uint8_t*)chunk - (((*(size_t*)((uint8_t*)chunk - sizeof(size_t))) | 0xf) ^ 0xf);
// void* get_forward_chunk(void* chunk) {
//     size_t forward_chunk_size = *(size_t*)((uint8_t*)chunk - sizeof(size_t));
//     forward_chunk_size = (forward_chunk_size | 0xf) ^ 0xf;
//     return (uint8_t*)chunk - (forward_chunk_size);
// }

#define get_backward_chunk(chunk) (uint8_t*)chunk + (((*(size_t*)chunk) | 0xf) ^ 0xf);
// void* get_backward_chunk(void* chunk) {
//     size_t cur_chunk_size = *(size_t*)chunk;
//     cur_chunk_size = (cur_chunk_size | 0xf) ^ 0xf;
//     return (uint8_t*)chunk + (cur_chunk_size);
// }


void *myalloc(register size_t size)
{
    size = size_normalization(size);
    debug("myalloc size: %p\n", size);

    // 할당 방법은 3가지
    // 1. small_bin
    //   a. 요청 사이즈 크기부터 찾을 때까지 순회
    
    // 2. large_bin
    //   a. 요청 사이즈 크기부터 찾을 때까지 순회

    // 3. topchunk
    //    a. topchunk 사이즈 > 요청 사이즈 => topchunk에서 일부를 내어 줌
    //    b. else => sbrk로 topchunk 증가 후 일부를 내어 줌


    // small_bin에 들어갈 사이즈인지부터 확인
    if(size < SMALL_BIN_SIZE) {
        size_t idx = size >> 4;
        while(idx < SMALL_BIN_NUM && !small_bins[idx]) idx++;
        if(idx < SMALL_BIN_NUM) {
            size_t tmp_size = idx << 4;
            struct SmallChunk* small_chunk = small_bins[idx];
            pop_singly_linked_list(&small_bins[idx], small_chunk->fw); // small_chunk->fw는 NULL 가능
            set_chunk_size_and_flag(small_chunk, tmp_size, USED);
            debug("small_bin alloc(%p): %p\n", size, small_chunk);

            return_ptr(small_chunk);
        }

        // 못 찾았으면 다음 단계로
    }

    // large_bin에 적당한 사이즈 존재 확인
    {
        size_t idx = size; find_msb(idx); // idx++;// msb + 1
        while((idx < LARGE_BIN_NUM && !large_bins[idx]) || ((1 << idx) <= (size + 0x10))) idx++;
        // while((idx < LARGE_BIN_NUM && !large_bins[idx])) idx++;
        // remainder에서 small_bin 사이즈가 0x10이 되지 않도록 마지막 조건 추가

        if(idx < LARGE_BIN_NUM) {
            debug("idx: %p\n", idx);

            // 찾았으니까 사이즈만큼 할당하고 나머지는 bin으로~
            size_t tmp_size = (*(size_t*)large_bins[idx] | 0xf) ^ 0xf;

            struct LargeChunk* large_chunk = large_bins[idx];

            pop_doubly_linked_list(&large_bins[idx], large_chunk->fw); // large_chunk->fw는 NULL 가능
            set_chunk_size_and_flag(large_chunk, size, USED);

            // 나머지는 쪼개기
            void* remainder = (uint8_t*)large_chunk + size;
            size_t remainder_size = tmp_size - size;
            set_chunk_size_and_flag(remainder, remainder_size, USED);

            if(remainder_size < SMALL_BIN_SIZE) {
                debug("small_bin free(%p): %p\n", remainder_size, remainder);

                set_chunk_size_and_flag(remainder, remainder_size, UNUSED);
                set_chunk_fw(remainder, NULL);
                push_singly_linked_list(&small_bins[remainder_size >> 4], remainder);
            }
            else {
                debug("large_bin free(%p): %p\n", remainder_size, remainder);

                size_t _idx = remainder_size; find_msb(_idx);// msb
                set_chunk_size_and_flag(remainder, remainder_size, UNUSED);
                set_chunk_bw(remainder, NULL);
                set_chunk_fw(remainder, NULL);

                push_doubly_linked_list(&large_bins[_idx], remainder);
            }
            
            
            debug("large_bin alloc(%p): %p\n", size, large_chunk);

            return_ptr(large_chunk);
        }

        // 못 찾았으면 다음 단계로
    }


    // topchunk에서 내어 줌
    {
        // topchunk가 없으면
        if(topchunk == NULL) {

            void *p = sbrk(TOPCHUNK_SIZE);
            if(p == NULL) return -1;
            max_size += TOPCHUNK_SIZE;
            limit = p;
            debug("topchunk_init(%p): \n", TOPCHUNK_SIZE);

            topchunk = p;
            // 헤더 푸터 셋팅
            size_t top_size = TOPCHUNK_SIZE;
            set_chunk_size_and_flag(topchunk, top_size ,UNUSED);
            set_chunk_bw(topchunk, NULL);
            set_chunk_fw(topchunk, NULL);
        }

        // topchunk 사이즈가 요청 사이즈보다 작으면
        if(*(size_t*)topchunk < size + 0x20) {

            size_t _size = size > TOPCHUNK_SIZE ? size + 0x20 : TOPCHUNK_SIZE;
            void *p = sbrk(_size);
            if(p == NULL) return -1;
            debug("topchunk_extend(%p): \n", _size);

            max_size += _size;
            // 헤더 푸터 셋팅
            size_t top_size = ((_size + *(size_t*)topchunk) | 0xf) ^ 0xf;
            set_chunk_size_and_flag(topchunk, top_size ,UNUSED);
            set_chunk_bw(topchunk, NULL);
            set_chunk_fw(topchunk, NULL);
        }

        // 떼어주고 topchunk 갱신
        {
            void* cur_chunk = topchunk;
            size_t top_size = *(size_t*)topchunk;
            set_chunk_size_and_flag(cur_chunk, size, USED);

            topchunk = (uint8_t*)cur_chunk + size;
            top_size = top_size - size;

            set_chunk_size_and_flag(topchunk, top_size, UNUSED);
            set_chunk_bw(topchunk, NULL);
            set_chunk_fw(topchunk, NULL);

            debug("topchunk alloc(%p): %p\n", size, cur_chunk);
            return_ptr(cur_chunk);
        }
    }
}

void *myrealloc(void *ptr, size_t size)
{
    if(ptr==NULL) return myalloc(size);
    void *p = myalloc(size);
    if(p) {
        memcpy(p, ptr, size);
        myfree(ptr);
    }
    return p;
}

void myfree(register void* ptr)
{
    if(ptr == NULL) return;

    ptr = ((size_t)ptr | 0xf) ^ 0xf;


    register size_t cur_chunk_size = *(size_t*)ptr;
    debug("free(%p): %p\n", cur_chunk_size, ptr);


    if(cur_chunk_size < SMALL_BIN_SIZE) {
        debug("small_bin free(%p): %p\n", cur_chunk_size, ptr);
        set_chunk_size_and_flag(ptr, cur_chunk_size, UNUSED);
        set_chunk_fw(ptr, NULL);
        push_singly_linked_list(&small_bins[cur_chunk_size >> 4], ptr); // ptr은 NULL 불가능
    }
    else {

        // 앞 뒤 청크들을 보고 병합이 되는지 체크
        void* forward_chunk = NULL;
        if(ptr != limit) forward_chunk = get_forward_chunk(ptr);
        void* backward_chunk = get_backward_chunk(ptr);


        // 앞 뒤 모두 라지 or topchunk면 병합
        size_t forward_size = NULL;
        if(forward_chunk >= limit) forward_size = *(size_t*)forward_chunk;
        else forward_chunk = NULL;
        size_t backward_size = *(size_t*)backward_chunk;
       

        if((forward_size & UNUSED) && (backward_size & UNUSED)) {
            if((forward_size >= SMALL_BIN_SIZE) && (backward_size >= SMALL_BIN_SIZE || backward_chunk == topchunk)) {

                size_t total_size = cur_chunk_size + forward_size + backward_size;
                cur_chunk_size = total_size = (total_size | 0xf) ^ 0xf;
                ptr = (uint8_t*)ptr - ((forward_size | 0xf) ^ 0xf);

                // 연결리스트
                delete_doubly_linked_list(forward_chunk);
                if(backward_chunk != topchunk) delete_doubly_linked_list(backward_chunk);

                set_chunk_size_and_flag(ptr, total_size, UNUSED);
            }
        }
        else if (forward_size & UNUSED) {
            if(forward_size >= SMALL_BIN_SIZE) {

                size_t total_size = cur_chunk_size + forward_size;
                cur_chunk_size = total_size = (total_size | 0xf) ^ 0xf;
                ptr = (uint8_t*)ptr - ((forward_size | 0xf) ^ 0xf);

                delete_doubly_linked_list(forward_chunk);

                set_chunk_size_and_flag(ptr, total_size, UNUSED);
            }
        }
        else if (backward_size & UNUSED) {

            if(backward_size >= SMALL_BIN_SIZE || backward_chunk == topchunk) {
                size_t total_size = cur_chunk_size + backward_size;
                cur_chunk_size = total_size = (total_size | 0xf) ^ 0xf;
                

                if(backward_chunk != topchunk) delete_doubly_linked_list(backward_chunk);

                set_chunk_size_and_flag(ptr, total_size, UNUSED);
            }
        }
        else {
            //
            set_chunk_size_and_flag(ptr, cur_chunk_size, UNUSED);

        }

        // large bin에 넣는 과정
        {
            // topchunk로 병합되었다면

            if(((uint8_t*)ptr + cur_chunk_size) == (limit + max_size)) {
                debug("topchunk free(%p): %p\n", cur_chunk_size, ptr);

                topchunk = ptr;
                set_chunk_bw(ptr, NULL);
                set_chunk_fw(ptr, NULL);
                // set_chunk_size_and_flag(ptr, cur_chunk_size, UNUSED);
                return;
            }
            debug("large_bin free(%p): %p\n", cur_chunk_size, ptr);
            size_t idx = cur_chunk_size; find_msb(idx);// msb
            // set_chunk_size_and_flag(ptr, cur_chunk_size, UNUSED);
            set_chunk_bw(ptr, NULL);
            set_chunk_fw(ptr, NULL);
            push_doubly_linked_list(&large_bins[idx], ptr);
        }


    }

}
