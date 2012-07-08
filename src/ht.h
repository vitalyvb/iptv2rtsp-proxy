/* Copyright (c) 2012, Vitaly Bursov <vitaly<AT>bursov.com>
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the author nor the names of its contributors may
 *       be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef HT_H
#define HT_H

#include <stdint.h>
#include <assert.h>
#include "global.h" /* some useful macros*/

typedef uint32_t hthash_value;
typedef hthash_value (*htfunc_hash)(const void *item);
typedef int (*htfunc_cmp)(const void *item1, const void *item2_or_key);
typedef int (*htfunc_cb)(void *item, void *param);

#define HT_CB_CONTINUE (0)
#define HT_CB_ABORT_ITEM_NOT_FREED (-10)
#define HT_CB_ABORT_ITEM_FREED (-11)

struct ht {
    int hashable_offset;
    int po2_size;
    void **hash;
};

struct ht_iterator {
    struct ht *ht;
    int current_bucket;
};

struct hashable {
    hthash_value hash;
    struct hashable *next_hashable;
};

/***************************************************/

int ht_init(struct ht *ht, int initial_size, int hashable_offset);
void ht_destroy(struct ht *ht);

#ifndef HT_INLINE

void ht_insert(struct ht *ht, void *item, htfunc_hash hc);
void *ht_find(struct ht *ht, const void *item_key, htfunc_hash hc, htfunc_cmp cmp);
void *ht_remove(struct ht *ht, const void *item_key, htfunc_hash hc, htfunc_cmp cmp);
int ht_remove_all(struct ht *ht, htfunc_cb cb, void *param);

void ht_iterator_init(struct ht_iterator *iter, struct ht *ht);
void *ht_iterate(struct ht_iterator *iter, void **_hnext, int *buckets_limit);
int ht_iterator_is_bucket_end(struct ht_iterator *iter, void **_hnext);

#else /* HT_INLINE */
# ifndef HT_DECL
#  define HT_DECL static __inline__
# endif


#define HASHABLE_FROM_ITEM(_ht_, _item_)  ((struct hashable *)(((char*)_item_)+((_ht_)->hashable_offset)))
#define ITEM_FROM_HASHABLE(_ht_, _item_)  ((struct hashable *)(((char*)_item_)-((_ht_)->hashable_offset)))
#define BUCKET_FROM_HASHVALUE(_ht_, _value_) ((_value_) & ((_ht_)->po2_size - 1))
#define BUCKET_FROM_HASHABLE(_ht_, _hashable_) BUCKET_FROM_HASHVALUE((_ht_), (_hashable_)->hash)

/* Inserts item to hash table hc using hash function hc.
 */
HT_DECL
void ht_insert(struct ht *ht, void *item, htfunc_hash hc)
{
    struct hashable *h = HASHABLE_FROM_ITEM(ht, item);
    struct hashable *prev;
    int bucket;

    h->hash = hc(item);

    bucket = BUCKET_FROM_HASHABLE(ht, h);

    assert(h->next_hashable == NULL);
    prev = ht->hash[bucket];
    h->next_hashable = prev;
    ht->hash[bucket] = h;
}

/* Searches item in hash table hc.
 * Item is defined by item_key which should be a hashable by hc object.
 * Additionally, if cmd is not NULL it is used to check if item matches key.
 *
 * Returns found item or NULL
 */
HT_DECL
void *ht_find(struct ht *ht, const void *item_key, htfunc_hash hc, htfunc_cmp cmp)
{
    struct hashable *litem;
    hthash_value hash;
    int bucket;

    hash = hc(item_key);

    bucket = BUCKET_FROM_HASHVALUE(ht, hash);
    litem = ht->hash[bucket];

    while (litem){
	if (hash == litem->hash){
	    if (cmp == NULL || (cmp(ITEM_FROM_HASHABLE(ht, litem), item_key) == 0))
		return ITEM_FROM_HASHABLE(ht, litem);
	}
	litem = litem->next_hashable;
    }

    return NULL;
}

/* Removes item from hash table.
 * Arguments are the same as for ht_find().
 *
 * Returns removed item or NULL
 */
HT_DECL
void *ht_remove(struct ht *ht, const void *item_key, htfunc_hash hc, htfunc_cmp cmp)
{
    struct hashable *litem, *lprev = NULL;
    hthash_value hash;
    int bucket;

    hash = hc(item_key);

    bucket = BUCKET_FROM_HASHVALUE(ht, hash);
    litem = ht->hash[bucket];

    while (litem){

	if (hash == litem->hash){
	    if (cmp == NULL || (cmp(ITEM_FROM_HASHABLE(ht, litem), item_key) == 0)){

		if (lprev == NULL){
		    ht->hash[bucket] = litem->next_hashable;
		} else {
		    lprev->next_hashable = litem->next_hashable;
		}
		litem->next_hashable = NULL;

		return ITEM_FROM_HASHABLE(ht, litem);
	    }
	}

	lprev = litem;
	litem = litem->next_hashable;
    }

    return NULL;

}

/* Iterates through hast table and removes all items from it.
 * For every item before it gets removed from ht callback cb()
 * is called.
 *
 * Callback can abort table destuction by returning either
 * HT_CB_ABORT_ITEM_NOT_FREED or HT_CB_ABORT_ITEM_FREED.
 *
 * Function returns last callback's return value or 0
 */
HT_DECL
int ht_remove_all(struct ht *ht, htfunc_cb cb, void *param)
{
    int bucket;
    struct hashable *item, *next;
    int cbres;

    for (bucket=0; bucket<ht->po2_size; bucket++){
	item = ht->hash[bucket];
	while (item){
	    next = item->next_hashable;

	    if (cb != NULL)
		cbres = cb(ITEM_FROM_HASHABLE(ht, item), param);
	    else
		cbres = HT_CB_CONTINUE;

	    /* item can be freed already, do not touch it! */

	    if (likely(cbres == HT_CB_CONTINUE)){
		/* continue */
		ht->hash[bucket] = next;
	    } else if (cbres == HT_CB_ABORT_ITEM_NOT_FREED){
		/* keep item in place */
		return cbres;
	    } else if (cbres == HT_CB_ABORT_ITEM_FREED){
		/* remove item */
		ht->hash[bucket] = next;
		return cbres;
	    } else {
		assert(("invalid callback result", 0));
		/* assume item is freed */
		ht->hash[bucket] = next;
		return cbres;
	    }

	    item = next;
	}
    }

    return 0;
}

/* Initialize hash table iterator
 */
HT_DECL
void ht_iterator_init(struct ht_iterator *iter, struct ht *ht)
{
    iter->ht = ht;
    iter->current_bucket = 0;
}

/* Get next item from hash table. Returned item can be modifed (removed from table),
 * other items must not be modified if current state is not on the bucket boundary.
 *
 * _hnext stores internal state - the next item in current bucket. Because
 * table can be changed during iteration this variable holds "local" state.
 *
 * buckets_limit points to variable to limit number of buckets processed per
 * iterator run.
 */
HT_DECL
void *ht_iterate(struct ht_iterator *iter, void **_hnext, int *buckets_limit)
{
    struct ht *ht = iter->ht;
    struct hashable *hnext = *_hnext;


    while (hnext == NULL) {
	/* start closest non-free bucket */

	if (unlikely(iter->current_bucket >= ht->po2_size)){
	    iter->current_bucket = 0;
	    /* the end */
	    return NULL;
	}

	if (unlikely(buckets_limit && (*buckets_limit <= 0))){
	    /* signal caller to break */
	    return NULL;
	}

	hnext = ht->hash[iter->current_bucket];

	if (hnext == NULL){
	    if (buckets_limit)
		(*buckets_limit)--;
	    iter->current_bucket++;
	}

    }

    if (hnext->next_hashable == NULL){
	/* last item in this bucket */
	if (buckets_limit)
	    *buckets_limit--;
	iter->current_bucket++;
	*_hnext = NULL;
    } else {
	*_hnext = hnext->next_hashable;
    }

    return ITEM_FROM_HASHABLE(ht, hnext);
}

/* Returns true if next item (if any) will be on a bucket boundary.
 * A good place to stop.
 */
HT_DECL
int ht_iterator_is_bucket_end(struct ht_iterator *iter, void **_hnext)
{
    return *_hnext == NULL;
}

#undef HASHABLE_FROM_ITEM
#undef ITEM_FROM_HASHABLE
#undef BUCKET_FROM_HASHVALUE
#undef BUCKET_FROM_HASHABLE

#undef HT_DECL

#endif /* HT_INLINE */

#endif /* HT_H */
