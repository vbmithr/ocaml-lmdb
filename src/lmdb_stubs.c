/* --------------------------------------------------------------------------
   Copyright (c) 2018 Vincent Bernardoff. All rights reserved.
   Distributed under the ISC license, see terms at the end of the file.
  --------------------------------------------------------------------------- */

#include <string.h>

#include <caml/mlvalues.h>
#include <caml/alloc.h>
#include <caml/memory.h>
#include <caml/bigarray.h>

#include "lmdb.h"

CAMLprim value stub_mdb_version(value unit) {
    CAMLparam1(unit);
    CAMLlocal1(result);

    int major, minor, patch;
    mdb_version(&major, &minor, &patch);
    result = caml_alloc_tuple(3);
    Store_field(result, 0, Val_int(major));
    Store_field(result, 1, Val_int(minor));
    Store_field(result, 2, Val_int(patch));

    CAMLreturn(result);
}

CAMLprim value stub_mdb_strerror(value errno) {
    CAMLparam1(errno);
    CAMLlocal1(result);

    char *errstr;
    errstr = mdb_strerror(Int_val(errno));
    result = caml_copy_string(errstr);

    CAMLreturn(result);
}

CAMLprim value stub_mdb_env_create(value unit) {
    CAMLparam1(unit);
    CAMLlocal1(result);

    int ret;
    MDB_env *env;

    ret = mdb_env_create(&env);
    if (ret) {
        result = caml_alloc(1, 1);
        Store_field(result, 0, Val_int(ret));
    }
    else {
        result = caml_alloc(1, 0);
        Store_field(result, 0, (value) env);
    }

    CAMLreturn(result);
}

CAMLprim value stub_mdb_env_open(value env, value path, value flags, value mode) {
    return Val_int(mdb_env_open((MDB_env *) env, String_val(path), Int_val(flags), Int_val(mode)));
}

CAMLprim value stub_mdb_env_close(value env) {
    mdb_env_close((MDB_env *) env);
    return Val_unit;
}

CAMLprim value stub_mdb_env_copy2(value env, value path, value flags) {
    return Val_int(mdb_env_copy2((MDB_env *) env, String_val(path), Int_val(flags)));
}

CAMLprim value stub_mdb_env_copyfd2(value env, value fd, value flags) {
    return Val_int(mdb_env_copyfd2((MDB_env *) env, Int_val(fd), Int_val(flags)));
}

static void caml_mdb_stat(value result, const MDB_stat *stat) {
    Store_field(result, 0, Val_int(stat->ms_psize));
    Store_field(result, 1, Val_int(stat->ms_depth));
    Store_field(result, 2, Val_long(stat->ms_branch_pages));
    Store_field(result, 3, Val_long(stat->ms_leaf_pages));
    Store_field(result, 4, Val_long(stat->ms_overflow_pages));
    Store_field(result, 5, Val_long(stat->ms_entries));
}

CAMLprim value stub_mdb_env_stat(value env) {
    CAMLparam1(env);
    CAMLlocal1(result);

    MDB_stat stat;
    mdb_env_stat((MDB_env *) env, &stat);
    result = caml_alloc_tuple(6);
    caml_mdb_stat(result, &stat);
    CAMLreturn(result);
}

CAMLprim value stub_mdb_env_info(value env) {
    CAMLparam1(env);
    CAMLlocal1(result);

    MDB_envinfo info;
    mdb_env_info((MDB_env *) env, &info);
    result = caml_alloc_tuple(5);

    Store_field(result, 0, Val_long(info.me_mapsize));
    Store_field(result, 1, Val_long(info.me_last_pgno));
    Store_field(result, 2, Val_long(info.me_last_txnid));
    Store_field(result, 3, Val_int(info.me_maxreaders));
    Store_field(result, 4, Val_int(info.me_numreaders));

    CAMLreturn(result);
}

CAMLprim value stub_mdb_env_sync(value env, value force) {
    return Val_int(mdb_env_sync((MDB_env *) env, Bool_val(force)));
}

CAMLprim value stub_mdb_env_set_flags(value env, value flags, value onoff) {
    return Val_int(mdb_env_set_flags((MDB_env *) env, Int_val(flags), Bool_val(onoff)));
}

CAMLprim value stub_mdb_env_get_flags(value env) {
    int flags;
    mdb_env_get_flags((MDB_env *) env, &flags);
    return Val_int(flags);
}

CAMLprim value stub_mdb_env_get_path(value env) {
    CAMLparam1(env);
    CAMLlocal1(result);

    const char *path;
    mdb_env_get_path((MDB_env *) env, &path);
    result = caml_copy_string(path);

    CAMLreturn(result);
}

CAMLprim value stub_mdb_env_get_fd(value env) {
    mdb_filehandle_t fd;
    mdb_env_get_fd((MDB_env *) env, &fd);
    return Val_int(fd);
}

CAMLprim value stub_mdb_env_set_mapsize(value env, value size) {
    return Val_int(mdb_env_set_mapsize((MDB_env *) env, Int64_val(size)));
}

CAMLprim value stub_mdb_env_set_maxreaders(value env, value readers) {
    return Val_int(mdb_env_set_maxreaders((MDB_env *) env, Int_val(readers)));
}

CAMLprim value stub_mdb_env_get_maxreaders(value env) {
    unsigned int readers;
    mdb_env_get_maxreaders((MDB_env *) env, &readers);
    return Val_int(readers);
}

CAMLprim value stub_mdb_env_set_maxdbs(value env, value dbs) {
    return Val_int(mdb_env_set_maxdbs((MDB_env *) env, Int_val(dbs)));
}

CAMLprim value stub_mdb_env_get_maxkeysize(value env) {
    return Val_int(mdb_env_get_maxkeysize((MDB_env *) env));
}

CAMLprim value stub_mdb_txn_begin(value env, value flags, value parent) {
    CAMLparam3(env, flags, parent);
    CAMLlocal1(result);

    int ret;
    MDB_txn *parent_txn = Is_block(parent) ? (MDB_txn *) Field(parent, 0) : NULL;
    MDB_txn *new_txn;

    ret = mdb_txn_begin((MDB_env *) env, parent_txn, Int_val(flags), &new_txn);

    if (ret) {
        result = caml_alloc(1, 1);
        Store_field(result, 0, Val_int(ret));
    }
    else {
        result = caml_alloc(1, 0);
        Store_field(result, 0, (value) new_txn);
    }

    CAMLreturn(result);
}

CAMLprim value stub_mdb_txn_env(value txn) {
    return (value) mdb_txn_env((MDB_txn *) txn);
}

CAMLprim value stub_mdb_txn_id(value txn) {
    return Val_long(mdb_txn_id((MDB_txn *) txn));
}

CAMLprim value stub_mdb_txn_commit(value txn) {
    return Val_int(mdb_txn_commit((MDB_txn *) txn));
}

CAMLprim value stub_mdb_txn_abort(value txn) {
    mdb_txn_abort((MDB_txn *) txn);
    return Val_unit;
}

CAMLprim value stub_mdb_txn_reset(value txn) {
    mdb_txn_reset((MDB_txn *) txn);
    return Val_unit;
}

CAMLprim value stub_mdb_txn_renew(value txn) {
    return Val_int(mdb_txn_renew((MDB_txn *) txn));
}

CAMLprim value stub_mdb_dbi_open(value txn, value name, value flags) {
    CAMLparam3(txn, name, flags);
    CAMLlocal1(result);

    MDB_dbi dbi;
    int ret;
    const char* db_name = NULL;

    if (caml_string_length(name) > 0)
        db_name = String_val(name);

    ret = mdb_dbi_open((MDB_txn *) txn, db_name, Int_val(flags), &dbi);

    if (ret) {
        result = caml_alloc(1, 1);
        Store_field(result, 0, Val_int(ret));
    }
    else {
        result = caml_alloc(1, 0);
        Store_field(result, 0, Val_int(dbi));
    }

    CAMLreturn(result);
}

CAMLprim value stub_mdb_stat(value txn, value dbi) {
    CAMLparam2(txn, dbi);
    CAMLlocal2(result, tuple);

    MDB_stat stat;
    int ret;
    ret = mdb_stat((MDB_txn *) txn, Int_val(dbi), &stat);

    if (ret) {
        result = caml_alloc(1, 1);
        Store_field(result, 0, Val_int(ret));
    }
    else {
        result = caml_alloc(1, 0);
        tuple = caml_alloc_tuple(6);
        caml_mdb_stat(tuple, &stat);
        Store_field(result, 0, tuple);
    }

    CAMLreturn(result);
}

CAMLprim value stub_mdb_dbi_flags(value txn, value dbi) {
    CAMLparam2(txn, dbi);
    CAMLlocal1(result);

    unsigned int flags;
    int ret;
    ret = mdb_dbi_flags((MDB_txn *) txn, Int_val(dbi), &flags);

    if (ret) {
        result = caml_alloc(1, 1);
        Store_field(result, 0, Val_int(ret));
    }
    else {
        result = caml_alloc(1, 0);
        Store_field(result, 0, Val_int(flags));
    }

    CAMLreturn(result);
}

CAMLprim value stub_mdb_dbi_close(value env, value dbi) {
    mdb_dbi_close((MDB_env *) env, Int_val(dbi));
    return Val_unit;
}

CAMLprim value stub_mdb_drop(value txn, value dbi, value del) {
    return Val_int(mdb_drop((MDB_txn *) txn, Int_val(dbi), Bool_val(del)));
}

static inline value alloc_mdb_val_ba (MDB_val *v) {
    return
        (v ?
         caml_ba_alloc_dims(CAML_BA_UINT8 | CAML_BA_C_LAYOUT, 1, v->mv_data, v->mv_size) :
         caml_ba_alloc_dims(CAML_BA_UINT8 | CAML_BA_C_LAYOUT, 1, NULL, 0));
}

CAMLprim value stub_mdb_get(value txn, value dbi, value key) {
    CAMLparam3(txn, dbi, key);
    CAMLlocal1(result);

    MDB_val k, v;
    int ret;

    k.mv_size = caml_string_length(key);
    k.mv_data = String_val(key);

    ret = mdb_get((MDB_txn *) txn, Int_val(dbi), &k, &v);
    if (ret) {
        result = caml_alloc(1, 1);
        Store_field(result, 0, Val_int(ret));
    }
    else {
        result = caml_alloc(1, 0);
        Store_field(result, 0, alloc_mdb_val_ba(&v));
    }

    CAMLreturn(result);
}

CAMLprim value stub_mdb_put(value txn, value dbi,
                            value key, value data, value flags) {
    MDB_val k, v;
    k.mv_size = caml_string_length(key);
    k.mv_data = String_val(key);
    v.mv_size = Caml_ba_array_val(data)->dim[0];
    v.mv_data = Caml_ba_data_val(data);
    return Val_int(mdb_put((MDB_txn *) txn, Int_val(dbi), &k, &v, Int_val(flags)));
}

CAMLprim value stub_mdb_put_string(value txn, value dbi,
                                   value key, value data, value flags) {
    MDB_val k, v;
    k.mv_size = caml_string_length(key);
    k.mv_data = String_val(key);
    v.mv_size = caml_string_length(data);
    v.mv_data = String_val(data);
    return Val_int(mdb_put((MDB_txn *) txn, Int_val(dbi), &k, &v, Int_val(flags)));
}

CAMLprim value stub_mdb_del(value txn, value dbi, value key, value data) {
    MDB_val k, v, *vp = NULL;
    k.mv_size = caml_string_length(key);
    k.mv_data = String_val(key);

    if (Caml_ba_array_val(data)->dim[0] > 0) {
        v.mv_size = Caml_ba_array_val(data)->dim[0];
        v.mv_data = Caml_ba_data_val(data);
        vp = &v;
    }

    return Val_int(mdb_del((MDB_txn *) txn, Int_val(dbi), &k, vp));
}

CAMLprim value stub_mdb_del_string(value txn, value dbi, value key, value data) {
    MDB_val k, v, *vp = NULL;
    k.mv_size = caml_string_length(key);
    k.mv_data = String_val(key);

    if (caml_string_length(data) > 0) {
        v.mv_size = caml_string_length(data);
        v.mv_data = String_val(data);
        vp = &v;
    }

    return Val_int(mdb_del((MDB_txn *) txn, Int_val(dbi), &k, vp));
}

CAMLprim value stub_mdb_cursor_open(value txn, value dbi) {
    CAMLparam2(txn, dbi);
    CAMLlocal1(result);

    MDB_cursor *cursor;
    int ret;
    ret = mdb_cursor_open((MDB_txn *) txn, Int_val(dbi), &cursor);

    if (ret) {
        result = caml_alloc(1, 1);
        Store_field(result, 0, Val_int(ret));
    }
    else {
        result = caml_alloc(1, 0);
        Store_field(result, 0, (value) cursor);
    }

    CAMLreturn(result);
}

CAMLprim value stub_mdb_cursor_close(value cursor) {
    mdb_cursor_close((MDB_cursor *) cursor);
    return Val_unit;
}

CAMLprim value stub_mdb_cursor_renew(value txn, value cursor) {
    return Val_int(mdb_cursor_renew((MDB_txn *) txn, (MDB_cursor *) cursor));
}

CAMLprim value stub_mdb_cursor_txn(value cursor) {
    return (value) mdb_cursor_txn((MDB_cursor *) cursor);
}

CAMLprim value stub_mdb_cursor_dbi(value cursor) {
    return Val_int(mdb_cursor_dbi((MDB_cursor *) cursor));
}

CAMLprim value stub_mdb_cursor_get(value cursor, value key, value data, value op) {
    CAMLparam4(cursor, key, data, op);
    CAMLlocal2(result, tuple);

    MDB_val k, v;
    int ret;

    if (caml_string_length(key) > 0) {
        k.mv_size = caml_string_length(key);
        k.mv_data = String_val(key);
    }

    if (Caml_ba_array_val(data)->dim[0] > 0) {
        v.mv_size = Caml_ba_array_val(data)->dim[0];
        v.mv_data = Caml_ba_data_val(data);
    }

    ret = mdb_cursor_get((MDB_cursor *) cursor, &k, &v, Int_val(op));
    if (ret) {
        result = caml_alloc(1, 1);
        Store_field(result, 0, Val_int(ret));
    }
    else {
        result = caml_alloc(1, 0);
        tuple = caml_alloc_tuple(2);
        Store_field(tuple, 0, alloc_mdb_val_ba(&k));
        Store_field(tuple, 1, alloc_mdb_val_ba(&v));
        Store_field(result, 0, tuple);
    }

    CAMLreturn(result);
}

CAMLprim value stub_mdb_cursor_get_string(value cursor, value key, value data, value op) {
    CAMLparam4(cursor, key, data, op);
    CAMLlocal2(result, tuple);

    MDB_val k, v;
    int ret;

    if (caml_string_length(key) > 0) {
        k.mv_size = caml_string_length(key);
        k.mv_data = String_val(key);
    }

    if (caml_string_length(data) > 0) {
        v.mv_size = caml_string_length(data);
        v.mv_data = String_val(data);
    }

    ret = mdb_cursor_get((MDB_cursor *) cursor, &k, &v, Int_val(op));
    if (ret) {
        result = caml_alloc(1, 1);
        Store_field(result, 0, Val_int(ret));
    }
    else {
        result = caml_alloc(1, 0);
        tuple = caml_alloc_tuple(2);
        Store_field(tuple, 0, alloc_mdb_val_ba(&k));
        Store_field(tuple, 1, alloc_mdb_val_ba(&v));
        Store_field(result, 0, tuple);
    }

    CAMLreturn(result);
}

CAMLprim value stub_mdb_cursor_put(value cursor, value key, value data, value flags) {
    MDB_val k, v;
    k.mv_size = caml_string_length(key);
    k.mv_data = String_val(key);
    v.mv_size = Caml_ba_array_val(data)->dim[0];
    v.mv_data = Caml_ba_data_val(data);
    return Val_int(mdb_cursor_put((MDB_cursor *) cursor, &k, &v, Int_val(flags)));
}

CAMLprim value stub_mdb_cursor_put_string(value cursor, value key, value data, value flags) {
    MDB_val k, v;
    k.mv_size = caml_string_length(key);
    k.mv_data = String_val(key);
    v.mv_size = caml_string_length(data);
    v.mv_data = String_val(data);
    return Val_int(mdb_cursor_put((MDB_cursor *) cursor, &k, &v, Int_val(flags)));
}

CAMLprim value stub_mdb_cursor_del(value cursor, value flags) {
    return Val_int(mdb_cursor_del((MDB_cursor *) cursor, Int_val(flags)));
}

CAMLprim value stub_mdb_cursor_count(value cursor) {
    CAMLparam1(cursor);
    CAMLlocal1(result);

    mdb_size_t count;
    int ret;

    ret = mdb_cursor_count((MDB_cursor *) cursor, &count);
    if (ret) {
        result = caml_alloc(1, 1);
        Store_field(result, 0, Val_int(ret));
    }
    else {
        result = caml_alloc(1, 0);
        Store_field(result, 0, Val_long(count));
    }

    CAMLreturn(result);
}

/* --------------------------------------------------------------------------
   Copyright (c) 2018 Vincent Bernardoff

   Permission to use, copy, modify, and/or distribute this software for any
   purpose with or without fee is hereby granted, provided that the above
   copyright notice and this permission notice appear in all copies.

   THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
   WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
   MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
   ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
   WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
   ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
   OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
  --------------------------------------------------------------------------- */
