
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include <ngx_md5.h>

#define PROLOGUE_SIZE 32

typedef struct {
    ngx_flag_t      enabled;
} ngx_stream_ssl_preread_srv_conf_t;


typedef struct ngx_ssl_ja3_s {
    u_short         version;
    size_t          ciphers_sz;
    u_short         *ciphers;

    size_t          extensions_sz;
    u_short         *extensions;

    size_t          curves_sz;
    u_short         *curves;

    size_t          point_formats_sz;
    u_char          *point_formats;
} ngx_ssl_ja3_t;


typedef struct {
    size_t          left;
    size_t          size;
    size_t          ext;
    u_char         *pos;
    u_char         *dst;
    u_char          buf[4];
    u_char          version[2];
    ngx_str_t       host;
    ngx_str_t       alpn;
    ngx_log_t      *log;
    ngx_pool_t     *pool;
    ngx_uint_t      state;
    ngx_ssl_ja3_t   ja3;
    u_char          prologue[PROLOGUE_SIZE];
    size_t          prologue_sz;
    ngx_flag_t      is_ssl;
} ngx_stream_ssl_preread_ctx_t;

static void
ngx_sort_ext(u_short *ext, size_t size)
{
    size_t i, j;
    for (i = 0; i < size - 1; i++) {
        for (j = 0; j < size - i - 1; j++) {
            if (ext[j] > ext[j + 1]) {
                u_short tmp = ext[j];
                ext[j] = ext[j + 1];
                ext[j + 1] = tmp;
            }
        }
    }
}

static const u_short GREASE[] = {
    0x0a0a,
    0x1a1a,
    0x2a2a,
    0x3a3a,
    0x4a4a,
    0x5a5a,
    0x6a6a,
    0x7a7a,
    0x8a8a,
    0x9a9a,
    0xaaaa,
    0xbaba,
    0xcaca,
    0xdada,
    0xeaea,
    0xfafa,
};

static int
ngx_ssl_ja3_is_ext_greased(u_short id)
{
    size_t i;
    for (i = 0; i < (sizeof(GREASE) / sizeof(GREASE[0])); ++i) {
        if (id == GREASE[i]) {
            return 1;
        }
    }
    return 0;
}

static int
ngx_ssl_ja3_fp(ngx_pool_t *pool, ngx_ssl_ja3_t *ja3, ngx_str_t *out)
{
    size_t                    i;
    u_char                    *cur = NULL;

    if (pool == NULL || ja3 == NULL || out == NULL) {
        return 1;
    }

    const size_t total = ja3->ciphers_sz + ja3->extensions_sz + ja3->curves_sz + ja3->point_formats_sz;
    if(total <= 0) {
        return 2;
    }
    const size_t size = (total + 1) * 6;
    cur = ngx_pnalloc(pool, size);
    if(cur == NULL) {
        return 3;
    }
    out->data = cur;
    u_char *last = cur + size;

    cur = ngx_slprintf(cur, last, "%d,", ja3->version);

    if (ja3->ciphers_sz && ja3->ciphers) {
        size_t added = 0;
        for (i = 0; i < ja3->ciphers_sz; ++i) {
            u_short cipher = ntohs(ja3->ciphers[i]);
            if(ngx_ssl_ja3_is_ext_greased(cipher)) {
                continue;
            }
            if (added > 0) {
                cur = ngx_slprintf(cur, last, "-");
            }
            cur = ngx_slprintf(cur, last, "%d", cipher);
            added++;
        }
    }
    cur = ngx_slprintf(cur, last, ",");

    if (ja3->extensions_sz && ja3->extensions) {
        size_t added = 0;
        for (i = 0; i < ja3->extensions_sz; i++) {
            u_short extension = ja3->extensions[i];
            if(ngx_ssl_ja3_is_ext_greased(extension)) {
                continue;
            }
            if (added > 0) {
                cur = ngx_slprintf(cur, last, "-");
            }
            cur = ngx_slprintf(cur, last, "%d", extension);
            added++;
        }
    }
    cur = ngx_slprintf(cur, last, ",");

    if (ja3->curves_sz && ja3->curves) {
        size_t added = 0;
        for (i = 0; i < ja3->curves_sz; i++) {
            u_short curve = ntohs(ja3->curves[i]);
            if(ngx_ssl_ja3_is_ext_greased(curve)) {
                continue;
            }
            if (added > 0) {
                cur = ngx_slprintf(cur, last, "-");
            }
            cur = ngx_slprintf(cur, last, "%d", curve);
            added++;
        }
    }
    cur = ngx_slprintf(cur, last, ",");

    if(ja3->point_formats_sz && ja3->point_formats) {
        for (i = 0; i < ja3->point_formats_sz; i++) {
            if (i > 0) {
                cur = ngx_slprintf(cur, last, "-");
            }
            cur = ngx_slprintf(cur, last, "%d", ja3->point_formats[i]);
        }
    }

    out->len = ((size_t) cur) - ((size_t) out->data);
    return 0;
}


static ngx_int_t ngx_stream_ssl_preread_handler(ngx_stream_session_t *s);
static ngx_int_t ngx_stream_ssl_preread_parse_record(
    ngx_stream_ssl_preread_ctx_t *ctx, u_char *pos, u_char *last);
static ngx_int_t ngx_stream_ssl_preread_servername(ngx_stream_session_t *s,
    ngx_str_t *servername);
static ngx_int_t ngx_stream_ssl_preread_protocol_variable(
    ngx_stream_session_t *s, ngx_stream_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_stream_ssl_preread_server_name_variable(
    ngx_stream_session_t *s, ngx_stream_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_stream_ssl_preread_alpn_protocols_variable(
    ngx_stream_session_t *s, ngx_stream_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_stream_ssl_preread_add_variables(ngx_conf_t *cf);
static void *ngx_stream_ssl_preread_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_ssl_preread_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_stream_ssl_preread_init(ngx_conf_t *cf);


static ngx_command_t  ngx_stream_ssl_preread_commands[] = {

    { ngx_string("ssl_preread"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_ssl_preread_srv_conf_t, enabled),
      NULL },

      ngx_null_command
};


static ngx_stream_module_t  ngx_stream_ssl_preread_module_ctx = {
    ngx_stream_ssl_preread_add_variables,   /* preconfiguration */
    ngx_stream_ssl_preread_init,            /* postconfiguration */

    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */

    ngx_stream_ssl_preread_create_srv_conf, /* create server configuration */
    ngx_stream_ssl_preread_merge_srv_conf   /* merge server configuration */
};


ngx_module_t  ngx_stream_ssl_preread_module = {
    NGX_MODULE_V1,
    &ngx_stream_ssl_preread_module_ctx,     /* module context */
    ngx_stream_ssl_preread_commands,        /* module directives */
    NGX_STREAM_MODULE,                      /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t
ngx_stream_ssl_preread_prologue_variable(ngx_stream_session_t *s,
                                         ngx_stream_variable_value_t *v, uintptr_t data)
{
    ngx_stream_ssl_preread_ctx_t  *ctx;

    if (s->connection == NULL) {
        return NGX_OK;
    }

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_ssl_preread_module);
    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }
    if(ctx->prologue_sz <= 0) {
        v->not_found = 1;
        return NGX_OK;
    }
    v->data = ngx_pcalloc(s->connection->pool, PROLOGUE_SIZE * 2);
    if (v->data == NULL) {
        return NGX_ERROR;
    }
    ngx_hex_dump(v->data, ctx->prologue, ctx->prologue_sz);

    v->len = ctx->prologue_sz * 2;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}

static ngx_int_t
ngx_stream_ssl_preread_ja3n_hash_variable(ngx_stream_session_t *s,
        ngx_stream_variable_value_t *v, uintptr_t data)
{
    ngx_stream_ssl_preread_ctx_t  *ctx;
    ngx_str_t                      fp = ngx_null_string;

    ngx_md5_t                      md5_ctx;
    u_char                         hash[16] = {0};

    if (s->connection == NULL) {
        return NGX_OK;
    }

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_ssl_preread_module);
    if (ctx == NULL || !ctx->is_ssl) {
        v->not_found = 1;
        return NGX_OK;
    }
    if(ngx_ssl_ja3_fp(s->connection->pool, &ctx->ja3, &fp)) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = ngx_pcalloc(s->connection->pool, 32);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    ngx_md5_init(&md5_ctx);
    ngx_md5_update(&md5_ctx, fp.data, fp.len);
    ngx_md5_final(hash, &md5_ctx);
    ngx_hex_dump(v->data, hash, 16);

    v->len = 32;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}

static ngx_int_t
ngx_stream_ssl_preread_ja3n_variable(ngx_stream_session_t *s,
        ngx_stream_variable_value_t *v, uintptr_t data)
{
    ngx_stream_ssl_preread_ctx_t  *ctx;
    ngx_str_t                      fp = ngx_null_string;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_ssl_preread_module);
    if (ctx == NULL || !ctx->is_ssl) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (s->connection == NULL) {
        return NGX_OK;
    }

    if(ngx_ssl_ja3_fp(s->connection->pool, &ctx->ja3, &fp)) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = fp.data;
    v->len = fp.len;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_stream_variable_t  ngx_stream_ssl_preread_vars[] = {

    { ngx_string("ssl_preread_protocol"), NULL,
      ngx_stream_ssl_preread_protocol_variable, 0, 0, 0 },

    { ngx_string("ssl_preread_server_name"), NULL,
      ngx_stream_ssl_preread_server_name_variable, 0, 0, 0 },

    { ngx_string("ssl_preread_alpn_protocols"), NULL,
      ngx_stream_ssl_preread_alpn_protocols_variable, 0, 0, 0 },

    { ngx_string("ssl_preread_ja3n_hash"), NULL,
      ngx_stream_ssl_preread_ja3n_hash_variable, 0, 0, 0 },

    { ngx_string("ssl_preread_ja3n"), NULL,
      ngx_stream_ssl_preread_ja3n_variable, 0, 0, 0 },

    { ngx_string("ssl_preread_prologue"), NULL,
      ngx_stream_ssl_preread_prologue_variable, 0, 0, 0 },

      ngx_stream_null_variable
};


static ngx_int_t
ngx_stream_ssl_preread_handler(ngx_stream_session_t *s)
{
    u_char                             *last, *p;
    size_t                              len;
    ngx_int_t                           rc;
    ngx_connection_t                   *c;
    ngx_stream_ssl_preread_ctx_t       *ctx;
    ngx_stream_ssl_preread_srv_conf_t  *sscf;

    c = s->connection;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0, "ssl preread handler");

    sscf = ngx_stream_get_module_srv_conf(s, ngx_stream_ssl_preread_module);

    if (!sscf->enabled) {
        return NGX_DECLINED;
    }

    if (c->type != SOCK_STREAM) {
        return NGX_DECLINED;
    }

    if (c->buffer == NULL) {
        return NGX_AGAIN;
    }

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_ssl_preread_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(c->pool, sizeof(ngx_stream_ssl_preread_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }

        ngx_stream_set_ctx(s, ctx, ngx_stream_ssl_preread_module);

        ctx->pool = c->pool;
        ctx->log = c->log;
        ctx->pos = c->buffer->pos;
    }

    p = ctx->pos;
    last = c->buffer->last;
    if(ctx->prologue_sz < PROLOGUE_SIZE) {
        size_t sz = last > p ? ngx_min((size_t) (last - p), PROLOGUE_SIZE) : 0;
        memcpy(ctx->prologue, p, sz);
        ctx->prologue_sz = sz;
    }

    while (last - p >= 5) {

        if ((p[0] & 0x80) && p[2] == 1 && (p[3] == 0 || p[3] == 3)) {
            ngx_log_debug0(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
                           "ssl preread: version 2 ClientHello");
            ctx->version[0] = p[3];
            ctx->version[1] = p[4];
            ctx->is_ssl = 1;
            return NGX_OK;
        }

        if (p[0] != 0x16) {
            ngx_log_debug0(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
                           "ssl preread: not a handshake");
            return NGX_DECLINED;
        }

        if (p[1] != 3) {
            ngx_log_debug0(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
                           "ssl preread: unsupported SSL version");
            return NGX_DECLINED;
        }

        len = (p[3] << 8) + p[4];

        /* read the whole record before parsing */
        if ((size_t) (last - p) < len + 5) {
            break;
        }

        p += 5;

        rc = ngx_stream_ssl_preread_parse_record(ctx, p, p + len);

        if (rc == NGX_DECLINED) {
            return NGX_DECLINED;
        }

        if (rc == NGX_OK) {
            ctx->is_ssl = 1;
            if(ctx->ja3.extensions && ctx->ja3.extensions_sz) {
                ngx_sort_ext(ctx->ja3.extensions, ctx->ja3.extensions_sz);
            }
            return ngx_stream_ssl_preread_servername(s, &ctx->host);
        }

        if (rc != NGX_AGAIN) {
            return rc;
        }

        p += len;
    }

    ctx->pos = p;

    return NGX_AGAIN;
}


static ngx_int_t
ngx_stream_ssl_preread_parse_record(ngx_stream_ssl_preread_ctx_t *ctx,
    u_char *pos, u_char *last)
{
    size_t   left, n, size, ext;
    u_char  *dst, *p;

    enum {
        sw_start = 0,
        sw_header,          /* handshake msg_type, length */
        sw_version,         /* client_version */
        sw_random,          /* random */
        sw_sid_len,         /* session_id length */
        sw_sid,             /* session_id */
        sw_cs_len,          /* cipher_suites length */
        sw_cs,              /* cipher_suites */
        sw_cm_len,          /* compression_methods length */
        sw_cm,              /* compression_methods */
        sw_ext,             /* extension */
        sw_ext_header,      /* extension_type, extension_data length */
        sw_sni_len,         /* SNI length */
        sw_sni_host_head,   /* SNI name_type, host_name length */
        sw_sni_host,        /* SNI host_name */
        sw_alpn_len,        /* ALPN length */
        sw_alpn_proto_len,  /* ALPN protocol_name length */
        sw_alpn_proto_data, /* ALPN protocol_name */
        sw_supver_len,      /* supported_versions length */
        sw_supported_groups_len, /* supported_groups length */
        sw_ec_point_formats_len  /* ec_point_formats length */
    } state;

    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
                   "ssl preread: state %ui left %z", ctx->state, ctx->left);

    state = ctx->state;
    size = ctx->size;
    left = ctx->left;
    ext = ctx->ext;
    dst = ctx->dst;
    p = ctx->buf;

    for ( ;; ) {
        n = ngx_min((size_t) (last - pos), size);

        if (dst) {
            dst = ngx_cpymem(dst, pos, n);
        }

        pos += n;
        size -= n;
        left -= n;

        if (size != 0) {
            break;
        }

        switch (state) {

        case sw_start:
            ctx->ja3.extensions_sz = 0;
            ctx->ja3.extensions = NULL;
            state = sw_header;
            dst = p;
            size = 4;
            left = size;
            break;

        case sw_header:
            if (p[0] != 1) {
                ngx_log_debug0(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
                               "ssl preread: not a client hello");
                return NGX_DECLINED;
            }

            state = sw_version;
            dst = ctx->version;
            size = 2;
            left = (p[1] << 16) + (p[2] << 8) + p[3];
            break;

        case sw_version:
            ctx->ja3.version = (ctx->version[0] << 8) + ctx->version[1];
            state = sw_random;
            dst = NULL;
            size = 32;
            break;

        case sw_random:
            state = sw_sid_len;
            dst = p;
            size = 1;
            break;

        case sw_sid_len:
            state = sw_sid;
            dst = NULL;
            size = p[0];
            break;

        case sw_sid:
            state = sw_cs_len;
            dst = p;
            size = 2;
            break;

        case sw_cs_len:
            state = sw_cs;
            size = (p[0] << 8) + p[1];
            void *ciphers = ngx_pnalloc(ctx->pool, size);
            dst = ciphers;
            ctx->ja3.ciphers_sz = size / 2;
            ctx->ja3.ciphers = ciphers;
            break;

        case sw_cs:
            state = sw_cm_len;
            dst = p;
            size = 1;
            break;

        case sw_cm_len:
            state = sw_cm;
            dst = NULL;
            size = p[0];
            break;

        case sw_cm:
            if (left == 0) {
                /* no extensions */
                return NGX_OK;
            }

            state = sw_ext;
            dst = p;
            size = 2;
            break;

        case sw_ext:
            if (left == 0) {
                return NGX_OK;
            }

            if(ctx->ja3.extensions_sz == 0 && ctx->ja3.extensions == NULL) {
                size_t ext_size = (p[0] << 8) + p[1];
                ctx->ja3.extensions = ngx_pnalloc(ctx->pool, ext_size);
            }
            state = sw_ext_header;
            dst = p;
            size = 4;
            break;

        case sw_ext_header:
            if(ctx->ja3.extensions) {
                ctx->ja3.extensions[ctx->ja3.extensions_sz++] = (p[0] << 8) + p[1];
            }
            if (p[0] == 0 && p[1] == 0 && ctx->host.data == NULL) {
                /* SNI extension */
                state = sw_sni_len;
                dst = p;
                size = 2;
                break;
            }

            if (p[0] == 0 && p[1] == 16 && ctx->alpn.data == NULL) {
                /* ALPN extension */
                state = sw_alpn_len;
                dst = p;
                size = 2;
                break;
            }

            if (p[0] == 0 && p[1] == 43) {
                /* supported_versions extension */
                state = sw_supver_len;
                dst = p;
                size = 1;
                break;
            }

            if (p[0] == 0 && p[1] == 10) {
                /* supported_groups extension */
                state = sw_supported_groups_len;
                dst = p;
                size = 2;
                break;
            }

            if (p[0] == 0 && p[1] == 11) {
                /* ec_point_formats extension */
                state = sw_ec_point_formats_len;
                dst = p;
                size = 1;
                break;
            }

            state = sw_ext;
            dst = NULL;
            size = (p[2] << 8) + p[3];
            break;

        case sw_supported_groups_len:
            size = (p[0] << 8) + p[1];
            ctx->ja3.curves_sz = size / 2;
            ctx->ja3.curves = ngx_pnalloc(ctx->pool, size);
            dst = (u_char *) ctx->ja3.curves;
            state = sw_ext;
            break;

        case sw_ec_point_formats_len:
            size = p[0];
            ctx->ja3.point_formats_sz = size;
            ctx->ja3.point_formats = ngx_pnalloc(ctx->pool, size);
            dst = ctx->ja3.point_formats;
            state = sw_ext;
            break;

        case sw_sni_len:
            ext = (p[0] << 8) + p[1];
            state = sw_sni_host_head;
            dst = p;
            size = 3;
            break;

        case sw_sni_host_head:
            if (p[0] != 0) {
                ngx_log_debug0(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
                               "ssl preread: SNI hostname type is not DNS");
                return NGX_DECLINED;
            }

            size = (p[1] << 8) + p[2];

            if (ext < 3 + size) {
                ngx_log_debug0(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
                               "ssl preread: SNI format error");
                return NGX_DECLINED;
            }
            ext -= 3 + size;

            ctx->host.data = ngx_pnalloc(ctx->pool, size);
            if (ctx->host.data == NULL) {
                return NGX_ERROR;
            }

            state = sw_sni_host;
            dst = ctx->host.data;
            break;

        case sw_sni_host:
            ctx->host.len = (p[1] << 8) + p[2];

            state = sw_ext;
            dst = NULL;
            size = ext;
            break;

        case sw_alpn_len:
            ext = (p[0] << 8) + p[1];

            ctx->alpn.data = ngx_pnalloc(ctx->pool, ext);
            if (ctx->alpn.data == NULL) {
                return NGX_ERROR;
            }

            state = sw_alpn_proto_len;
            dst = p;
            size = 1;
            break;

        case sw_alpn_proto_len:
            size = p[0];

            if (size == 0) {
                ngx_log_debug0(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
                               "ssl preread: ALPN empty protocol");
                return NGX_DECLINED;
            }

            if (ext < 1 + size) {
                ngx_log_debug0(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
                               "ssl preread: ALPN format error");
                return NGX_DECLINED;
            }
            ext -= 1 + size;

            state = sw_alpn_proto_data;
            dst = ctx->alpn.data + ctx->alpn.len;
            break;

        case sw_alpn_proto_data:
            ctx->alpn.len += p[0];

            ngx_log_debug1(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
                           "ssl preread: ALPN protocols \"%V\"", &ctx->alpn);

            if (ext) {
                ctx->alpn.data[ctx->alpn.len++] = ',';

                state = sw_alpn_proto_len;
                dst = p;
                size = 1;
                break;
            }

            state = sw_ext;
            dst = NULL;
            size = 0;
            break;

        case sw_supver_len:
            ngx_log_debug0(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
                           "ssl preread: supported_versions");

            /* set TLSv1.3 */
            ctx->version[0] = 3;
            ctx->version[1] = 4;

            state = sw_ext;
            dst = NULL;
            size = p[0];
            break;
        }

        if (left < size) {
            ngx_log_debug0(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
                           "ssl preread: failed to parse handshake");
            return NGX_DECLINED;
        }
    }

    ctx->state = state;
    ctx->size = size;
    ctx->left = left;
    ctx->ext = ext;
    ctx->dst = dst;

    return NGX_AGAIN;
}


static ngx_int_t
ngx_stream_ssl_preread_servername(ngx_stream_session_t *s,
    ngx_str_t *servername)
{
    ngx_int_t                    rc;
    ngx_str_t                    host;
    ngx_connection_t            *c;
    ngx_stream_core_srv_conf_t  *cscf;

    c = s->connection;

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "SSL preread server name: \"%V\"", servername);

    if (servername->len == 0) {
        return NGX_OK;
    }

    host = *servername;

    rc = ngx_stream_validate_host(&host, c->pool, 0);

    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (rc == NGX_DECLINED) {
        return NGX_OK;
    }

    rc = ngx_stream_find_virtual_server(s, &host, &cscf);

    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (rc == NGX_DECLINED) {
        return NGX_OK;
    }

    s->srv_conf = cscf->ctx->srv_conf;

    ngx_set_connection_log(c, cscf->error_log);

    return NGX_OK;
}


static ngx_int_t
ngx_stream_ssl_preread_protocol_variable(ngx_stream_session_t *s,
    ngx_variable_value_t *v, uintptr_t data)
{
    ngx_str_t                      version;
    ngx_stream_ssl_preread_ctx_t  *ctx;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_ssl_preread_module);

    if (ctx == NULL || !ctx->is_ssl) {
        v->not_found = 1;
        return NGX_OK;
    }

    /* SSL_get_version() format */

    ngx_str_null(&version);

    switch (ctx->version[0]) {
    case 0:
        switch (ctx->version[1]) {
        case 2:
            ngx_str_set(&version, "SSLv2");
            break;
        }
        break;
    case 3:
        switch (ctx->version[1]) {
        case 0:
            ngx_str_set(&version, "SSLv3");
            break;
        case 1:
            ngx_str_set(&version, "TLSv1");
            break;
        case 2:
            ngx_str_set(&version, "TLSv1.1");
            break;
        case 3:
            ngx_str_set(&version, "TLSv1.2");
            break;
        case 4:
            ngx_str_set(&version, "TLSv1.3");
            break;
        }
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = version.len;
    v->data = version.data;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_ssl_preread_server_name_variable(ngx_stream_session_t *s,
    ngx_variable_value_t *v, uintptr_t data)
{
    ngx_stream_ssl_preread_ctx_t  *ctx;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_ssl_preread_module);

    if (ctx == NULL || !ctx->is_ssl) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = ctx->host.len;
    v->data = ctx->host.data;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_ssl_preread_alpn_protocols_variable(ngx_stream_session_t *s,
    ngx_variable_value_t *v, uintptr_t data)
{
    ngx_stream_ssl_preread_ctx_t  *ctx;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_ssl_preread_module);

    if (ctx == NULL || !ctx->is_ssl) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = ctx->alpn.len;
    v->data = ctx->alpn.data;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_ssl_preread_add_variables(ngx_conf_t *cf)
{
    ngx_stream_variable_t  *var, *v;

    for (v = ngx_stream_ssl_preread_vars; v->name.len; v++) {
        var = ngx_stream_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static void *
ngx_stream_ssl_preread_create_srv_conf(ngx_conf_t *cf)
{
    ngx_stream_ssl_preread_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_ssl_preread_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enabled = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_stream_ssl_preread_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_stream_ssl_preread_srv_conf_t *prev = parent;
    ngx_stream_ssl_preread_srv_conf_t *conf = child;

    ngx_conf_merge_value(conf->enabled, prev->enabled, 0);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_stream_ssl_preread_init(ngx_conf_t *cf)
{
    ngx_stream_handler_pt        *h;
    ngx_stream_core_main_conf_t  *cmcf;

    cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_STREAM_PREREAD_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_stream_ssl_preread_handler;

    return NGX_OK;
}
