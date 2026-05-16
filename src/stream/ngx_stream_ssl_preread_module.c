
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include <ngx_md5.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
#include <openssl/kdf.h>
#endif

#define REALITY_KEY_SIZE 32
#define REALITY_SHORT_ID_SIZE 8
#define REALITY_AUTH_KEY_SIZE 32
#define REALITY_SESSION_ID_SIZE 32
#define REALITY_RANDOM_SIZE 32

/* Offset of session_id within ClientHello body (no record header):
 *   msg_type(1) + length(3) + version(2) + random(32) + sid_len(1) = 39 */
#define REALITY_PRE_SID_OFFSET 39

#define PROLOGUE_SIZE 32

typedef struct {
    ngx_flag_t      enabled;
    ngx_str_t       reality_key;
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
    u_char          random[REALITY_RANDOM_SIZE];
    ngx_str_t       session_id;
    ngx_str_t       raw;
    ngx_str_t       public_key;
    u_char          reality_short_id[REALITY_SHORT_ID_SIZE];
    ngx_flag_t      reality_decrypted;
} ngx_stream_ssl_preread_ctx_t;

static ngx_int_t
ngx_ssl_ext_cmp(const void *a, const void *b)
{
    u_short va = *(const u_short *) a;
    u_short vb = *(const u_short *) b;

    return (va > vb) - (va < vb);
}

static void
ngx_sort_ext(u_short *ext, size_t size)
{
    if (size <= 1) {
        return;
    }

    ngx_sort(ext, size, sizeof(u_short), ngx_ssl_ext_cmp);
}

/*
 * GREASE (Generate Random Extensions And Sustain Extensibility) values
 * follow the pattern 0xNaNa where N is 0-F (e.g., 0x0a0a, 0x1a1a, ..., 0xfafa)
 * Use bit operations for O(1) lookup instead of array traversal
 */
static int
ngx_ssl_ja3_is_ext_greased(u_short id)
{
    return ((id & 0x0f) == 0x0a) && ((id >> 8) == (id & 0xff));
}

static int
ngx_ssl_ja3_fp(ngx_pool_t *pool, ngx_ssl_ja3_t *ja3, ngx_str_t *out)
{
    size_t   i, total, size, added;
    u_char  *cur;
    u_short  val;

    if (pool == NULL || ja3 == NULL || out == NULL) {
        return 1;
    }

    total = ja3->ciphers_sz + ja3->extensions_sz + ja3->curves_sz + ja3->point_formats_sz;
    if (total == 0) {
        return 2;
    }

    size = (total + 1) * 6 + 16;
    cur = ngx_pnalloc(pool, size);
    if (cur == NULL) {
        return 3;
    }

    out->data = cur;

    /* version */
    cur = ngx_sprintf(cur, "%ud", (ngx_uint_t) ja3->version);
    *cur++ = ',';

    /* ciphers */
    if (ja3->ciphers_sz && ja3->ciphers) {
        added = 0;
        for (i = 0; i < ja3->ciphers_sz; i++) {
            val = ntohs(ja3->ciphers[i]);
            if (ngx_ssl_ja3_is_ext_greased(val)) {
                continue;
            }
            if (added++ > 0) {
                *cur++ = '-';
            }
            cur = ngx_sprintf(cur, "%ud", (ngx_uint_t) val);
        }
    }
    *cur++ = ',';

    /* extensions */
    if (ja3->extensions_sz && ja3->extensions) {
        added = 0;
        for (i = 0; i < ja3->extensions_sz; i++) {
            val = ja3->extensions[i];
            if (ngx_ssl_ja3_is_ext_greased(val)) {
                continue;
            }
            if (added++ > 0) {
                *cur++ = '-';
            }
            cur = ngx_sprintf(cur, "%ud", (ngx_uint_t) val);
        }
    }
    *cur++ = ',';

    /* curves */
    if (ja3->curves_sz && ja3->curves) {
        added = 0;
        for (i = 0; i < ja3->curves_sz; i++) {
            val = ntohs(ja3->curves[i]);
            if (ngx_ssl_ja3_is_ext_greased(val)) {
                continue;
            }
            if (added++ > 0) {
                *cur++ = '-';
            }
            cur = ngx_sprintf(cur, "%ud", (ngx_uint_t) val);
        }
    }
    *cur++ = ',';

    /* point_formats */
    if (ja3->point_formats_sz && ja3->point_formats) {
        for (i = 0; i < ja3->point_formats_sz; i++) {
            if (i > 0) {
                *cur++ = '-';
            }
            cur = ngx_sprintf(cur, "%ud", (ngx_uint_t) ja3->point_formats[i]);
        }
    }

    out->len = cur - out->data;
    return 0;
}

static ngx_int_t
ngx_stream_reality_decrypt_short_id(ngx_stream_ssl_preread_ctx_t *ctx,
    u_char *reality_key, u_char *short_id, u_char *version,
    uint32_t *timestamp, ngx_log_t *log);

static ngx_flag_t is_reality_key_valid(ngx_stream_ssl_preread_srv_conf_t *sscf);
static ngx_int_t ngx_stream_ssl_preread_handler(ngx_stream_session_t *s);
static ngx_int_t ngx_stream_ssl_preread_parse_record(ngx_stream_ssl_preread_srv_conf_t *sscf,
    ngx_stream_ssl_preread_ctx_t *ctx, u_char *pos, u_char *last);
static ngx_int_t ngx_stream_ssl_preread_servername(ngx_stream_session_t *s,
    ngx_str_t *servername);
static ngx_int_t ngx_stream_ssl_preread_protocol_variable(
    ngx_stream_session_t *s, ngx_stream_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_stream_ssl_preread_server_name_variable(
    ngx_stream_session_t *s, ngx_stream_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_stream_ssl_preread_alpn_protocols_variable(
    ngx_stream_session_t *s, ngx_stream_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_stream_ssl_preread_reality_short_id_variable(
    ngx_stream_session_t *s, ngx_stream_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_stream_ssl_preread_add_variables(ngx_conf_t *cf);
static void *ngx_stream_ssl_preread_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_ssl_preread_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_stream_ssl_preread_init(ngx_conf_t *cf);
static char *ngx_stream_ssl_preread(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_stream_ssl_preread_commands[] = {

    { ngx_string("ssl_preread"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_1MORE,
      ngx_stream_ssl_preread,
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
    if (ctx->prologue_sz <= 0) {
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
    if (ngx_ssl_ja3_fp(s->connection->pool, &ctx->ja3, &fp)) {
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

    if (s->connection == NULL) {
        return NGX_OK;
    }

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_ssl_preread_module);
    if (ctx == NULL || !ctx->is_ssl) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (ngx_ssl_ja3_fp(s->connection->pool, &ctx->ja3, &fp)) {
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

    /* REALITY short_id (hex encoded, 16 chars) */
    { ngx_string("ssl_preread_reality_short_id"), NULL,
      ngx_stream_ssl_preread_reality_short_id_variable, 0, 0, 0 },

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
        ngx_str_null(&ctx->raw);
        ngx_str_null(&ctx->public_key);
        ngx_str_null(&ctx->session_id);
        ngx_memzero(ctx->reality_short_id, REALITY_SHORT_ID_SIZE);
        ctx->reality_decrypted = 0;
    }

    p = ctx->pos;
    last = c->buffer->last;
    if (ctx->prologue_sz < PROLOGUE_SIZE) {
        size_t sz = last > p ? ngx_min((size_t) (last - p), PROLOGUE_SIZE) : 0;
        ngx_memcpy(ctx->prologue, p, sz);
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

        rc = ngx_stream_ssl_preread_parse_record(sscf, ctx, p, p + len);

        if (rc == NGX_DECLINED) {
            return NGX_DECLINED;
        }

        if (rc == NGX_OK) {
            ctx->is_ssl = 1;
            if (ctx->ja3.extensions && ctx->ja3.extensions_sz) {
                ngx_sort_ext(ctx->ja3.extensions, ctx->ja3.extensions_sz);
            }

            if (is_reality_key_valid(sscf)) {
                /* save raw ClientHello record (without 5-byte TLS header);
                   only commit len after a successful allocation so downstream
                   code can rely on (data != NULL) iff (len > 0) */
                u_char  *raw_data = ngx_pnalloc(ctx->pool, len);
                if (raw_data != NULL) {
                    ngx_memcpy(raw_data, p, len);
                    ctx->raw.data = raw_data;
                    ctx->raw.len = len;
                }
            }

            if (ctx->log->log_level >= NGX_LOG_DEBUG) {
                u_char  *raw_hex;
                u_char  random_hex[REALITY_RANDOM_SIZE * 2 + 1];
                u_char  session_id_hex[REALITY_SESSION_ID_SIZE * 2 + 1];

                if (ctx->raw.data != NULL && ctx->raw.len > 0) {
                    raw_hex = ngx_pnalloc(ctx->pool, ctx->raw.len * 2 + 1);
                    if (raw_hex != NULL) {
                        ngx_hex_dump(raw_hex, ctx->raw.data, ctx->raw.len);
                        raw_hex[ctx->raw.len * 2] = '\0';

                        ngx_log_debug3(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
                                      "ssl preread: ClientHello parsed successfully, raw.len=%uz, raw=%*s",
                                      ctx->raw.len, ctx->raw.len * 2, raw_hex);
                    }
                } else {
                    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
                                  "ssl preread: ClientHello parsed successfully, raw=(null)");
                }

                ngx_hex_dump(random_hex, ctx->random, REALITY_RANDOM_SIZE);
                random_hex[REALITY_RANDOM_SIZE * 2] = '\0';

                if (ctx->session_id.data != NULL && ctx->session_id.len > 0) {
                    ngx_hex_dump(session_id_hex, ctx->session_id.data, ctx->session_id.len);
                    session_id_hex[ctx->session_id.len * 2] = '\0';

                    ngx_log_debug4(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
                                  "ssl preread: random=%*s, session_id=%*s",
                                  REALITY_RANDOM_SIZE * 2, random_hex,
                                  ctx->session_id.len * 2, session_id_hex);
                } else {
                    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
                                  "ssl preread: random=%*s, session_id=(empty)",
                                  REALITY_RANDOM_SIZE * 2, random_hex);
                }

                if (ctx->public_key.data != NULL && ctx->public_key.len > 0) {
                    u_char  *public_key_hex;
                    public_key_hex = ngx_pnalloc(ctx->pool, ctx->public_key.len * 2 + 1);
                    if (public_key_hex != NULL) {
                        ngx_hex_dump(public_key_hex, ctx->public_key.data, ctx->public_key.len);
                        public_key_hex[ctx->public_key.len * 2] = '\0';

                        ngx_log_debug2(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
                                      "ssl preread: public_key=%*s",
                                      ctx->public_key.len * 2, public_key_hex);
                    }
                }
            } else {
                ngx_log_debug1(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
                              "ssl preread: ClientHello parsed successfully, raw.len=%uz",
                              ctx->raw.len);
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
ngx_stream_ssl_preread_parse_record(ngx_stream_ssl_preread_srv_conf_t *sscf, ngx_stream_ssl_preread_ctx_t *ctx,
    u_char *pos, u_char *last)
{
    size_t   left, n, size, ext;
    u_char  *dst, *p;
    void    *ciphers;

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
        sw_ec_point_formats_len,  /* ec_point_formats length */
        sw_key_share_len,   /* key_share length */
        sw_key_share_entry,  /* key_share entry */
        sw_key_share_skip   /* skip key_share key data */
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
            dst = ctx->random;
            size = REALITY_RANDOM_SIZE;
            break;

        case sw_random:
            state = sw_sid_len;
            dst = p;
            size = 1;
            break;

        case sw_sid_len:
            ctx->session_id.len = p[0];
            state = sw_sid;
            if (ctx->session_id.len > 0 && is_reality_key_valid(sscf)) {
                ctx->session_id.data = ngx_pnalloc(ctx->pool, ctx->session_id.len);
                if (ctx->session_id.data == NULL) {
                    return NGX_ERROR;
                }
                dst = ctx->session_id.data;
            } else {
                dst = NULL;
            }
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
            ciphers = ngx_pnalloc(ctx->pool, size);
            if (ciphers == NULL) {
                return NGX_ERROR;
            }
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

            if (ctx->ja3.extensions_sz == 0 && ctx->ja3.extensions == NULL) {
                size_t ext_size = (p[0] << 8) + p[1];
                /* each extension occupies at least 4 wire bytes (type+len),
                   so capacity in u_short slots is ext_size/4 + 1 for safety */
                ctx->ja3.extensions = ngx_pnalloc(ctx->pool,
                                                  (ext_size / 4 + 1) * sizeof(u_short));
                if (ctx->ja3.extensions == NULL) {
                    return NGX_ERROR;
                }
            }
            state = sw_ext_header;
            dst = p;
            size = 4;
            break;

        case sw_ext_header:
            if (ctx->ja3.extensions) {
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

            if (p[0] == 0 && p[1] == 51 && is_reality_key_valid(sscf)) {
                /* key_share extension (0x0033) */
                state = sw_key_share_len;
                dst = p;
                size = 2;
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
            if (ctx->ja3.curves == NULL) {
                return NGX_ERROR;
            }
            dst = (u_char *) ctx->ja3.curves;
            state = sw_ext;
            break;

        case sw_ec_point_formats_len:
            size = p[0];
            ctx->ja3.point_formats_sz = size;
            ctx->ja3.point_formats = ngx_pnalloc(ctx->pool, size);
            if (ctx->ja3.point_formats == NULL) {
                return NGX_ERROR;
            }
            dst = ctx->ja3.point_formats;
            state = sw_ext;
            break;

        case sw_key_share_len:
            /* ext contains the extension data length, p contains key_share_len */
            ext = (p[0] << 8) + p[1];  /* total key_share list length */
            if (ext >= 4) {
                state = sw_key_share_entry;
                dst = ctx->buf;  /* read 4-byte header into buf */
                size = 4;  /* group(2) + key_len(2) */
            } else {
                /* skip this extension */
                state = sw_ext;
                dst = NULL;
                size = ext;
            }
            break;

        case sw_key_share_entry:
            {
                u_short group = (ctx->buf[0] << 8) + ctx->buf[1];
                u_short key_len = (ctx->buf[2] << 8) + ctx->buf[3];

                ext -= 4;  /* consumed group(2) + key_len(2) */

                if (group == 0x001d && key_len == REALITY_KEY_SIZE && ext >= key_len) {
                    /* X25519 with 32-byte key */
                    ctx->public_key.len = key_len;
                    ctx->public_key.data = ngx_pnalloc(ctx->pool, key_len);
                    if (ctx->public_key.data == NULL) {
                        return NGX_ERROR;
                    }
                    dst = ctx->public_key.data;
                    size = key_len;
                    ext -= key_len;
                    state = sw_ext;
                } else {
                    /* skip this key_share entry */
                    if (ext < key_len) {
                        ngx_log_debug2(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
                                       "ssl preread: key_share entry truncated"
                                       " (key_len=%uD, remaining=%uz)",
                                       (uint32_t) key_len, ext);
                        return NGX_DECLINED;
                    }
                    dst = NULL;
                    size = key_len;
                    ext -= key_len;
                    state = sw_key_share_skip;
                }
            }
            break;

        case sw_key_share_skip:
            /* Just skipped a key, check if there's another entry */
            if (ext >= 4) {
                /* Read next entry header */
                state = sw_key_share_entry;
                dst = ctx->buf;
                size = 4;
            } else {
                /* no more complete entries */
                state = sw_ext;
                dst = NULL;
                size = ext;
            }
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

static ngx_flag_t
is_reality_key_valid(ngx_stream_ssl_preread_srv_conf_t *sscf)
{
    if (sscf->reality_key.data != NULL && sscf->reality_key.len == REALITY_KEY_SIZE) {
        return 1;
    } else {
        return 0;
    }
}

static ngx_int_t
ngx_stream_ssl_preread_reality_short_id_variable(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data)
{
    ngx_stream_ssl_preread_ctx_t       *ctx;
    ngx_stream_ssl_preread_srv_conf_t  *sscf;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_ssl_preread_module);

    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    /* Decrypt on first access */
    if (!ctx->reality_decrypted && ctx->is_ssl) {
        sscf = ngx_stream_get_module_srv_conf(s, ngx_stream_ssl_preread_module);

        if (is_reality_key_valid(sscf)) {
            if (ngx_stream_reality_decrypt_short_id(ctx, sscf->reality_key.data,
                                                    ctx->reality_short_id,
                                                    NULL, NULL,
                                                    s->connection->log) == NGX_OK) {
                ctx->reality_decrypted = 1;
            }
        }
    }

    v->data = ngx_pnalloc(s->connection->pool, REALITY_SHORT_ID_SIZE * 2);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    ngx_hex_dump(v->data, ctx->reality_short_id, REALITY_SHORT_ID_SIZE);
    v->len = REALITY_SHORT_ID_SIZE * 2;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

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
    ngx_str_null(&conf->reality_key);

    return conf;
}


static char *
ngx_stream_ssl_preread_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_stream_ssl_preread_srv_conf_t *prev = parent;
    ngx_stream_ssl_preread_srv_conf_t *conf = child;

    ngx_conf_merge_value(conf->enabled, prev->enabled, 0);
    ngx_conf_merge_str_value(conf->reality_key, prev->reality_key, "");

    return NGX_CONF_OK;
}


static char *
ngx_stream_ssl_preread(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_ssl_preread_srv_conf_t  *sscf = conf;
    ngx_str_t                          *value;
    ngx_uint_t                          i;

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {
        if (ngx_strcmp(value[i].data, "on") == 0) {
            sscf->enabled = 1;
            continue;
        }

        if (ngx_strcmp(value[i].data, "off") == 0) {
            sscf->enabled = 0;
            continue;
        }

        if (ngx_strncmp(value[i].data, "reality=", 8) == 0) {
            ngx_str_t  base64_str, decoded;
            ngx_int_t  rc;

            base64_str.data = value[i].data + 8;
            base64_str.len = value[i].len - 8;

            /* Allocate buffer for decoded data */
            decoded.len = ngx_base64_decoded_length(base64_str.len);
            decoded.data = ngx_pnalloc(cf->pool, decoded.len);
            if (decoded.data == NULL) {
                return NGX_CONF_ERROR;
            }

            /* Decode base64url */
            rc = ngx_decode_base64url(&decoded, &base64_str);
            if (rc != NGX_OK) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                  "invalid base64url encoding in reality parameter");
                return NGX_CONF_ERROR;
            }

            /* Verify decoded length */
            if (decoded.len != REALITY_KEY_SIZE) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                  "reality key must be %uz bytes after base64url decoding (got %uz)",
                                  REALITY_KEY_SIZE, decoded.len);
                return NGX_CONF_ERROR;
            }

            /* Store the decoded key */
            sscf->reality_key = decoded;
            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                          "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }

    if (sscf->enabled == NGX_CONF_UNSET) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                          "\"ssl_preread\" must have \"on\" or \"off\" parameter");
        return NGX_CONF_ERROR;
    }

    /* Never log the reality_key value (it is a private key).  Report only
       whether it is configured so the operator can confirm the directive
       was parsed. */
    ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0,
                      "ssl_preread: enabled=%d, reality_key=%s (len=%uz)",
                      sscf->enabled,
                      (sscf->reality_key.data != NULL
                       && sscf->reality_key.len > 0) ? "set" : "(empty)",
                      sscf->reality_key.len);

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

/*
 * Decrypt REALITY protocol Short ID
 *
 * Parameters:
 *   ctx: SSL preread context (contains random, session_id, raw, public_key)
 *   reality_key: Server private key (32 bytes)
 *   short_id: Output decrypted Short ID (8 bytes)
 *   version: Output version array (3 bytes: major.minor.patch), optional, pass NULL to skip
 *   timestamp: Output timestamp (Unix timestamp), optional, pass NULL to skip
 *   log: nginx log object
 *
 * Returns:
 *   NGX_OK: Decryption successful
 *   NGX_ERROR: Decryption failed
 */
static ngx_int_t
ngx_stream_reality_decrypt_short_id(ngx_stream_ssl_preread_ctx_t *ctx,
    u_char *reality_key, u_char *short_id, u_char *version,
    uint32_t *timestamp, ngx_log_t *log)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    /* X25519 requires OpenSSL 1.1.0+ */
    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, log, 0,
        "reality: X25519 not supported in OpenSSL < 1.1.0");
    ngx_memzero(short_id, REALITY_SHORT_ID_SIZE);
    return NGX_OK;
#else
    EVP_PKEY           *pkey = NULL, *peer_key = NULL;
    EVP_PKEY_CTX       *pctx = NULL, *kctx = NULL;
    EVP_CIPHER_CTX     *cipher_ctx = NULL;
    u_char              shared_secret[REALITY_KEY_SIZE];
    u_char              auth_key[REALITY_AUTH_KEY_SIZE];
    u_char              plaintext[16];
    size_t              shared_len, auth_key_len;
    int                 len, tmplen;
    ngx_int_t           rc = NGX_ERROR;
    const char         *info = "REALITY";

    /* Validate input parameters */
    if (ctx->session_id.len != REALITY_SESSION_ID_SIZE) {
        ngx_log_debug2(NGX_LOG_DEBUG_STREAM, log, 0,
            "reality: invalid session_id length: %uz, expected %d",
            ctx->session_id.len, REALITY_SESSION_ID_SIZE);
        return NGX_ERROR;
    }

    if (ctx->public_key.len != REALITY_KEY_SIZE) {
        ngx_log_debug2(NGX_LOG_DEBUG_STREAM, log, 0,
            "reality: invalid public_key length: %uz, expected %d",
            ctx->public_key.len, REALITY_KEY_SIZE);
        return NGX_ERROR;
    }

    /* 1. X25519 ECDH key exchange */
    pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL,
        reality_key, REALITY_KEY_SIZE);
    if (pkey == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, log, 0,
            "reality: EVP_PKEY_new_raw_private_key() failed");
        goto cleanup;
    }

    peer_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL,
        ctx->public_key.data, ctx->public_key.len);
    if (peer_key == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, log, 0,
            "reality: EVP_PKEY_new_raw_public_key() failed");
        goto cleanup;
    }

    pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (pctx == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, log, 0,
            "reality: EVP_PKEY_CTX_new() failed");
        goto cleanup;
    }

    if (EVP_PKEY_derive_init(pctx) != 1) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, log, 0,
            "reality: EVP_PKEY_derive_init() failed");
        goto cleanup;
    }

    if (EVP_PKEY_derive_set_peer(pctx, peer_key) != 1) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, log, 0,
            "reality: EVP_PKEY_derive_set_peer() failed");
        goto cleanup;
    }

    shared_len = sizeof(shared_secret);
    if (EVP_PKEY_derive(pctx, shared_secret, &shared_len) != 1) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, log, 0,
            "reality: EVP_PKEY_derive() failed");
        goto cleanup;
    }

    /* 2. HKDF-SHA256 key derivation */
    kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (kctx == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, log, 0,
            "reality: EVP_PKEY_CTX_new_id(HKDF) failed");
        goto cleanup;
    }

    if (EVP_PKEY_derive_init(kctx) != 1 ||
        EVP_PKEY_CTX_set_hkdf_md(kctx, EVP_sha256()) != 1 ||
        EVP_PKEY_CTX_set1_hkdf_key(kctx, shared_secret, shared_len) != 1 ||
        EVP_PKEY_CTX_set1_hkdf_salt(kctx, ctx->random, 20) != 1 ||
        EVP_PKEY_CTX_add1_hkdf_info(kctx, (u_char *)info, ngx_strlen(info)) != 1)
    {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, log, 0,
            "reality: HKDF setup failed");
        goto cleanup;
    }

    auth_key_len = REALITY_AUTH_KEY_SIZE;
    if (EVP_PKEY_derive(kctx, auth_key, &auth_key_len) != 1) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, log, 0,
            "reality: HKDF derive failed");
        goto cleanup;
    }

    /* 3. Prepare AAD (Additional Authenticated Data)
     *
     * ClientHello body layout (without 5-byte TLS record header):
     *   msg_type(1) + length(3) + version(2) + random(32) + sid_len(1) = 39
     *   followed by session_id of REALITY_SESSION_ID_SIZE bytes.
     *
     * The AAD is the captured ClientHello with the 32-byte session_id
     * position replaced by zeros.  Build it from three segments so the
     * original ctx->raw is not mutated and can be retried/inspected. */
    if (ctx->raw.data == NULL
        || ctx->raw.len < REALITY_PRE_SID_OFFSET + REALITY_SESSION_ID_SIZE)
    {
        ngx_log_debug2(NGX_LOG_DEBUG_STREAM, log, 0,
            "reality: raw data invalid (data=%p, len=%uz)",
            ctx->raw.data, ctx->raw.len);
        goto cleanup;
    }

    if (ctx->raw.data[REALITY_PRE_SID_OFFSET - 1] != REALITY_SESSION_ID_SIZE) {
        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, log, 0,
            "reality: unexpected session_id length in raw (got %ud)",
            (unsigned) ctx->raw.data[REALITY_PRE_SID_OFFSET - 1]);
        goto cleanup;
    }

    /* 4. AES-256-GCM decryption */
    cipher_ctx = EVP_CIPHER_CTX_new();
    if (cipher_ctx == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, log, 0,
            "reality: EVP_CIPHER_CTX_new() failed");
        goto cleanup;
    }

    if (EVP_DecryptInit_ex(cipher_ctx, EVP_aes_256_gcm(), NULL,
            NULL, NULL) != 1)
    {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, log, 0,
            "reality: EVP_DecryptInit_ex() failed");
        goto cleanup;
    }

    if (EVP_DecryptInit_ex(cipher_ctx, NULL, NULL, auth_key,
            ctx->random + 20) != 1)
    {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, log, 0,
            "reality: EVP_DecryptInit_ex(key, nonce) failed");
        goto cleanup;
    }

    {
        static const u_char  zero_sid[REALITY_SESSION_ID_SIZE] = { 0 };
        size_t               after_sid_off = REALITY_PRE_SID_OFFSET
                                             + REALITY_SESSION_ID_SIZE;

        if (EVP_DecryptUpdate(cipher_ctx, NULL, &len,
                              ctx->raw.data, REALITY_PRE_SID_OFFSET) != 1
            || EVP_DecryptUpdate(cipher_ctx, NULL, &len,
                                 zero_sid, REALITY_SESSION_ID_SIZE) != 1
            || EVP_DecryptUpdate(cipher_ctx, NULL, &len,
                                 ctx->raw.data + after_sid_off,
                                 ctx->raw.len - after_sid_off) != 1)
        {
            ngx_log_debug0(NGX_LOG_DEBUG_STREAM, log, 0,
                "reality: EVP_DecryptUpdate(AAD) failed");
            goto cleanup;
        }
    }

    if (EVP_DecryptUpdate(cipher_ctx, plaintext, &len,
            ctx->session_id.data, REALITY_SESSION_ID_SIZE / 2) != 1)
    {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, log, 0,
            "reality: EVP_DecryptUpdate(ciphertext) failed");
        goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_SET_TAG,
            REALITY_SESSION_ID_SIZE / 2,
            ctx->session_id.data + REALITY_SESSION_ID_SIZE / 2) != 1)
    {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, log, 0,
            "reality: EVP_CIPHER_CTX_ctrl(SET_TAG) failed");
        goto cleanup;
    }

    if (EVP_DecryptFinal_ex(cipher_ctx, plaintext + len, &tmplen) <= 0) {
        if (log->log_level >= NGX_LOG_DEBUG) {
            u_char  *random_hex, *session_id_hex, *raw_hex, *public_key_hex;

            ngx_log_debug0(NGX_LOG_DEBUG_STREAM, log, 0,
                "reality: GCM authentication failed - invalid key or tampered data");

            random_hex = ngx_pnalloc(ctx->pool, REALITY_RANDOM_SIZE * 2 + 1);
            if (random_hex != NULL) {
                ngx_hex_dump(random_hex, ctx->random, REALITY_RANDOM_SIZE);
                random_hex[REALITY_RANDOM_SIZE * 2] = '\0';
                ngx_log_debug2(NGX_LOG_DEBUG_STREAM, log, 0,
                              "reality: random=%*s", REALITY_RANDOM_SIZE * 2, random_hex);
            }

            if (ctx->session_id.data != NULL && ctx->session_id.len > 0) {
                session_id_hex = ngx_pnalloc(ctx->pool, ctx->session_id.len * 2 + 1);
                if (session_id_hex != NULL) {
                    ngx_hex_dump(session_id_hex, ctx->session_id.data, ctx->session_id.len);
                    session_id_hex[ctx->session_id.len * 2] = '\0';
                    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, log, 0,
                                  "reality: session_id=%*s",
                                  ctx->session_id.len * 2, session_id_hex);
                }
            }

            if (ctx->raw.data != NULL && ctx->raw.len > 0) {
                raw_hex = ngx_pnalloc(ctx->pool, ctx->raw.len * 2 + 1);
                if (raw_hex != NULL) {
                    ngx_hex_dump(raw_hex, ctx->raw.data, ctx->raw.len);
                    raw_hex[ctx->raw.len * 2] = '\0';
                    ngx_log_debug3(NGX_LOG_DEBUG_STREAM, log, 0,
                                  "reality: raw.len=%uz, raw=%*s",
                                  ctx->raw.len, ctx->raw.len * 2, raw_hex);
                }
            }

            if (ctx->public_key.data != NULL && ctx->public_key.len > 0) {
                public_key_hex = ngx_pnalloc(ctx->pool, ctx->public_key.len * 2 + 1);
                if (public_key_hex != NULL) {
                    ngx_hex_dump(public_key_hex, ctx->public_key.data, ctx->public_key.len);
                    public_key_hex[ctx->public_key.len * 2] = '\0';
                    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, log, 0,
                                  "reality: public_key=%*s",
                                  ctx->public_key.len * 2, public_key_hex);
                }
            }
        } else {
            ngx_log_debug0(NGX_LOG_DEBUG_STREAM, log, 0,
                "reality: GCM authentication failed - invalid key or tampered data");
        }
        goto cleanup;
    }

    /* 5. Extract data */

    /* Short ID (plaintext bytes [8:16]) */
    ngx_memcpy(short_id, plaintext + 8, REALITY_SHORT_ID_SIZE);

    /* Optional: extract version (plaintext bytes [0:3]) */
    if (version != NULL) {
        version[0] = plaintext[0];  /* major */
        version[1] = plaintext[1];  /* minor */
        version[2] = plaintext[2];  /* patch */
    }

    /* Optional: extract timestamp (plaintext bytes [4:8], Big Endian) */
    if (timestamp != NULL) {
        *timestamp = (plaintext[4] << 24) | (plaintext[5] << 16) |
                     (plaintext[6] << 8) | plaintext[7];
    }

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, log, 0,
        "reality: decryption successful");

    rc = NGX_OK;

cleanup:
    if (cipher_ctx != NULL) {
        EVP_CIPHER_CTX_free(cipher_ctx);
    }
    if (kctx != NULL) {
        EVP_PKEY_CTX_free(kctx);
    }
    if (pctx != NULL) {
        EVP_PKEY_CTX_free(pctx);
    }
    if (peer_key != NULL) {
        EVP_PKEY_free(peer_key);
    }
    if (pkey != NULL) {
        EVP_PKEY_free(pkey);
    }

    /* Clean up sensitive data */
    ngx_memzero(shared_secret, sizeof(shared_secret));
    ngx_memzero(auth_key, sizeof(auth_key));
    ngx_memzero(plaintext, sizeof(plaintext));

    return rc;
#endif  /* OPENSSL_VERSION_NUMBER >= 0x10100000L */
}
