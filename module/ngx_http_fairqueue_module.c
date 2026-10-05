/*
 * ngx_http_fairqueue_module.c
 *
 * FairQueue: a fair virtual waiting room / admission-control module for nginx.
 *
 * A protected location admits visitors at a configured rate. Each participant
 * is assigned a deterministic, unpredictable slot derived from a keyed hash of
 * its device identity, projected over the live population. Admission is gated by
 * a cursor that advances with wall-clock time, so a request is let through to
 * the backend only when its slot falls at or before the cursor; otherwise it is
 * redirected to a waiting page. Arrival time does not influence the slot, so raw
 * request speed confers no advantage; abusive volume is turned into cost through
 * a per-IP device cap and a pluggable risk signal.
 *
 * State (participants and per-IP counters) lives in a shared-memory zone backed
 * by a slab pool, an rbtree keyed by a crc32 of the identity, and an LRU queue
 * that bounds memory and keeps the active-participant count current.
 *
 * Directives (http: fairqueue_zone; location: the rest):
 *   fairqueue_zone zone=NAME:SIZE [rate=Nr/m]
 *   fairqueue NAME | on | off
 *   fairqueue_status
 *   fairqueue_secret <str>              fairqueue_scope <str>
 *   fairqueue_rate 500r/m               fairqueue_start <epoch>
 *   fairqueue_waiting_start <epoch>     fairqueue_waiting_uri <uri>
 *   fairqueue_token_ttl <sec>           fairqueue_penalty <0..1>
 *   fairqueue_aging <pos/sec>           fairqueue_aging_cap <0..1 of window>
 *   fairqueue_window_headroom <0..1>    fairqueue_allocation hash|fifo
 *   fairqueue_risk_header <name>        fairqueue_risk_weight <0..1>
 *   fairqueue_max_devices_per_ip <n>    fairqueue_trust_xff on|off
 *   fairqueue_cookie_secure on|off
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_sha1.h>


/* Fractions (penalty, aging, headroom, risk) are stored in per-mille because
 * nginx directives carry no floating-point type: 0.02 -> 20. */
#define NGX_FQ_PERMILLE    1000

/* Admission rate is stored as requests-per-second scaled by 1000. */
#define NGX_FQ_RATE_SCALE  1000

/* A participant or IP node is evicted after this many seconds of inactivity. */
#ifndef NGX_FQ_NODE_TTL
#define NGX_FQ_NODE_TTL    3600
#endif


/* ------------------------------------------------------------------------- */
/* Shared-memory state                                                       */
/* ------------------------------------------------------------------------- */

/*
 * One node of either the participant rbtree or the per-IP rbtree. The embedded
 * rbtree node carries a crc32 of the key; the first `len` bytes of `data` are
 * the key, so colliding hashes are disambiguated by exact comparison and both
 * trees share the lookup/insert code. The queue link orders nodes by recency
 * for LRU eviction.
 *
 * Participant nodes: `rank` is the arrival index (fifo strategy) and the node
 * remembers the IP it was counted against (`ip_hash` and the `iplen` bytes that
 * follow the key in `data`) so eviction can decrement that IP's counter.
 *
 * IP nodes: `count` is the number of currently-active devices from the address.
 */
typedef struct {
    ngx_rbtree_node_t   node;
    ngx_queue_t         queue;
    time_t              first_seen;
    time_t              last_seen;
    ngx_uint_t          count;      /* IP nodes: active devices from this IP */
    ngx_uint_t          rank;       /* participant nodes: arrival index      */
    ngx_uint_t          ip_hash;    /* participant nodes: crc32 of the IP    */
    u_short             len;        /* key length (device id or IP)          */
    u_short             iplen;      /* participant nodes: trailing IP length */
    u_char              data[1];    /* key bytes; participants append the IP */
} ngx_http_fq_node_t;

typedef struct {
    ngx_rbtree_t        rbtree;      /* participants (devices)   */
    ngx_rbtree_node_t   sentinel;
    ngx_queue_t         queue;       /* participant LRU          */
    ngx_atomic_t        n;           /* active participant count */

    ngx_rbtree_t        iprbtree;    /* devices-per-IP counters; a node lives    */
    ngx_rbtree_node_t   ipsentinel;  /* exactly while it has >= 1 active device,  */
                                     /* so it needs no LRU of its own.            */
} ngx_http_fq_shctx_t;

typedef struct {
    ngx_http_fq_shctx_t *sh;
    ngx_slab_pool_t     *shpool;
    ngx_uint_t           rate;       /* zone default rate (req/s * 1000) */
} ngx_http_fq_ctx_t;

/* Outcome of an admission evaluation, shared by the gate and the status view. */
typedef struct {
    double      position;
    double      cursor;
    ngx_uint_t  total;      /* active participants */
    ngx_int_t   started;    /* now >= sale start   */
    ngx_int_t   admitted;
    time_t      sale_in;    /* seconds until the sale starts */
    double      eta;        /* estimated seconds until admission */
} ngx_http_fq_eval_t;


/* ------------------------------------------------------------------------- */
/* Per-location configuration                                                */
/* ------------------------------------------------------------------------- */

typedef struct {
    ngx_flag_t       enable;
    ngx_shm_zone_t  *shm_zone;

    ngx_uint_t       rate;              /* req/s * 1000 */
    time_t           start;            /* sale start (epoch) */
    time_t           waiting_start;    /* registration opens (epoch); 0 = always */
    ngx_uint_t       token_ttl;        /* seconds */

    ngx_uint_t       penalty;          /* per-mille of N */
    ngx_uint_t       aging;            /* positions/sec * 1000 */
    ngx_uint_t       aging_cap;        /* per-mille of the window */
    ngx_uint_t       headroom;         /* per-mille */

    ngx_uint_t       allocation;       /* 0 = hash, 1 = fifo */
    ngx_str_t        scope;
    ngx_str_t        secret;

    ngx_str_t        risk_header;
    ngx_uint_t       risk_weight;      /* per-mille of N */

    ngx_uint_t       max_devices_per_ip;
    ngx_flag_t       trust_xff;
    ngx_flag_t       cookie_secure;

    ngx_str_t        waiting_uri;

    ngx_flag_t       is_status;        /* this location serves the status view */
} ngx_http_fairqueue_loc_conf_t;


/* ------------------------------------------------------------------------- */
/* Forward declarations                                                      */
/* ------------------------------------------------------------------------- */

static ngx_int_t ngx_http_fairqueue_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_fairqueue_init(ngx_conf_t *cf);
static void *ngx_http_fairqueue_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_fairqueue_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);

static char *ngx_http_fairqueue_enable(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_fairqueue_set_rate(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_fairqueue_set_permille(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_fairqueue_set_alloc(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_fairqueue_zone(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_fairqueue_status(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static ngx_int_t ngx_http_fq_init_zone(ngx_shm_zone_t *shm_zone, void *data);
static void ngx_http_fq_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
static ngx_http_fq_node_t *ngx_http_fq_rb_lookup(ngx_rbtree_t *tree,
    ngx_uint_t hash, u_char *data, size_t len);
static void ngx_http_fq_expire_devices(ngx_http_fq_ctx_t *ctx, time_t now,
    ngx_uint_t force);
static ngx_uint_t ngx_http_fq_ip_touch(ngx_http_fq_ctx_t *ctx, u_char *ip,
    size_t iplen, time_t now, ngx_int_t create, ngx_uint_t cap,
    ngx_int_t *limited);
static time_t ngx_http_fq_register(ngx_http_fq_ctx_t *ctx, u_char *devid,
    size_t devlen, u_char *ip, size_t iplen, ngx_uint_t cap, time_t now,
    ngx_uint_t *n_out, ngx_uint_t *rank_out, ngx_uint_t *ip_devices_out,
    ngx_int_t *limited);
static ngx_int_t ngx_http_fq_peek(ngx_http_fq_ctx_t *ctx, u_char *devid,
    size_t devlen, u_char *ip, size_t iplen, time_t *first_seen, ngx_uint_t *N,
    ngx_uint_t *rank, ngx_uint_t *ip_devices);

static void ngx_http_fq_hmac_sha1(u_char *key, size_t klen, u_char *data,
    size_t dlen, u_char out[20]);
static void ngx_http_fq_hmac_hex(ngx_str_t *secret, u_char *data, size_t dlen,
    u_char out[40]);
static ngx_int_t ngx_http_fq_ct_eq(u_char *a, u_char *b, size_t n);
static void ngx_http_fq_new_id(ngx_pool_t *pool, ngx_str_t *out);
static ngx_int_t ngx_http_fq_get_cookie(ngx_http_request_t *r, ngx_str_t *name,
    ngx_str_t *val);
static ngx_int_t ngx_http_fq_add_set_cookie(ngx_http_request_t *r,
    ngx_str_t *cookie);
static ngx_int_t ngx_http_fq_sign_value(ngx_pool_t *pool, ngx_str_t *secret,
    const char *prefix, ngx_str_t *rid, ngx_str_t *out);
static ngx_int_t ngx_http_fq_verify_cookie(ngx_http_request_t *r,
    ngx_str_t *secret, ngx_str_t *cookiename, const char *prefix, ngx_str_t *rid);
static ngx_int_t ngx_http_fq_set_signed_cookie(ngx_http_request_t *r,
    ngx_http_fairqueue_loc_conf_t *flcf, const char *name, const char *prefix,
    ngx_str_t *rid, time_t max_age);
static void ngx_http_fq_token_sig(ngx_http_request_t *r,
    ngx_http_fairqueue_loc_conf_t *flcf, ngx_str_t *rid, ngx_str_t *devid,
    time_t exp, u_char out[40]);
static ngx_int_t ngx_http_fq_issue_admission(ngx_http_request_t *r,
    ngx_http_fairqueue_loc_conf_t *flcf, ngx_str_t *rid, ngx_str_t *devid);
static ngx_int_t ngx_http_fq_admission_valid(ngx_http_request_t *r,
    ngx_http_fairqueue_loc_conf_t *flcf, ngx_str_t *rid, ngx_str_t *devid);
static ngx_int_t ngx_http_fq_resolve_identity(ngx_http_request_t *r,
    ngx_http_fairqueue_loc_conf_t *flcf, ngx_str_t *rid, ngx_str_t *devid);

static double ngx_http_fq_frac(ngx_str_t *secret, u_char *data, size_t dlen);
static ngx_int_t ngx_http_fq_header(ngx_http_request_t *r, ngx_str_t *name,
    ngx_str_t *val);
static double ngx_http_fq_parse_risk(ngx_str_t *s);
static ngx_str_t ngx_http_fq_client_ip(ngx_http_request_t *r,
    ngx_http_fairqueue_loc_conf_t *flcf);
static void ngx_http_fq_evaluate(ngx_http_request_t *r,
    ngx_http_fairqueue_loc_conf_t *flcf, ngx_str_t *devid, time_t first_seen,
    ngx_uint_t N, ngx_uint_t rank, ngx_uint_t ip_devices, time_t now,
    ngx_http_fq_eval_t *e);
static ngx_int_t ngx_http_fq_redirect(ngx_http_request_t *r, ngx_str_t *uri);
static ngx_int_t ngx_http_fq_send_json(ngx_http_request_t *r, ngx_str_t *body);
static ngx_int_t ngx_http_fairqueue_status_handler(ngx_http_request_t *r);


/* ------------------------------------------------------------------------- */
/* Directives and module definition                                         */
/* ------------------------------------------------------------------------- */

#define NGX_FQ_LOC_OFF  NGX_HTTP_LOC_CONF_OFFSET
#define NGX_FQ_FIELD(f) offsetof(ngx_http_fairqueue_loc_conf_t, f)

static ngx_command_t  ngx_http_fairqueue_commands[] = {

    { ngx_string("fairqueue_zone"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE12,
      ngx_http_fairqueue_zone,
      0, 0, NULL },

    { ngx_string("fairqueue"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_http_fairqueue_enable,
      NGX_FQ_LOC_OFF, 0, NULL },

    { ngx_string("fairqueue_status"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_fairqueue_status,
      NGX_FQ_LOC_OFF, 0, NULL },

    { ngx_string("fairqueue_rate"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_fairqueue_set_rate,
      NGX_FQ_LOC_OFF, NGX_FQ_FIELD(rate), NULL },

    { ngx_string("fairqueue_start"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_FQ_LOC_OFF, NGX_FQ_FIELD(start), NULL },

    { ngx_string("fairqueue_waiting_start"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_FQ_LOC_OFF, NGX_FQ_FIELD(waiting_start), NULL },

    { ngx_string("fairqueue_token_ttl"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_FQ_LOC_OFF, NGX_FQ_FIELD(token_ttl), NULL },

    { ngx_string("fairqueue_penalty"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_fairqueue_set_permille,
      NGX_FQ_LOC_OFF, NGX_FQ_FIELD(penalty), NULL },

    { ngx_string("fairqueue_aging"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_fairqueue_set_permille,
      NGX_FQ_LOC_OFF, NGX_FQ_FIELD(aging), NULL },

    { ngx_string("fairqueue_aging_cap"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_fairqueue_set_permille,
      NGX_FQ_LOC_OFF, NGX_FQ_FIELD(aging_cap), NULL },

    { ngx_string("fairqueue_window_headroom"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_fairqueue_set_permille,
      NGX_FQ_LOC_OFF, NGX_FQ_FIELD(headroom), NULL },

    { ngx_string("fairqueue_allocation"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_fairqueue_set_alloc,
      NGX_FQ_LOC_OFF, NGX_FQ_FIELD(allocation), NULL },

    { ngx_string("fairqueue_scope"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_FQ_LOC_OFF, NGX_FQ_FIELD(scope), NULL },

    { ngx_string("fairqueue_secret"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_FQ_LOC_OFF, NGX_FQ_FIELD(secret), NULL },

    { ngx_string("fairqueue_risk_header"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_FQ_LOC_OFF, NGX_FQ_FIELD(risk_header), NULL },

    { ngx_string("fairqueue_risk_weight"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_fairqueue_set_permille,
      NGX_FQ_LOC_OFF, NGX_FQ_FIELD(risk_weight), NULL },

    { ngx_string("fairqueue_max_devices_per_ip"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_FQ_LOC_OFF, NGX_FQ_FIELD(max_devices_per_ip), NULL },

    { ngx_string("fairqueue_trust_xff"),
      NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_FQ_LOC_OFF, NGX_FQ_FIELD(trust_xff), NULL },

    { ngx_string("fairqueue_cookie_secure"),
      NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_FQ_LOC_OFF, NGX_FQ_FIELD(cookie_secure), NULL },

    { ngx_string("fairqueue_waiting_uri"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_FQ_LOC_OFF, NGX_FQ_FIELD(waiting_uri), NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_fairqueue_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_fairqueue_init,               /* postconfiguration */
    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */
    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */
    ngx_http_fairqueue_create_loc_conf,    /* create location configuration */
    ngx_http_fairqueue_merge_loc_conf      /* merge location configuration */
};


ngx_module_t  ngx_http_fairqueue_module = {
    NGX_MODULE_V1,
    &ngx_http_fairqueue_module_ctx,
    ngx_http_fairqueue_commands,
    NGX_HTTP_MODULE,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NGX_MODULE_V1_PADDING
};


/* ------------------------------------------------------------------------- */
/* Access-phase handler                                                      */
/* ------------------------------------------------------------------------- */

static ngx_int_t
ngx_http_fairqueue_handler(ngx_http_request_t *r)
{
    ngx_http_fairqueue_loc_conf_t *flcf;
    ngx_http_fq_ctx_t             *ctx;
    ngx_uint_t                     N = 0, rank = 0, ip_devices = 1;
    ngx_int_t                      limited = 0;
    ngx_str_t                      rid, devid, ip;
    time_t                         now, fs;
    ngx_http_fq_eval_t             e;

    flcf = ngx_http_get_module_loc_conf(r, ngx_http_fairqueue_module);

    /* The status view runs as its own content handler and must not be gated. */
    if (!flcf->enable || flcf->is_status || flcf->shm_zone == NULL) {
        return NGX_DECLINED;
    }

    ctx = flcf->shm_zone->data;
    now = ngx_time();

    if (ngx_http_fq_resolve_identity(r, flcf, &rid, &devid) != NGX_OK) {
        return ngx_http_fq_redirect(r, &flcf->waiting_uri);  /* fail closed */
    }

    /* A valid admission token lets the request through without re-evaluating,
     * holding the participant's place for the lifetime of the token. */
    if (ngx_http_fq_admission_valid(r, flcf, &rid, &devid) == NGX_OK) {
        return NGX_DECLINED;
    }

    ip = ngx_http_fq_client_ip(r, flcf);
    fs = ngx_http_fq_register(ctx, devid.data, devid.len, ip.data, ip.len,
                              flcf->max_devices_per_ip, now,
                              &N, &rank, &ip_devices, &limited);
    if (limited) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "fairqueue: rate-limited ip:%V", &ip);
        return ngx_http_fq_redirect(r, &flcf->waiting_uri);
    }

    ngx_http_fq_evaluate(r, flcf, &devid, fs, N, rank, ip_devices, now, &e);

    if (e.admitted) {
        ngx_http_fq_issue_admission(r, flcf, &rid, &devid);
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "fairqueue: admit pos:%ui cursor:%ui",
                       (ngx_uint_t) e.position, (ngx_uint_t) e.cursor);
        return NGX_DECLINED;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "fairqueue: wait pos:%ui cursor:%ui",
                   (ngx_uint_t) e.position, (ngx_uint_t) e.cursor);
    return ngx_http_fq_redirect(r, &flcf->waiting_uri);
}


static ngx_int_t
ngx_http_fairqueue_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_fairqueue_handler;

    return NGX_OK;
}


/* ------------------------------------------------------------------------- */
/* Configuration                                                             */
/* ------------------------------------------------------------------------- */

static void *
ngx_http_fairqueue_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_fairqueue_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_fairqueue_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET;
    conf->shm_zone = NGX_CONF_UNSET_PTR;
    conf->rate = NGX_CONF_UNSET_UINT;
    conf->start = NGX_CONF_UNSET;
    conf->waiting_start = NGX_CONF_UNSET;
    conf->token_ttl = NGX_CONF_UNSET_UINT;
    conf->penalty = NGX_CONF_UNSET_UINT;
    conf->aging = NGX_CONF_UNSET_UINT;
    conf->aging_cap = NGX_CONF_UNSET_UINT;
    conf->headroom = NGX_CONF_UNSET_UINT;
    conf->allocation = NGX_CONF_UNSET_UINT;
    conf->risk_weight = NGX_CONF_UNSET_UINT;
    conf->max_devices_per_ip = NGX_CONF_UNSET_UINT;
    conf->trust_xff = NGX_CONF_UNSET;
    conf->cookie_secure = NGX_CONF_UNSET;
    conf->is_status = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_fairqueue_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_fairqueue_loc_conf_t *prev = parent;
    ngx_http_fairqueue_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_ptr_value(conf->shm_zone, prev->shm_zone, NULL);
    ngx_conf_merge_uint_value(conf->rate, prev->rate,
                              500 * NGX_FQ_RATE_SCALE / 60);         /* 500r/m */
    ngx_conf_merge_sec_value(conf->start, prev->start, 0);
    ngx_conf_merge_sec_value(conf->waiting_start, prev->waiting_start, 0);
    ngx_conf_merge_uint_value(conf->token_ttl, prev->token_ttl, 300);
    ngx_conf_merge_uint_value(conf->penalty, prev->penalty, 20);     /* 0.02 */
    ngx_conf_merge_uint_value(conf->aging, prev->aging, 500);        /* 0.5  */
    ngx_conf_merge_uint_value(conf->aging_cap, prev->aging_cap, 100);/* 0.1  */
    ngx_conf_merge_uint_value(conf->headroom, prev->headroom, 200);  /* 0.2  */
    ngx_conf_merge_uint_value(conf->allocation, prev->allocation, 0);
    ngx_conf_merge_str_value(conf->scope, prev->scope, "default");
    ngx_conf_merge_str_value(conf->secret, prev->secret, "");
    ngx_conf_merge_str_value(conf->risk_header, prev->risk_header, "");
    ngx_conf_merge_uint_value(conf->risk_weight, prev->risk_weight, 500);/* 0.5 */
    ngx_conf_merge_uint_value(conf->max_devices_per_ip,
                              prev->max_devices_per_ip, 64);
    ngx_conf_merge_value(conf->trust_xff, prev->trust_xff, 0);
    ngx_conf_merge_value(conf->cookie_secure, prev->cookie_secure, 0);
    ngx_conf_merge_str_value(conf->waiting_uri, prev->waiting_uri,
                             "/waiting-room");
    ngx_conf_merge_value(conf->is_status, prev->is_status, 0);

    if (conf->rate == 0) {
        conf->rate = 500 * NGX_FQ_RATE_SCALE / 60;
    }

    /* The secret keys every signature; without it cookies and tokens could be
     * forged, so refuse to start where fairqueue is enabled but no secret is
     * configured. */
    if ((conf->enable || conf->is_status) && conf->secret.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "\"fairqueue_secret\" is required where fairqueue is enabled");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


/* "fairqueue NAME" binds a zone and enables the gate; "on"/"off" toggle it
 * without a zone (the handler then declines). */
static char *
ngx_http_fairqueue_enable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_fairqueue_loc_conf_t *flcf = conf;
    ngx_str_t                     *value = cf->args->elts;
    ngx_shm_zone_t                *zone;

    if (ngx_strcmp(value[1].data, "on") == 0) {
        flcf->enable = 1;
        flcf->shm_zone = NULL;
        return NGX_CONF_OK;
    }
    if (ngx_strcmp(value[1].data, "off") == 0) {
        flcf->enable = 0;
        return NGX_CONF_OK;
    }

    zone = ngx_shared_memory_add(cf, &value[1], 0, &ngx_http_fairqueue_module);
    if (zone == NULL) {
        return NGX_CONF_ERROR;
    }
    flcf->enable = 1;
    flcf->shm_zone = zone;
    return NGX_CONF_OK;
}


/* Parse "Nr/s" | "Nr/m" | "Nr/h" into requests-per-second * 1000. */
static char *
ngx_http_fairqueue_set_rate(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_fairqueue_loc_conf_t *flcf = conf;
    ngx_str_t                     *value = cf->args->elts;
    ngx_str_t                      s = value[1];
    ngx_uint_t                     n, scale_div;
    u_char                        *p, *last;

    last = s.data + s.len;
    for (p = s.data; p < last && *p >= '0' && *p <= '9'; p++) { /* void */ }

    n = ngx_atoi(s.data, p - s.data);
    if (n == (ngx_uint_t) NGX_ERROR || p == s.data) {
        return "invalid rate";
    }
    if (n > 10000000) {
        return "rate out of range";
    }

    if (ngx_strncmp(p, "r/s", 3) == 0)      scale_div = 1;
    else if (ngx_strncmp(p, "r/m", 3) == 0) scale_div = 60;
    else if (ngx_strncmp(p, "r/h", 3) == 0) scale_div = 3600;
    else return "invalid rate (use r/s, r/m or r/h)";

    flcf->rate = (ngx_uint_t) (n * NGX_FQ_RATE_SCALE / scale_div);
    if (flcf->rate == 0) {
        flcf->rate = 1;
    }
    return NGX_CONF_OK;
}


/* Parse a decimal in [0, N] into per-mille: "0.02" -> 20. */
static char *
ngx_http_fairqueue_set_permille(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char       *base = conf;
    ngx_uint_t *field = (ngx_uint_t *) (base + cmd->offset);
    ngx_str_t  *value = cf->args->elts;
    ngx_str_t   s = value[1];
    ngx_uint_t  intpart = 0, frac = 0, scale = 100;
    ngx_uint_t  seen_dot = 0;
    u_char     *p, *last;

    last = s.data + s.len;
    for (p = s.data; p < last; p++) {
        if (*p == '.') { seen_dot = 1; continue; }
        if (*p < '0' || *p > '9') {
            return "invalid fraction";
        }
        if (!seen_dot) {
            intpart = intpart * 10 + (*p - '0');
            if (intpart > 1000000) {
                return "value out of range";
            }
        } else if (scale > 0) {
            frac += (*p - '0') * scale;
            scale /= 10;
        }
    }
    *field = intpart * NGX_FQ_PERMILLE + frac;
    return NGX_CONF_OK;
}


static char *
ngx_http_fairqueue_set_alloc(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char       *base = conf;
    ngx_uint_t *field = (ngx_uint_t *) (base + cmd->offset);
    ngx_str_t  *value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "hash") == 0)      *field = 0;
    else if (ngx_strcmp(value[1].data, "fifo") == 0) *field = 1;
    else return "invalid allocation (hash | fifo)";

    return NGX_CONF_OK;
}


/* fairqueue_zone zone=NAME:SIZE [rate=Nr/m] */
static char *
ngx_http_fairqueue_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t          *value = cf->args->elts;
    ngx_str_t           name, ss;
    ssize_t             size = 0;
    ngx_uint_t          rate = 500 * NGX_FQ_RATE_SCALE / 60;
    ngx_uint_t          i, num, div;
    u_char             *p, *sep, *q, *last;
    ngx_shm_zone_t     *shm_zone;
    ngx_http_fq_ctx_t  *ctx;

    ngx_str_null(&name);

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {
            p = value[i].data + 5;
            sep = ngx_strlchr(p, value[i].data + value[i].len, ':');
            if (sep == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "fairqueue_zone: expected zone=NAME:SIZE");
                return NGX_CONF_ERROR;
            }
            name.data = p;
            name.len = sep - p;
            ss.data = sep + 1;
            ss.len = value[i].data + value[i].len - (sep + 1);
            size = ngx_parse_size(&ss);
            if (size == NGX_ERROR || size < (ssize_t) (8 * ngx_pagesize)) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "fairqueue_zone: invalid size (minimum 8 pages)");
                return NGX_CONF_ERROR;
            }
            continue;
        }

        if (ngx_strncmp(value[i].data, "rate=", 5) == 0) {
            q = value[i].data + 5;
            last = value[i].data + value[i].len;
            for (p = q; p < last && *p >= '0' && *p <= '9'; p++) { /* void */ }
            num = ngx_atoi(q, p - q);
            if (num == (ngx_uint_t) NGX_ERROR || p == q || num > 10000000) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "fairqueue_zone: invalid rate");
                return NGX_CONF_ERROR;
            }
            if (ngx_strncmp(p, "r/s", 3) == 0) div = 1;
            else if (ngx_strncmp(p, "r/m", 3) == 0) div = 60;
            else if (ngx_strncmp(p, "r/h", 3) == 0) div = 3600;
            else {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "fairqueue_zone: rate must be Nr/s, Nr/m or Nr/h");
                return NGX_CONF_ERROR;
            }
            rate = num * NGX_FQ_RATE_SCALE / div;
            if (rate == 0) rate = 1;
            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "fairqueue_zone: unexpected parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }

    if (name.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "fairqueue_zone: missing zone=NAME:SIZE");
        return NGX_CONF_ERROR;
    }

    shm_zone = ngx_shared_memory_add(cf, &name, size, &ngx_http_fairqueue_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }
    if (shm_zone->data) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "fairqueue_zone: zone \"%V\" is already defined", &name);
        return NGX_CONF_ERROR;
    }

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_fq_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }
    ctx->rate = rate;

    shm_zone->init = ngx_http_fq_init_zone;
    shm_zone->data = ctx;

    return NGX_CONF_OK;
}


static char *
ngx_http_fairqueue_status(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_fairqueue_loc_conf_t *flcf = conf;
    ngx_http_core_loc_conf_t      *clcf;

    flcf->is_status = 1;
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_fairqueue_status_handler;
    return NGX_CONF_OK;
}


/* ------------------------------------------------------------------------- */
/* Shared-memory zone: rbtree, LRU eviction, registration                    */
/* ------------------------------------------------------------------------- */

static void
ngx_http_fq_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t  **p;
    ngx_http_fq_node_t  *n, *nt;

    for ( ;; ) {
        if (node->key < temp->key) {
            p = &temp->left;
        } else if (node->key > temp->key) {
            p = &temp->right;
        } else {
            n = (ngx_http_fq_node_t *) node;
            nt = (ngx_http_fq_node_t *) temp;
            p = (ngx_memn2cmp(n->data, nt->data, n->len, nt->len) < 0)
                ? &temp->left : &temp->right;
        }
        if (*p == sentinel) {
            break;
        }
        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


static ngx_http_fq_node_t *
ngx_http_fq_rb_lookup(ngx_rbtree_t *tree, ngx_uint_t hash, u_char *data,
    size_t len)
{
    ngx_rbtree_node_t  *node, *sentinel;
    ngx_http_fq_node_t *fqn;
    ngx_int_t           rc;

    node = tree->root;
    sentinel = tree->sentinel;

    while (node != sentinel) {
        if ((ngx_rbtree_key_t) hash < node->key) { node = node->left; continue; }
        if ((ngx_rbtree_key_t) hash > node->key) { node = node->right; continue; }

        fqn = (ngx_http_fq_node_t *) node;
        rc = ngx_memn2cmp(data, fqn->data, len, (size_t) fqn->len);
        if (rc == 0) {
            return fqn;
        }
        node = (rc < 0) ? node->left : node->right;
    }
    return NULL;
}


/*
 * Evict up to two idle participant nodes from the LRU tail. N is decremented so
 * it tracks currently-active participants, and the per-IP counter each evicted
 * device was charged to is decremented too; an IP node whose count reaches zero
 * is freed immediately. Because an IP node therefore exists exactly while it has
 * at least one live device, the per-IP count can never be orphaned or undercount
 * (which would let the cap be evaded). Caller holds the zone mutex.
 */
static void
ngx_http_fq_expire_devices(ngx_http_fq_ctx_t *ctx, time_t now, ngx_uint_t force)
{
    ngx_queue_t        *q;
    ngx_http_fq_node_t *dev, *ipn;
    ngx_uint_t          i;

    for (i = 0; i < 2; i++) {
        if (ngx_queue_empty(&ctx->sh->queue)) {
            return;
        }
        q = ngx_queue_last(&ctx->sh->queue);
        dev = ngx_queue_data(q, ngx_http_fq_node_t, queue);

        if (!force && (now - dev->last_seen) < NGX_FQ_NODE_TTL) {
            return;
        }
        if (dev->iplen) {
            ipn = ngx_http_fq_rb_lookup(&ctx->sh->iprbtree, dev->ip_hash,
                                        dev->data + dev->len, dev->iplen);
            if (ipn) {
                if (ipn->count > 0) {
                    ipn->count--;
                }
                if (ipn->count == 0) {        /* last device gone: drop the IP node */
                    ngx_rbtree_delete(&ctx->sh->iprbtree, &ipn->node);
                    ngx_slab_free_locked(ctx->shpool, ipn);
                }
            }
        }
        ngx_queue_remove(q);
        ngx_rbtree_delete(&ctx->sh->rbtree, &dev->node);
        if (ctx->sh->n > 0) {
            ctx->sh->n--;
        }
        ngx_slab_free_locked(ctx->shpool, dev);
    }
}


/*
 * Devices-per-IP counter. With create set, this counts a new device against the
 * address and returns the resulting count; if that would exceed cap, *limited is
 * set and nothing is counted. With create clear it only reads the current count.
 * The caller must hold the zone mutex.
 */
static ngx_uint_t
ngx_http_fq_ip_touch(ngx_http_fq_ctx_t *ctx, u_char *ip, size_t iplen,
    time_t now, ngx_int_t create, ngx_uint_t cap, ngx_int_t *limited)
{
    ngx_uint_t          hash;
    ngx_http_fq_node_t *ipn;
    size_t              size;

    if (limited) *limited = 0;
    if (iplen == 0) {
        return 1;
    }

    hash = ngx_crc32_short(ip, iplen);
    ipn = ngx_http_fq_rb_lookup(&ctx->sh->iprbtree, hash, ip, iplen);

    if (!create) {
        return ipn ? ipn->count : 0;
    }

    if (ipn) {
        if (ipn->count >= cap) {
            if (limited) *limited = 1;
            return ipn->count;
        }
        ipn->count++;
        ipn->last_seen = now;
        return ipn->count;
    }

    if (cap == 0) {
        if (limited) *limited = 1;
        return 0;
    }

    size = offsetof(ngx_http_fq_node_t, data) + iplen;
    ipn = ngx_slab_alloc_locked(ctx->shpool, size);
    if (ipn == NULL) {
        return 1;   /* under memory pressure, leave this device uncounted */
    }
    ipn->node.key = hash;
    ipn->len = (u_short) iplen;
    ipn->iplen = 0;
    ipn->ip_hash = 0;
    ngx_memcpy(ipn->data, ip, iplen);
    ipn->first_seen = now;
    ipn->last_seen = now;
    ipn->count = 1;
    ipn->rank = 0;
    ngx_rbtree_insert(&ctx->sh->iprbtree, &ipn->node);
    return 1;
}


/*
 * Register a device and enforce the per-IP cap. Idempotent: repeat visits touch
 * the LRU and keep the original first_seen and rank. A new device is charged to
 * its IP only after its node is allocated, so a failed allocation never consumes
 * a cap slot. Returns the device's first_seen and reports N, rank and the
 * device-per-IP count by pointer.
 *
 * A device is charged to the IP it registered from; if the same device later
 * returns from a different address the original charge stands until the device
 * expires (the cap is "devices per registration IP"). The reported per-IP count
 * reflects the current request's address, used only as a volume signal.
 */
static time_t
ngx_http_fq_register(ngx_http_fq_ctx_t *ctx, u_char *devid, size_t devlen,
    u_char *ip, size_t iplen, ngx_uint_t cap, time_t now,
    ngx_uint_t *n_out, ngx_uint_t *rank_out, ngx_uint_t *ip_devices_out,
    ngx_int_t *limited)
{
    ngx_uint_t          hash, ipd;
    ngx_http_fq_node_t *fqn;
    size_t              size;
    time_t              first_seen;

    if (limited) *limited = 0;
    hash = ngx_crc32_short(devid, devlen);

    ngx_shmtx_lock(&ctx->shpool->mutex);

    ngx_http_fq_expire_devices(ctx, now, 0);

    fqn = ngx_http_fq_rb_lookup(&ctx->sh->rbtree, hash, devid, devlen);

    if (fqn) {
        fqn->last_seen = now;
        ngx_queue_remove(&fqn->queue);
        ngx_queue_insert_head(&ctx->sh->queue, &fqn->queue);
        first_seen = fqn->first_seen;
        if (rank_out) *rank_out = fqn->rank;
        ipd = ngx_http_fq_ip_touch(ctx, ip, iplen, now, 0, cap, NULL);

    } else {
        /* Check the per-IP cap first (peek), then allocate the device, and only
         * commit the IP count once the device exists, so a failed allocation
         * never consumes a cap slot. All under the zone mutex. */
        ipd = ngx_http_fq_ip_touch(ctx, ip, iplen, now, 0, cap, NULL);
        if (cap == 0 || ipd >= cap) {
            if (limited) *limited = 1;
            if (rank_out) *rank_out = 0;
            if (ip_devices_out) *ip_devices_out = ipd;
            if (n_out) *n_out = (ngx_uint_t) ctx->sh->n;
            ngx_shmtx_unlock(&ctx->shpool->mutex);
            return now;
        }

        size = offsetof(ngx_http_fq_node_t, data) + devlen + iplen;
        fqn = ngx_slab_alloc_locked(ctx->shpool, size);
        if (fqn == NULL) {
            ngx_http_fq_expire_devices(ctx, now, 1);
            fqn = ngx_slab_alloc_locked(ctx->shpool, size);
        }
        if (fqn == NULL) {
            if (rank_out) *rank_out = 0;
            if (ip_devices_out) *ip_devices_out = ipd;
            if (n_out) *n_out = (ngx_uint_t) ctx->sh->n;
            ngx_shmtx_unlock(&ctx->shpool->mutex);
            return now;
        }

        /* Commit one device against the IP now that the node is allocated. */
        ipd = ngx_http_fq_ip_touch(ctx, ip, iplen, now, 1, cap, NULL);

        fqn->node.key = hash;
        fqn->len = (u_short) devlen;
        fqn->iplen = (u_short) iplen;
        fqn->ip_hash = iplen ? ngx_crc32_short(ip, iplen) : 0;
        fqn->count = 0;
        ngx_memcpy(fqn->data, devid, devlen);
        if (iplen) {
            ngx_memcpy(fqn->data + devlen, ip, iplen);
        }
        fqn->first_seen = now;
        fqn->last_seen = now;
        ctx->sh->n++;
        fqn->rank = (ngx_uint_t) ctx->sh->n;

        ngx_rbtree_insert(&ctx->sh->rbtree, &fqn->node);
        ngx_queue_insert_head(&ctx->sh->queue, &fqn->queue);

        first_seen = now;
        if (rank_out) *rank_out = fqn->rank;
    }

    if (ip_devices_out) *ip_devices_out = ipd ? ipd : 1;
    if (n_out) *n_out = (ngx_uint_t) ctx->sh->n;
    ngx_shmtx_unlock(&ctx->shpool->mutex);
    return first_seen;
}


/* Read-only lookup for the status view: never creates or counts anything. */
static ngx_int_t
ngx_http_fq_peek(ngx_http_fq_ctx_t *ctx, u_char *devid, size_t devlen,
    u_char *ip, size_t iplen, time_t *first_seen, ngx_uint_t *N,
    ngx_uint_t *rank, ngx_uint_t *ip_devices)
{
    ngx_uint_t           hash;
    ngx_http_fq_node_t  *fqn;
    ngx_int_t            found = NGX_DECLINED;

    hash = ngx_crc32_short(devid, devlen);
    ngx_shmtx_lock(&ctx->shpool->mutex);

    fqn = ngx_http_fq_rb_lookup(&ctx->sh->rbtree, hash, devid, devlen);
    if (fqn) {
        *first_seen = fqn->first_seen;
        if (rank) *rank = fqn->rank;
        found = NGX_OK;
    }
    if (N) *N = (ngx_uint_t) ctx->sh->n;
    if (ip_devices) {
        ngx_uint_t c = ngx_http_fq_ip_touch(ctx, ip, iplen, 0, 0, 0, NULL);
        *ip_devices = c ? c : 1;
    }

    ngx_shmtx_unlock(&ctx->shpool->mutex);
    return found;
}


static ngx_int_t
ngx_http_fq_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_http_fq_ctx_t *octx = data;
    ngx_http_fq_ctx_t *ctx = shm_zone->data;
    ngx_slab_pool_t   *shpool;

    if (octx) {                 /* inherit the existing zone across a reload */
        ctx->sh = octx->sh;
        ctx->shpool = octx->shpool;
        return NGX_OK;
    }

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        ctx->sh = shpool->data;
        ctx->shpool = shpool;
        return NGX_OK;
    }

    ctx->shpool = shpool;
    ctx->sh = ngx_slab_alloc(shpool, sizeof(ngx_http_fq_shctx_t));
    if (ctx->sh == NULL) {
        return NGX_ERROR;
    }
    shpool->data = ctx->sh;

    ngx_rbtree_init(&ctx->sh->rbtree, &ctx->sh->sentinel,
                    ngx_http_fq_rbtree_insert_value);
    ngx_queue_init(&ctx->sh->queue);
    ctx->sh->n = 0;

    ngx_rbtree_init(&ctx->sh->iprbtree, &ctx->sh->ipsentinel,
                    ngx_http_fq_rbtree_insert_value);

    return NGX_OK;
}


/* ------------------------------------------------------------------------- */
/* Identity: signed cookies and admission tokens (HMAC-SHA1)                 */
/* ------------------------------------------------------------------------- */

static void
ngx_http_fq_hmac_sha1(u_char *key, size_t klen, u_char *data, size_t dlen,
    u_char out[20])
{
    ngx_sha1_t  ctx;
    u_char      k[64], ipad[64], opad[64], inner[20];
    ngx_uint_t  i;

    ngx_memzero(k, sizeof(k));
    if (klen > 64) {
        ngx_sha1_init(&ctx);
        ngx_sha1_update(&ctx, key, klen);
        ngx_sha1_final(k, &ctx);
    } else {
        ngx_memcpy(k, key, klen);
    }
    for (i = 0; i < 64; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }
    ngx_sha1_init(&ctx);
    ngx_sha1_update(&ctx, ipad, 64);
    ngx_sha1_update(&ctx, data, dlen);
    ngx_sha1_final(inner, &ctx);

    ngx_sha1_init(&ctx);
    ngx_sha1_update(&ctx, opad, 64);
    ngx_sha1_update(&ctx, inner, 20);
    ngx_sha1_final(out, &ctx);
}


/* HMAC as 40 lowercase hex characters (no terminator) in out. */
static void
ngx_http_fq_hmac_hex(ngx_str_t *secret, u_char *data, size_t dlen, u_char out[40])
{
    u_char mac[20];
    ngx_http_fq_hmac_sha1(secret->data, secret->len, data, dlen, mac);
    ngx_hex_dump(out, mac, 20);
}


/* Constant-time equality, to avoid leaking signatures through timing. */
static ngx_int_t
ngx_http_fq_ct_eq(u_char *a, u_char *b, size_t n)
{
    u_char  d = 0;
    size_t  i;

    for (i = 0; i < n; i++) {
        d |= (u_char) (a[i] ^ b[i]);
    }
    return d == 0;
}


/* A fresh random identifier: 16 random bytes as 32 hex characters. */
static void
ngx_http_fq_new_id(ngx_pool_t *pool, ngx_str_t *out)
{
    u_char      raw[16];
    ngx_uint_t  i;

    for (i = 0; i < 16; i++) {
        raw[i] = (u_char) ngx_random();
    }
    out->data = ngx_pnalloc(pool, 32);
    if (out->data == NULL) {
        out->len = 0;
        return;
    }
    ngx_hex_dump(out->data, raw, 16);
    out->len = 32;
}


static ngx_int_t
ngx_http_fq_get_cookie(ngx_http_request_t *r, ngx_str_t *name, ngx_str_t *val)
{
    if (r->headers_in.cookie == NULL) {
        return NGX_DECLINED;
    }
    if (ngx_http_parse_multi_header_lines(r, r->headers_in.cookie, name, val)
        == NULL)
    {
        return NGX_DECLINED;
    }
    return NGX_OK;
}


static ngx_int_t
ngx_http_fq_add_set_cookie(ngx_http_request_t *r, ngx_str_t *cookie)
{
    ngx_table_elt_t  *h;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    h->hash = 1;
#if (nginx_version >= 1023000)
    h->next = NULL;
#endif
    ngx_str_set(&h->key, "Set-Cookie");
    h->value = *cookie;
    return NGX_OK;
}


/* Signed cookie value: "<rid>.<hmac_hex(prefix ':' rid)>". */
static ngx_int_t
ngx_http_fq_sign_value(ngx_pool_t *pool, ngx_str_t *secret, const char *prefix,
    ngx_str_t *rid, ngx_str_t *out)
{
    size_t   plen = ngx_strlen(prefix);
    u_char  *msg, *p, sig[40];

    msg = ngx_pnalloc(pool, plen + 1 + rid->len);
    if (msg == NULL) {
        return NGX_ERROR;
    }
    p = ngx_cpymem(msg, (u_char *) prefix, plen);
    *p++ = ':';
    ngx_memcpy(p, rid->data, rid->len);

    ngx_http_fq_hmac_hex(secret, msg, plen + 1 + rid->len, sig);

    out->data = ngx_pnalloc(pool, rid->len + 1 + 40);
    if (out->data == NULL) {
        return NGX_ERROR;
    }
    p = ngx_cpymem(out->data, rid->data, rid->len);
    *p++ = '.';
    ngx_memcpy(p, sig, 40);
    out->len = rid->len + 1 + 40;
    return NGX_OK;
}


/* Read a signed cookie and, if its signature verifies, return the identifier. */
static ngx_int_t
ngx_http_fq_verify_cookie(ngx_http_request_t *r, ngx_str_t *secret,
    ngx_str_t *cookiename, const char *prefix, ngx_str_t *rid)
{
    ngx_str_t  v, ridpart;
    size_t     plen = ngx_strlen(prefix);
    u_char    *msg, *p, *sig, calc[40];

    if (ngx_http_fq_get_cookie(r, cookiename, &v) != NGX_OK) return NGX_DECLINED;
    if (v.len < 1 + 1 + 40) return NGX_DECLINED;
    if (v.data[v.len - 41] != '.') return NGX_DECLINED;

    ridpart.data = v.data;
    ridpart.len = v.len - 41;
    if (ridpart.len > 64) {             /* legitimate identifiers are 32 hex */
        return NGX_DECLINED;
    }
    sig = v.data + v.len - 40;

    msg = ngx_pnalloc(r->pool, plen + 1 + ridpart.len);
    if (msg == NULL) {
        return NGX_ERROR;
    }
    p = ngx_cpymem(msg, (u_char *) prefix, plen);
    *p++ = ':';
    ngx_memcpy(p, ridpart.data, ridpart.len);

    ngx_http_fq_hmac_hex(secret, msg, plen + 1 + ridpart.len, calc);
    if (!ngx_http_fq_ct_eq(calc, sig, 40)) {
        return NGX_DECLINED;
    }

    *rid = ridpart;
    return NGX_OK;
}


static ngx_int_t
ngx_http_fq_set_signed_cookie(ngx_http_request_t *r,
    ngx_http_fairqueue_loc_conf_t *flcf, const char *name, const char *prefix,
    ngx_str_t *rid, time_t max_age)
{
    ngx_str_t  val, cookie;
    u_char    *b, *p;
    size_t     cap;

    if (ngx_http_fq_sign_value(r->pool, &flcf->secret, prefix, rid, &val)
        != NGX_OK)
    {
        return NGX_ERROR;
    }
    cap = ngx_strlen(name) + 1 + val.len + 96;
    b = ngx_pnalloc(r->pool, cap);
    if (b == NULL) {
        return NGX_ERROR;
    }

    p = ngx_sprintf(b, "%s=%V; Path=/; SameSite=Lax; HttpOnly", name, &val);
    if (flcf->cookie_secure) {
        p = ngx_cpymem(p, "; Secure", 8);
    }
    if (max_age > 0) {
        p = ngx_sprintf(p, "; Max-Age=%T", max_age);
    }
    cookie.data = b;
    cookie.len = p - b;
    return ngx_http_fq_add_set_cookie(r, &cookie);
}


/*
 * Admission-token signature over event, scope, device, identity and expiry.
 * Binding the device makes a stolen fq_adm useless without the matching fq_dev;
 * binding scope and start keeps a token from being replayed across queues or
 * across sale windows.
 */
static void
ngx_http_fq_token_sig(ngx_http_request_t *r,
    ngx_http_fairqueue_loc_conf_t *flcf, ngx_str_t *rid, ngx_str_t *devid,
    time_t exp, u_char out[40])
{
    u_char  *msg, *p;
    size_t   cap;

    cap = 4 + flcf->scope.len + 1 + NGX_TIME_T_LEN + 1 + devid->len + 1
          + rid->len + 1 + NGX_TIME_T_LEN + 1;
    msg = ngx_pnalloc(r->pool, cap);
    if (msg == NULL) {
        ngx_memzero(out, 40);
        return;
    }
    p = ngx_sprintf(msg, "adm:%V:%T:%V:%V:%T",
                    &flcf->scope, flcf->start, devid, rid, exp);
    ngx_http_fq_hmac_hex(&flcf->secret, msg, p - msg, out);
}


static ngx_int_t
ngx_http_fq_issue_admission(ngx_http_request_t *r,
    ngx_http_fairqueue_loc_conf_t *flcf, ngx_str_t *rid, ngx_str_t *devid)
{
    time_t     exp = ngx_time() + (time_t) flcf->token_ttl;
    u_char     sig[40], *b, *p;
    ngx_str_t  val, cookie;

    ngx_http_fq_token_sig(r, flcf, rid, devid, exp, sig);

    b = ngx_pnalloc(r->pool, rid->len + 1 + NGX_TIME_T_LEN + 1 + 40);
    if (b == NULL) {
        return NGX_ERROR;
    }
    p = ngx_sprintf(b, "%V.%T.", rid, exp);
    p = ngx_cpymem(p, sig, 40);
    val.data = b;
    val.len = p - b;

    b = ngx_pnalloc(r->pool, val.len + 96);
    if (b == NULL) {
        return NGX_ERROR;
    }
    p = ngx_sprintf(b, "fq_adm=%V; Path=/; SameSite=Lax; HttpOnly", &val);
    if (flcf->cookie_secure) {
        p = ngx_cpymem(p, "; Secure", 8);
    }
    p = ngx_sprintf(p, "; Max-Age=%ui", flcf->token_ttl);
    cookie.data = b;
    cookie.len = p - b;
    return ngx_http_fq_add_set_cookie(r, &cookie);
}


static ngx_int_t
ngx_http_fq_admission_valid(ngx_http_request_t *r,
    ngx_http_fairqueue_loc_conf_t *flcf, ngx_str_t *rid, ngx_str_t *devid)
{
    ngx_str_t   name = ngx_string("fq_adm");
    ngx_str_t   v, trid, expstr;
    u_char     *dot1, *dot2, *sig, calc[40];
    time_t      exp;

    if (ngx_http_fq_get_cookie(r, &name, &v) != NGX_OK) return NGX_DECLINED;
    if (v.len < 1 + 1 + 1 + 1 + 40) return NGX_DECLINED;
    if (v.data[v.len - 41] != '.') return NGX_DECLINED;

    dot2 = v.data + v.len - 41;                     /* dot before signature */
    sig = v.data + v.len - 40;
    dot1 = ngx_strlchr(v.data, dot2, '.');          /* dot between rid and exp */
    if (dot1 == NULL) return NGX_DECLINED;

    trid.data = v.data;
    trid.len = dot1 - v.data;
    expstr.data = dot1 + 1;
    expstr.len = dot2 - (dot1 + 1);

    if (trid.len != rid->len
        || ngx_memcmp(trid.data, rid->data, rid->len) != 0)
    {
        return NGX_DECLINED;
    }
    exp = ngx_atotm(expstr.data, expstr.len);
    if (exp == NGX_ERROR || exp < ngx_time()) {
        return NGX_DECLINED;
    }

    ngx_http_fq_token_sig(r, flcf, &trid, devid, exp, calc);
    if (!ngx_http_fq_ct_eq(calc, sig, 40)) {
        return NGX_DECLINED;
    }
    return NGX_OK;
}


/* Resolve the participant's identity and device cookies, minting and signing
 * fresh ones when absent. Keeping the slot tied to the device (not the identity)
 * means clearing fq_id alone does not re-roll the assigned slot. */
static ngx_int_t
ngx_http_fq_resolve_identity(ngx_http_request_t *r,
    ngx_http_fairqueue_loc_conf_t *flcf, ngx_str_t *rid, ngx_str_t *devid)
{
    ngx_str_t  idn = ngx_string("fq_id");
    ngx_str_t  devn = ngx_string("fq_dev");

    if (ngx_http_fq_verify_cookie(r, &flcf->secret, &idn, "id", rid) != NGX_OK) {
        ngx_http_fq_new_id(r->pool, rid);
        if (rid->len == 0
            || ngx_http_fq_set_signed_cookie(r, flcf, "fq_id", "id", rid, 0)
               != NGX_OK)
        {
            return NGX_ERROR;
        }
    }
    if (ngx_http_fq_verify_cookie(r, &flcf->secret, &devn, "dev", devid)
        != NGX_OK)
    {
        ngx_http_fq_new_id(r->pool, devid);
        if (devid->len == 0
            || ngx_http_fq_set_signed_cookie(r, flcf, "fq_dev", "dev", devid,
                                             60 * 60 * 24 * 30) != NGX_OK)
        {
            return NGX_ERROR;
        }
    }
    return NGX_OK;
}


/* ------------------------------------------------------------------------- */
/* Position and admission                                                    */
/* ------------------------------------------------------------------------- */

/* Deterministic fraction in [0, 1) from the top 48 bits of the HMAC. */
static double
ngx_http_fq_frac(ngx_str_t *secret, u_char *data, size_t dlen)
{
    u_char    mac[20];
    uint64_t  v;

    ngx_http_fq_hmac_sha1(secret->data, secret->len, data, dlen, mac);
    v = ((uint64_t) mac[0] << 40) | ((uint64_t) mac[1] << 32)
      | ((uint64_t) mac[2] << 24) | ((uint64_t) mac[3] << 16)
      | ((uint64_t) mac[4] << 8)  | (uint64_t) mac[5];
    return (double) v / 281474976710656.0;      /* 2^48 */
}


static ngx_int_t
ngx_http_fq_header(ngx_http_request_t *r, ngx_str_t *name, ngx_str_t *val)
{
    ngx_list_part_t  *part = &r->headers_in.headers.part;
    ngx_table_elt_t  *h = part->elts;
    ngx_uint_t        i;

    for (i = 0; /* void */; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) break;
            part = part->next; h = part->elts; i = 0;
        }
        if (h[i].key.len == name->len
            && ngx_strncasecmp(h[i].key.data, name->data, name->len) == 0)
        {
            *val = h[i].value;
            return NGX_OK;
        }
    }
    return NGX_DECLINED;
}


/* Parse a decimal in [0, 1] from a header value, clamped to the range. */
static double
ngx_http_fq_parse_risk(ngx_str_t *s)
{
    double     v = 0.0, scale = 0.1;
    u_char    *p = s->data, *last = s->data + s->len;
    ngx_int_t  seen_dot = 0;

    for (; p < last; p++) {
        if (*p == '.') { seen_dot = 1; continue; }
        if (*p < '0' || *p > '9') break;
        if (!seen_dot) {
            v = v * 10.0 + (*p - '0');
        } else {
            v += (*p - '0') * scale;
            scale /= 10.0;
        }
    }
    if (v < 0.0) v = 0.0;
    if (v > 1.0) v = 1.0;
    return v;
}


/*
 * Client address. With forwarded headers trusted, use the last X-Forwarded-For
 * element: that is the address appended by the nearest trusted proxy, whereas
 * earlier elements are client-supplied and forgeable. Only enable trust_xff
 * behind a proxy that appends (or rewrites) this header; for multi-proxy chains
 * use ngx_http_realip_module and leave trust_xff off. Falls back to the peer.
 */
static ngx_str_t
ngx_http_fq_client_ip(ngx_http_request_t *r, ngx_http_fairqueue_loc_conf_t *flcf)
{
    ngx_str_t  name = ngx_string("X-Forwarded-For");
    ngx_str_t  xff, ip;
    u_char    *p, *e;

    if (flcf->trust_xff
        && ngx_http_fq_header(r, &name, &xff) == NGX_OK && xff.len)
    {
        e = xff.data + xff.len;
        while (e > xff.data && (e[-1] == ' ' || e[-1] == ',')) e--;  /* trim right */
        p = e;
        while (p > xff.data && p[-1] != ',') p--;                    /* last token */
        while (p < e && *p == ' ') p++;                              /* trim left  */
        if (e > p) {
            ip.data = p;
            ip.len = (size_t) (e - p);
            if (ip.len > 64) {          /* bound: longest plausible address */
                ip.len = 64;
            }
            return ip;
        }
    }
    return r->connection->addr_text;
}


/*
 * Compute a participant's position and the admission outcome.
 *
 *   base     = floor(frac * N * (1 + headroom))   (hash)  |  rank  (fifo)
 *   penalty  = (volume - 1) * penalty * N  +  risk * risk_weight * N
 *   position = base + max(0, penalty - aging)
 *   cursor   = rate * (now - start)      (0 before the sale starts)
 *   admitted = started AND position <= cursor
 *
 * Headroom spreads N participants over a wider span so slots stay sparse, which
 * keeps room for later arrivals with a good hash. Aging only erodes the penalty,
 * never the base, so an honest participant (no penalty) has a pure, arrival-
 * independent slot, while a penalized one gradually recovers (anti-starvation).
 */
static void
ngx_http_fq_evaluate(ngx_http_request_t *r, ngx_http_fairqueue_loc_conf_t *flcf,
    ngx_str_t *devid, time_t first_seen, ngx_uint_t N, ngx_uint_t rank,
    ngx_uint_t ip_devices, time_t now, ngx_http_fq_eval_t *e)
{
    double     span, base, penalty, aging, aging_cap, effpen, position, cursor;
    double     risk = 0.0;
    time_t     anchor;
    u_char    *msg, *p;
    size_t     cap;
    ngx_uint_t volume;

    if (N == 0) {
        N = 1;
    }
    span = (double) N * (1000.0 + (double) flcf->headroom) / 1000.0;

    if (flcf->allocation == 1) {
        base = (double) rank;
    } else {
        cap = flcf->scope.len + 1 + NGX_TIME_T_LEN + 1 + devid->len + 1;
        msg = ngx_pnalloc(r->pool, cap);
        if (msg == NULL) {
            base = span;            /* fail closed: send to the back, never admit */
        } else {
            p = ngx_sprintf(msg, "%V:%T:%V", &flcf->scope, flcf->start, devid);
            base = (double) (ngx_uint_t)
                   (ngx_http_fq_frac(&flcf->secret, msg, p - msg) * span);
        }
    }

    /* External risk is only honored when forwarded headers are trusted. */
    if (flcf->trust_xff && flcf->risk_header.len > 0) {
        ngx_str_t v;
        if (ngx_http_fq_header(r, &flcf->risk_header, &v) == NGX_OK) {
            risk = ngx_http_fq_parse_risk(&v);
        }
    }

    volume = (ip_devices > 1) ? ip_devices : 1;
    penalty = (double) (volume - 1) * (double) flcf->penalty / 1000.0 * (double) N
            + risk * (double) flcf->risk_weight / 1000.0 * (double) N;

    anchor = (first_seen > flcf->start) ? first_seen : flcf->start;
    aging = (now > anchor)
            ? (double) (now - anchor) * (double) flcf->aging / 1000.0 : 0.0;
    aging_cap = (double) flcf->aging_cap / 1000.0 * span;
    if (aging > aging_cap) {
        aging = aging_cap;
    }

    effpen = penalty - aging;
    if (effpen < 0) {
        effpen = 0;
    }
    position = base + effpen;
    if (position < 0) {
        position = 0;
    }

    e->started = (now >= flcf->start);
    cursor = e->started
             ? (double) flcf->rate * (double) (now - flcf->start) / 1000.0 : 0.0;

    e->position = position;
    e->cursor = cursor;
    e->total = N;
    e->admitted = e->started && (position <= cursor);
    e->sale_in = (flcf->start > now) ? (flcf->start - now) : 0;

    if (e->admitted) {
        e->eta = 0;
    } else {
        double reach = (double) flcf->start + position * 1000.0 / (double) flcf->rate;
        double eta = reach - (double) now;
        e->eta = (eta > 0) ? eta : 0;
    }
}


/* Redirect a waiting visitor to the waiting page. Any Set-Cookie headers already
 * queued on the response are sent with the redirect. */
static ngx_int_t
ngx_http_fq_redirect(ngx_http_request_t *r, ngx_str_t *uri)
{
    ngx_table_elt_t  *loc;

    loc = ngx_list_push(&r->headers_out.headers);
    if (loc == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    loc->hash = 1;
#if (nginx_version >= 1023000)
    loc->next = NULL;
#endif
    ngx_str_set(&loc->key, "Location");
    loc->value = *uri;
    r->headers_out.location = loc;
    return NGX_HTTP_MOVED_TEMPORARILY;
}


/* ------------------------------------------------------------------------- */
/* Status view (read-only JSON)                                              */
/* ------------------------------------------------------------------------- */

static ngx_int_t
ngx_http_fq_send_json(ngx_http_request_t *r, ngx_str_t *body)
{
    ngx_int_t         rc;
    ngx_buf_t        *buf;
    ngx_chain_t       out;
    ngx_table_elt_t  *cc;

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = body->len;
    ngx_str_set(&r->headers_out.content_type, "application/json");
    r->headers_out.content_type_len = r->headers_out.content_type.len;

    cc = ngx_list_push(&r->headers_out.headers);
    if (cc == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    cc->hash = 1;
#if (nginx_version >= 1023000)
    cc->next = NULL;
#endif
    ngx_str_set(&cc->key, "Cache-Control");
    ngx_str_set(&cc->value, "no-store");

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    buf = ngx_create_temp_buf(r->pool, body->len);
    if (buf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_memcpy(buf->pos, body->data, body->len);
    buf->last = buf->pos + body->len;
    buf->last_buf = 1;
    buf->last_in_chain = 1;

    out.buf = buf;
    out.next = NULL;
    return ngx_http_output_filter(r, &out);
}


/*
 * Report the caller's queue state as JSON. This endpoint is strictly read-only:
 * it never registers a device, issues a token or sets a cookie, so it cannot be
 * used from a third-party page to enqueue a visitor. During registration it
 * withholds the fine-grained position so slots cannot be probed before the sale.
 */
static ngx_int_t
ngx_http_fairqueue_status_handler(ngx_http_request_t *r)
{
    ngx_http_fairqueue_loc_conf_t *flcf;
    ngx_http_fq_ctx_t             *ctx;
    ngx_str_t   idn = ngx_string("fq_id"), devn = ngx_string("fq_dev");
    ngx_str_t   rid, devid, ip, body;
    time_t      now = ngx_time(), fs, closed_in;
    ngx_uint_t  N = 0, rank = 0, ip_devices = 1;
    ngx_http_fq_eval_t  e;
    u_char     *b, *p;

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    flcf = ngx_http_get_module_loc_conf(r, ngx_http_fairqueue_module);

    if (ngx_http_fq_verify_cookie(r, &flcf->secret, &idn, "id", &rid) != NGX_OK
        || ngx_http_fq_verify_cookie(r, &flcf->secret, &devn, "dev", &devid)
           != NGX_OK)
    {
        ngx_str_set(&body, "{\"state\":\"redirect\",\"redirect\":\"/checkout\"}");
        return ngx_http_fq_send_json(r, &body);
    }

    if (ngx_http_fq_admission_valid(r, flcf, &rid, &devid) == NGX_OK) {
        ngx_str_set(&body, "{\"state\":\"admitted\",\"redirect\":\"/checkout\"}");
        return ngx_http_fq_send_json(r, &body);
    }

    if (flcf->waiting_start > now) {
        closed_in = flcf->waiting_start - now;
        b = ngx_pnalloc(r->pool, 64);
        if (b == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
        p = ngx_sprintf(b, "{\"state\":\"closed\",\"opens_in\":%T}", closed_in);
        body.data = b; body.len = p - b;
        return ngx_http_fq_send_json(r, &body);
    }

    if (flcf->shm_zone == NULL) {
        ngx_str_set(&body, "{\"state\":\"redirect\",\"redirect\":\"/checkout\"}");
        return ngx_http_fq_send_json(r, &body);
    }
    ctx = flcf->shm_zone->data;

    ip = ngx_http_fq_client_ip(r, flcf);
    if (ngx_http_fq_peek(ctx, devid.data, devid.len, ip.data, ip.len,
                         &fs, &N, &rank, &ip_devices) != NGX_OK)
    {
        ngx_str_set(&body, "{\"state\":\"redirect\",\"redirect\":\"/checkout\"}");
        return ngx_http_fq_send_json(r, &body);
    }

    ngx_http_fq_evaluate(r, flcf, &devid, fs, N, rank, ip_devices, now, &e);

    if (e.admitted) {
        ngx_str_set(&body, "{\"state\":\"admitted\",\"redirect\":\"/checkout\"}");
        return ngx_http_fq_send_json(r, &body);
    }

    b = ngx_pnalloc(r->pool, 256);
    if (b == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;

    if (!e.started) {
        p = ngx_sprintf(b, "{\"state\":\"waiting\",\"phase\":\"registration\","
                           "\"total\":%ui,\"sale_in\":%T}", e.total, e.sale_in);
    } else {
        p = ngx_sprintf(b, "{\"state\":\"waiting\",\"phase\":\"sale\","
                           "\"position\":%ui,\"total\":%ui,\"cursor\":%ui,"
                           "\"eta_seconds\":%ui}",
                        (ngx_uint_t) e.position, e.total,
                        (ngx_uint_t) e.cursor, (ngx_uint_t) e.eta);
    }
    body.data = b; body.len = p - b;
    return ngx_http_fq_send_json(r, &body);
}
