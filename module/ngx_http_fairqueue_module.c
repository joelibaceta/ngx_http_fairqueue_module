/*
 * ngx_http_fairqueue_module.c  —  FairQueue (módulo dinámico de Nginx)
 *
 * Port en C del prototipo validado (prototype/openresty/lua/fairqueue.lua).
 * Waiting room justo por hash + ventanas incrementales + admisión acotada por
 * tasa, con detección enchufable. Ver analysis/REPORT.md.
 *
 * ESTADO: Fase 0–1 (scaffolding).
 *   [x] Fase 0: el módulo carga; directiva de activación; handler en ACCESS phase.
 *   [x] Fase 1: directivas + structs de config + merge + parseo de rate/fracción.
 *   [ ] Fase 2: zona de memoria compartida (rbtree de devices + N + LRU).  TODO
 *   [ ] Fase 3: identidad (cookies) + HMAC + token de admisión.            TODO
 *   [ ] Fase 4: evaluate() (posición/cursor/penalty/aging).                TODO
 *   [ ] Fase 5: redirect a waiting room + endpoint /status (JSON).         TODO
 *   [ ] Fase 6: cap por IP + hook de riesgo + hardening.                   TODO
 *
 * El handler de esta fase solo loguea la config efectiva y devuelve
 * NGX_DECLINED (pasa el request sin tocarlo), para validar build/ABI y el
 * plumbing de directivas sin cambiar el comportamiento del sitio todavía.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_sha1.h>   /* SHA1 de serie en Nginx (para HMAC, sin OpenSSL) */


/* Fracciones (penalty, aging, headroom, risk) se guardan en PER-MILLE (×1000)
 * porque las directivas de Nginx no manejan floats. 0.02 -> 20. */
#define NGX_FQ_PERMILLE 1000

/* rate se guarda escalado ×1000 (req por segundo ×1000), como limit_req. */
#define NGX_FQ_RATE_SCALE 1000


typedef struct {
    ngx_flag_t   enable;

    ngx_shm_zone_t *shm_zone;      /* Fase 2: estado compartido */

    ngx_uint_t   rate;            /* req/seg ×1000 */
    time_t       start;          /* sale_start (epoch) */
    time_t       waiting_start;  /* apertura de registro (epoch); 0 = siempre */
    ngx_uint_t   token_ttl;      /* seg */

    ngx_uint_t   penalty;        /* fracción de N ×1000 (penalty_fraction) */
    ngx_uint_t   aging;          /* pos/seg ×1000 */
    ngx_uint_t   aging_cap;      /* fracción del span ×1000 */
    ngx_uint_t   headroom;       /* ×1000 */

    ngx_uint_t   allocation;     /* 0=hash, 1=fifo */
    ngx_str_t    scope;
    ngx_str_t    secret;

    ngx_str_t    risk_header;
    ngx_uint_t   risk_weight;    /* ×1000 */

    ngx_uint_t   max_devices_per_ip;
    ngx_flag_t   trust_xff;
    ngx_flag_t   cookie_secure;

    ngx_str_t    waiting_uri;

    ngx_flag_t   is_status;      /* este location es el endpoint /status (read-only) */
} ngx_http_fairqueue_loc_conf_t;


/* ----------------------------------------------------------------------------
 * Fase 2: estado en memoria compartida.
 *
 * rbtree de "participantes" (device) con cola LRU para expiración. N = nº de
 * participantes ACTIVOS: se incrementa al registrar un device nuevo y se
 * DECREMENTA al expirarlo por LRU/TTL => N refleja la demanda actual (cierra el
 * "N nunca decrementa / fantasmas" del red-team). Patrón calcado de
 * ngx_http_limit_req_module (rbtree + slab + queue + shmtx).
 * -------------------------------------------------------------------------- */

#define NGX_FQ_NODE_TTL   3600   /* seg sin actividad -> device expira (Fase 6: configurable) */

typedef struct {
    ngx_rbtree_node_t   node;        /* .key = crc32(devid); DEBE ir primero */
    ngx_queue_t         queue;       /* nodo en la lista LRU */
    time_t              first_seen;
    time_t              last_seen;
    ngx_uint_t          dev_count;   /* cuentas (rid) sobre este device (Fase 3) */
    ngx_uint_t          rank;        /* orden de llegada (allocation=fifo) */
    u_short             len;         /* long. de devid (para desempatar colisiones) */
    u_char              data[1];     /* devid */
} ngx_http_fq_node_t;

typedef struct {
    ngx_rbtree_t        rbtree;      /* devices */
    ngx_rbtree_node_t   sentinel;
    ngx_queue_t         queue;       /* LRU devices */
    ngx_atomic_t        n;           /* N = participantes activos */

    ngx_rbtree_t        iprbtree;    /* contadores de devices por IP */
    ngx_rbtree_node_t   ipsentinel;
    ngx_queue_t         ipqueue;     /* LRU IPs */
} ngx_http_fq_shctx_t;

typedef struct {
    ngx_http_fq_shctx_t *sh;
    ngx_slab_pool_t     *shpool;
    ngx_uint_t           rate;       /* rate base de la zona (req/seg ×1000) */
} ngx_http_fq_ctx_t;

/* Resultado de evaluate() (compartido por gate y /status). */
typedef struct {
    double      position;
    double      cursor;
    ngx_uint_t  total;      /* N activos */
    ngx_int_t   started;    /* now >= sale_start */
    ngx_int_t   admitted;
    time_t      sale_in;    /* seg hasta sale_start (0 si ya abrió) */
    double      eta;        /* seg estimados hasta admisión */
} ngx_http_fq_eval_t;


static ngx_int_t ngx_http_fairqueue_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_fairqueue_init(ngx_conf_t *cf);
static void *ngx_http_fairqueue_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_fairqueue_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);

/* parsers a medida */
static char *ngx_http_fairqueue_enable(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_fairqueue_set_rate(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_fairqueue_set_permille(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_fairqueue_set_alloc(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

/* Fase 2: zona compartida */
static char *ngx_http_fairqueue_zone(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_fq_init_zone(ngx_shm_zone_t *shm_zone, void *data);
static ngx_http_fq_node_t *fq_rb_lookup(ngx_rbtree_t *tree,
    ngx_uint_t hash, u_char *data, size_t len);
static void fq_rb_expire(ngx_rbtree_t *tree, ngx_queue_t *queue,
    ngx_atomic_t *counter, ngx_slab_pool_t *shpool, time_t now, ngx_uint_t force);
static ngx_uint_t fq_ip_touch(ngx_http_fq_ctx_t *ctx, u_char *ip, size_t iplen,
    time_t now, ngx_int_t create, ngx_uint_t cap, ngx_int_t *limited);
static void ngx_http_fq_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
static time_t ngx_http_fq_register(ngx_http_fq_ctx_t *ctx,
    u_char *devid, size_t devlen, u_char *ip, size_t iplen, ngx_uint_t cap,
    time_t now, ngx_uint_t *n_out, ngx_uint_t *rank_out,
    ngx_uint_t *ip_devices_out, ngx_int_t *limited);
static ngx_str_t fq_client_ip(ngx_http_request_t *r,
    ngx_http_fairqueue_loc_conf_t *flcf);

/* Fase 3: identidad / crypto */
static ngx_int_t ngx_http_fq_resolve_identity(ngx_http_request_t *r,
    ngx_http_fairqueue_loc_conf_t *flcf, ngx_str_t *rid, ngx_str_t *devid);
static ngx_int_t ngx_http_fq_admission_valid(ngx_http_request_t *r,
    ngx_http_fairqueue_loc_conf_t *flcf, ngx_str_t *rid, ngx_str_t *devid);
static ngx_int_t ngx_http_fq_issue_admission(ngx_http_request_t *r,
    ngx_http_fairqueue_loc_conf_t *flcf, ngx_str_t *rid, ngx_str_t *devid);
/* Fase 4: posición / admisión */
static double fq_frac(ngx_str_t *secret, u_char *data, size_t dlen);
static ngx_int_t fq_redirect(ngx_http_request_t *r, ngx_str_t *uri);
static void ngx_http_fq_evaluate(ngx_http_request_t *r,
    ngx_http_fairqueue_loc_conf_t *flcf, ngx_str_t *devid, time_t first_seen,
    ngx_uint_t N, ngx_uint_t rank, ngx_uint_t ip_devices, time_t now,
    ngx_http_fq_eval_t *e);

/* Fase 5: endpoint /status (read-only) */
static char *ngx_http_fairqueue_status(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_fairqueue_status_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_fq_peek(ngx_http_fq_ctx_t *ctx, u_char *devid,
    size_t devlen, u_char *ip, size_t iplen, time_t *first_seen, ngx_uint_t *N,
    ngx_uint_t *rank, ngx_uint_t *ip_devices);
static ngx_int_t ngx_http_fq_send_json(ngx_http_request_t *r, ngx_str_t *body);


static ngx_command_t  ngx_http_fairqueue_commands[] = {

    { ngx_string("fairqueue_zone"),  /* fairqueue_zone name zone=NAME:SIZE rate=.. */
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE23,
      ngx_http_fairqueue_zone,
      0, 0, NULL },

    { ngx_string("fairqueue"),   /* fairqueue on | <zona> */
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_http_fairqueue_enable,
      NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },

    { ngx_string("fairqueue_status"),  /* endpoint JSON read-only */
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_fairqueue_status,
      NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },

    { ngx_string("fairqueue_rate"),          /* 500r/m | r/s | r/h */
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_fairqueue_set_rate,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fairqueue_loc_conf_t, rate), NULL },

    { ngx_string("fairqueue_start"),         /* epoch (TODO: ISO8601) */
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fairqueue_loc_conf_t, start), NULL },

    { ngx_string("fairqueue_waiting_start"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fairqueue_loc_conf_t, waiting_start), NULL },

    { ngx_string("fairqueue_token_ttl"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fairqueue_loc_conf_t, token_ttl), NULL },

    { ngx_string("fairqueue_penalty"),       /* fracción de N (0.02) */
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_fairqueue_set_permille,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fairqueue_loc_conf_t, penalty), NULL },

    { ngx_string("fairqueue_aging"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_fairqueue_set_permille,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fairqueue_loc_conf_t, aging), NULL },

    { ngx_string("fairqueue_aging_cap"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_fairqueue_set_permille,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fairqueue_loc_conf_t, aging_cap), NULL },

    { ngx_string("fairqueue_window_headroom"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_fairqueue_set_permille,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fairqueue_loc_conf_t, headroom), NULL },

    { ngx_string("fairqueue_allocation"),    /* hash | fifo */
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_fairqueue_set_alloc,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fairqueue_loc_conf_t, allocation), NULL },

    { ngx_string("fairqueue_scope"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fairqueue_loc_conf_t, scope), NULL },

    { ngx_string("fairqueue_secret"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fairqueue_loc_conf_t, secret), NULL },

    { ngx_string("fairqueue_risk_header"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fairqueue_loc_conf_t, risk_header), NULL },

    { ngx_string("fairqueue_risk_weight"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_fairqueue_set_permille,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fairqueue_loc_conf_t, risk_weight), NULL },

    { ngx_string("fairqueue_max_devices_per_ip"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fairqueue_loc_conf_t, max_devices_per_ip), NULL },

    { ngx_string("fairqueue_trust_xff"),
      NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fairqueue_loc_conf_t, trust_xff), NULL },

    { ngx_string("fairqueue_cookie_secure"),
      NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fairqueue_loc_conf_t, cookie_secure), NULL },

    { ngx_string("fairqueue_waiting_uri"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fairqueue_loc_conf_t, waiting_uri), NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_fairqueue_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_fairqueue_init,               /* postconfiguration */
    NULL,                                  /* create main conf */
    NULL,                                  /* init main conf */
    NULL,                                  /* create srv conf */
    NULL,                                  /* merge srv conf */
    ngx_http_fairqueue_create_loc_conf,    /* create loc conf */
    ngx_http_fairqueue_merge_loc_conf      /* merge loc conf */
};


ngx_module_t  ngx_http_fairqueue_module = {
    NGX_MODULE_V1,
    &ngx_http_fairqueue_module_ctx,
    ngx_http_fairqueue_commands,
    NGX_HTTP_MODULE,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NGX_MODULE_V1_PADDING
};


/* ---- handler (Fase 0: no-op que loguea; Fase 3-5 lo llenan) ---- */
static ngx_int_t
ngx_http_fairqueue_handler(ngx_http_request_t *r)
{
    ngx_http_fairqueue_loc_conf_t  *flcf;

    flcf = ngx_http_get_module_loc_conf(r, ngx_http_fairqueue_module);

    /* El endpoint /status tiene su propio content handler (read-only): no gatear. */
    if (!flcf->enable || flcf->is_status) {
        return NGX_DECLINED;
    }

    /* Fase 2: si hay zona, ejercitamos el shm registrando por remote_addr como
     * PLACEHOLDER del devid (Fase 3 lo reemplaza por la cookie firmada). Esto
     * valida rbtree + N + LRU en runtime. Seguimos devolviendo NGX_DECLINED. */
    if (!flcf->shm_zone) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
            "fairqueue: uri=\"%V\" sin zona (Fase <2, pass-through)", &r->uri);
        return NGX_DECLINED;
    }

    {
    ngx_http_fq_ctx_t   *ctx = flcf->shm_zone->data;
    ngx_uint_t           N = 0, rank = 0, ip_devices = 1;
    ngx_int_t            limited = 0;
    ngx_str_t            rid, devid, ip;
    time_t               now = ngx_time(), fs;
    ngx_http_fq_eval_t   e;

    /* Fase 3: identidad por cookies firmadas (acuña si faltan). */
    if (ngx_http_fq_resolve_identity(r, flcf, &rid, &devid) != NGX_OK) {
        return NGX_DECLINED;
    }

    /* Fast-path: token de admisión válido -> pasa directo al contenido/proxy. */
    if (ngx_http_fq_admission_valid(r, flcf, &rid, &devid) == NGX_OK) {
        return NGX_DECLINED;
    }

    ip = fq_client_ip(r, flcf);
    fs = ngx_http_fq_register(ctx, devid.data, devid.len, ip.data, ip.len,
                              flcf->max_devices_per_ip, now,
                              &N, &rank, &ip_devices, &limited);
    if (limited) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
            "fairqueue: uri=\"%V\" ip=\"%V\" RATE_LIMITED (cap por IP) -> %V",
            &r->uri, &ip, &flcf->waiting_uri);
        return fq_redirect(r, &flcf->waiting_uri);
    }

    ngx_http_fq_evaluate(r, flcf, &devid, fs, N, rank, ip_devices, now, &e);

    if (e.admitted) {
        ngx_http_fq_issue_admission(r, flcf, &rid, &devid);
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
            "fairqueue: uri=\"%V\" rid=\"%V\" ADMITIDO pos=%ui cursor=%ui N=%ui",
            &r->uri, &rid, (ngx_uint_t) e.position, (ngx_uint_t) e.cursor, N);
        return NGX_DECLINED;          /* -> contenido / proxy_pass */
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
        "fairqueue: uri=\"%V\" rid=\"%V\" WAITING pos=%ui cursor=%ui N=%ui -> %V",
        &r->uri, &rid, (ngx_uint_t) e.position, (ngx_uint_t) e.cursor, N,
        &flcf->waiting_uri);
    return fq_redirect(r, &flcf->waiting_uri);
    }
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


static void *
ngx_http_fairqueue_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_fairqueue_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_fairqueue_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /* ngx_pcalloc deja todo en 0; marcamos lo que necesita UNSET para merge. */
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
    ngx_conf_merge_uint_value(conf->rate, prev->rate, 500 * NGX_FQ_RATE_SCALE / 60); /* 500r/m */
    ngx_conf_merge_sec_value(conf->start, prev->start, 0);
    ngx_conf_merge_sec_value(conf->waiting_start, prev->waiting_start, 0);
    ngx_conf_merge_uint_value(conf->token_ttl, prev->token_ttl, 300);
    ngx_conf_merge_uint_value(conf->penalty, prev->penalty, 20);     /* 0.02 */
    ngx_conf_merge_uint_value(conf->aging, prev->aging, 500);        /* 0.5 */
    ngx_conf_merge_uint_value(conf->aging_cap, prev->aging_cap, 100);/* 0.1 */
    ngx_conf_merge_uint_value(conf->headroom, prev->headroom, 200);  /* 0.2 */
    ngx_conf_merge_uint_value(conf->allocation, prev->allocation, 0);/* hash */
    ngx_conf_merge_str_value(conf->scope, prev->scope, "default");
    ngx_conf_merge_str_value(conf->secret, prev->secret, "");
    ngx_conf_merge_str_value(conf->risk_header, prev->risk_header, "");
    ngx_conf_merge_uint_value(conf->risk_weight, prev->risk_weight, 500); /* 0.5 */
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

    /* FAIL-CLOSED: sin secreto, cualquiera forja cookies/tokens. Abortar. */
    if (conf->enable && conf->secret.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "fairqueue: \"fairqueue_secret\" es obligatorio donde fairqueue está "
            "activo");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


/* ---- parsers a medida ---- */

static char *
ngx_http_fairqueue_enable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_fairqueue_loc_conf_t *flcf = conf;
    ngx_str_t                     *value = cf->args->elts;
    ngx_shm_zone_t                *zone;

    if (ngx_strcmp(value[1].data, "on") == 0) {
        flcf->enable = 1;
        flcf->shm_zone = NULL;    /* sin zona: Fase <2 (handler no usa shm) */
        return NGX_CONF_OK;
    }
    if (ngx_strcmp(value[1].data, "off") == 0) {
        flcf->enable = 0;
        return NGX_CONF_OK;
    }

    /* El argumento es el nombre de una zona definida por fairqueue_zone. */
    zone = ngx_shared_memory_add(cf, &value[1], 0, &ngx_http_fairqueue_module);
    if (zone == NULL) {
        return NGX_CONF_ERROR;
    }
    flcf->enable = 1;
    flcf->shm_zone = zone;
    return NGX_CONF_OK;
}


/* Parsea "NNNr/m" | "NNNr/s" | "NNNr/h" -> req/seg ×1000 (como limit_req). */
static char *
ngx_http_fairqueue_set_rate(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_fairqueue_loc_conf_t *flcf = conf;
    ngx_str_t                     *value = cf->args->elts;
    ngx_str_t                      s = value[1];
    ngx_uint_t                     n, scale_div;
    u_char                        *p, *last;

    last = s.data + s.len;
    for (p = s.data; p < last && *p >= '0' && *p <= '9'; p++) { /* num */ }

    n = ngx_atoi(s.data, p - s.data);
    if (n == (ngx_uint_t) NGX_ERROR || p == s.data) {
        return "tasa inválida";
    }

    if (ngx_strncmp(p, "r/s", 3) == 0)      scale_div = 1;
    else if (ngx_strncmp(p, "r/m", 3) == 0) scale_div = 60;
    else if (ngx_strncmp(p, "r/h", 3) == 0) scale_div = 3600;
    else return "tasa inválida (usar r/s, r/m o r/h)";

    /* req/seg ×1000 */
    flcf->rate = (ngx_uint_t) (n * NGX_FQ_RATE_SCALE / scale_div);
    if (flcf->rate == 0) {
        flcf->rate = 1; /* clamp >0 (robustez, red-team) */
    }
    return NGX_CONF_OK;
}


/* Parsea un decimal "0.02" -> per-mille (20). Acepta "N" o "N.mmm". */
static char *
ngx_http_fairqueue_set_permille(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char      *base = conf;
    ngx_uint_t *field = (ngx_uint_t *) (base + cmd->offset);
    ngx_str_t  *value = cf->args->elts;
    ngx_str_t   s = value[1];
    ngx_uint_t  intpart = 0, frac = 0, scale = 100;
    u_char     *p, *last;
    ngx_uint_t  seen_dot = 0;

    last = s.data + s.len;
    for (p = s.data; p < last; p++) {
        if (*p == '.') { seen_dot = 1; continue; }
        if (*p < '0' || *p > '9') {
            return "fracción inválida";
        }
        if (!seen_dot) {
            intpart = intpart * 10 + (*p - '0');
        } else if (scale > 0) {
            frac += (*p - '0') * scale;   /* 3 decimales -> per-mille */
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
    else return "allocation inválida (hash | fifo)";

    return NGX_CONF_OK;
}


/* ===========================================================================
 * Fase 2: memoria compartida (rbtree de devices + N activo + LRU)
 * ======================================================================== */

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


/* lookup genérico en un rbtree (device o IP) */
static ngx_http_fq_node_t *
fq_rb_lookup(ngx_rbtree_t *tree, ngx_uint_t hash, u_char *data, size_t len)
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

/* Expira hasta 2 nodos stale del tail de la LRU de un rbtree. Si counter!=NULL
 * (árbol de devices) lo decrementa (N = conteo activo). */
static void
fq_rb_expire(ngx_rbtree_t *tree, ngx_queue_t *queue, ngx_atomic_t *counter,
    ngx_slab_pool_t *shpool, time_t now, ngx_uint_t force)
{
    ngx_queue_t        *q;
    ngx_http_fq_node_t *fqn;
    ngx_uint_t          i;

    for (i = 0; i < 2; i++) {
        if (ngx_queue_empty(queue)) {
            return;
        }
        q = ngx_queue_last(queue);
        fqn = ngx_queue_data(q, ngx_http_fq_node_t, queue);

        if (!force && (now - fqn->last_seen) < NGX_FQ_NODE_TTL) {
            return;
        }
        ngx_queue_remove(q);
        ngx_rbtree_delete(tree, &fqn->node);
        if (counter && *counter > 0) {
            (*counter)--;
        }
        ngx_slab_free_locked(shpool, fqn);
    }
}

/* Contador de devices por IP. create=1 cuenta un device NUEVO para esta IP.
 * Debe llamarse con el shmtx ya tomado. Devuelve el conteo resultante; si
 * create y el conteo superaría cap, setea *limited y NO cuenta. */
static ngx_uint_t
fq_ip_touch(ngx_http_fq_ctx_t *ctx, u_char *ip, size_t iplen, time_t now,
    ngx_int_t create, ngx_uint_t cap, ngx_int_t *limited)
{
    ngx_uint_t          hash;
    ngx_http_fq_node_t *ipn;
    size_t              size;

    if (limited) *limited = 0;
    if (iplen == 0) return 1;

    hash = ngx_crc32_short(ip, iplen);
    ipn = fq_rb_lookup(&ctx->sh->iprbtree, hash, ip, iplen);

    if (!create) {
        return ipn ? ipn->dev_count : 0;
    }

    if (ipn) {
        if (ipn->dev_count >= cap) {
            if (limited) *limited = 1;
            return ipn->dev_count;
        }
        ipn->dev_count++;
        ipn->last_seen = now;
        ngx_queue_remove(&ipn->queue);
        ngx_queue_insert_head(&ctx->sh->ipqueue, &ipn->queue);
        return ipn->dev_count;
    }

    if (cap == 0) {              /* cap 0 => imposible admitir nada */
        if (limited) *limited = 1;
        return 0;
    }

    size = offsetof(ngx_http_fq_node_t, data) + iplen;
    ipn = ngx_slab_alloc_locked(ctx->shpool, size);
    if (ipn == NULL) {
        fq_rb_expire(&ctx->sh->iprbtree, &ctx->sh->ipqueue, NULL,
                     ctx->shpool, now, 1);
        ipn = ngx_slab_alloc_locked(ctx->shpool, size);
    }
    if (ipn == NULL) {
        return 1;   /* degradado: no contamos la IP */
    }
    ipn->node.key = hash;
    ipn->len = (u_short) iplen;
    ngx_memcpy(ipn->data, ip, iplen);
    ipn->first_seen = now;
    ipn->last_seen = now;
    ipn->dev_count = 1;
    ipn->rank = 0;
    ngx_rbtree_insert(&ctx->sh->iprbtree, &ipn->node);
    ngx_queue_insert_head(&ctx->sh->ipqueue, &ipn->queue);
    return 1;
}

/* Registra device + aplica cap por IP. Idempotente. Bajo shmtx.
 * Entrega first_seen, N, rank, ip_devices; y *limited si la IP superó el cap. */
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
    ngx_int_t           lim = 0;

    if (limited) *limited = 0;
    hash = ngx_crc32_short(devid, devlen);

    ngx_shmtx_lock(&ctx->shpool->mutex);

    fq_rb_expire(&ctx->sh->rbtree, &ctx->sh->queue, &ctx->sh->n,
                 ctx->shpool, now, 0);
    fq_rb_expire(&ctx->sh->iprbtree, &ctx->sh->ipqueue, NULL,
                 ctx->shpool, now, 0);

    fqn = fq_rb_lookup(&ctx->sh->rbtree, hash, devid, devlen);

    if (fqn) {
        fqn->last_seen = now;
        ngx_queue_remove(&fqn->queue);
        ngx_queue_insert_head(&ctx->sh->queue, &fqn->queue);
        first_seen = fqn->first_seen;
        if (rank_out) *rank_out = fqn->rank;
        ipd = fq_ip_touch(ctx, ip, iplen, now, 0, cap, NULL);  /* peek */

    } else {
        /* device NUEVO: primero el cap por IP (cuenta este device). */
        ipd = fq_ip_touch(ctx, ip, iplen, now, 1, cap, &lim);
        if (lim) {
            if (limited) *limited = 1;
            if (rank_out) *rank_out = 0;
            if (ip_devices_out) *ip_devices_out = ipd;
            if (n_out) *n_out = (ngx_uint_t) ctx->sh->n;
            ngx_shmtx_unlock(&ctx->shpool->mutex);
            return now;
        }

        size = offsetof(ngx_http_fq_node_t, data) + devlen;
        fqn = ngx_slab_alloc_locked(ctx->shpool, size);
        if (fqn == NULL) {
            fq_rb_expire(&ctx->sh->rbtree, &ctx->sh->queue, &ctx->sh->n,
                         ctx->shpool, now, 1);
            fqn = ngx_slab_alloc_locked(ctx->shpool, size);
        }
        if (fqn == NULL) {
            if (rank_out) *rank_out = 0;
            if (ip_devices_out) *ip_devices_out = ipd;
            if (n_out) *n_out = (ngx_uint_t) ctx->sh->n;
            ngx_shmtx_unlock(&ctx->shpool->mutex);
            return now;
        }

        fqn->node.key = hash;
        fqn->len = (u_short) devlen;
        ngx_memcpy(fqn->data, devid, devlen);
        fqn->first_seen = now;
        fqn->last_seen = now;
        fqn->dev_count = 1;
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


static ngx_int_t
ngx_http_fq_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_http_fq_ctx_t *octx = data;
    ngx_http_fq_ctx_t *ctx = shm_zone->data;
    ngx_slab_pool_t   *shpool;

    if (octx) {                      /* reload: reutiliza el shm existente */
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
    ngx_queue_init(&ctx->sh->ipqueue);

    return NGX_OK;
}


/* fairqueue_zone zone=NAME:SIZE [rate=Nr/m]  (contexto http) */
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
                    "fairqueue_zone: formato zone=NAME:SIZE");
                return NGX_CONF_ERROR;
            }
            name.data = p;
            name.len = sep - p;
            ss.data = sep + 1;
            ss.len = value[i].data + value[i].len - (sep + 1);
            size = ngx_parse_size(&ss);
            if (size == NGX_ERROR || size < (ssize_t) (8 * ngx_pagesize)) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "fairqueue_zone: tamaño inválido (mínimo 8 páginas)");
                return NGX_CONF_ERROR;
            }
            continue;
        }

        if (ngx_strncmp(value[i].data, "rate=", 5) == 0) {
            q = value[i].data + 5;
            last = value[i].data + value[i].len;
            for (p = q; p < last && *p >= '0' && *p <= '9'; p++) { /* num */ }
            num = ngx_atoi(q, p - q);
            if (num == (ngx_uint_t) NGX_ERROR || p == q) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "fairqueue_zone: rate inválido");
                return NGX_CONF_ERROR;
            }
            if (ngx_strncmp(p, "r/s", 3) == 0) div = 1;
            else if (ngx_strncmp(p, "r/m", 3) == 0) div = 60;
            else if (ngx_strncmp(p, "r/h", 3) == 0) div = 3600;
            else {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "fairqueue_zone: rate usar Nr/s|r/m|r/h");
                return NGX_CONF_ERROR;
            }
            rate = num * NGX_FQ_RATE_SCALE / div;
            if (rate == 0) rate = 1;
            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "fairqueue_zone: parámetro desconocido \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }

    if (name.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "fairqueue_zone: falta zone=NAME:SIZE");
        return NGX_CONF_ERROR;
    }

    shm_zone = ngx_shared_memory_add(cf, &name, size, &ngx_http_fairqueue_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }
    if (shm_zone->data) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "fairqueue_zone: zona \"%V\" duplicada", &name);
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


/* ===========================================================================
 * Fase 3: identidad (cookies firmadas) + crypto (HMAC-SHA1 con SHA1 de Nginx)
 * ======================================================================== */

/* HMAC-SHA1(key, data) -> out[20]. Construcción estándar (ipad/opad). */
static void
fq_hmac_sha1(u_char *key, size_t klen, u_char *data, size_t dlen, u_char out[20])
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

/* HMAC hex (40 chars, sin null) en outhex. */
static void
fq_hmac_hex(ngx_str_t *secret, u_char *data, size_t dlen, u_char *outhex)
{
    u_char mac[20];
    fq_hmac_sha1(secret->data, secret->len, data, dlen, mac);
    ngx_hex_dump(outhex, mac, 20);
}

/* comparación en tiempo constante */
static ngx_int_t
fq_ct_eq(u_char *a, u_char *b, size_t n)
{
    u_char      d = 0;
    size_t      i;
    for (i = 0; i < n; i++) {
        d |= (u_char) (a[i] ^ b[i]);
    }
    return d == 0;
}

/* id aleatorio de 16 bytes -> 32 hex (en el pool del request) */
static void
fq_new_id(ngx_pool_t *pool, ngx_str_t *out)
{
    u_char      raw[16];
    ngx_uint_t  i;

    for (i = 0; i < 16; i++) {
        raw[i] = (u_char) ngx_random();
    }
    out->data = ngx_pnalloc(pool, 32);
    if (out->data == NULL) { out->len = 0; return; }
    ngx_hex_dump(out->data, raw, 16);
    out->len = 32;
}

/* lee una cookie por nombre */
static ngx_int_t
fq_cookie(ngx_http_request_t *r, ngx_str_t *name, ngx_str_t *val)
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

/* agrega un header Set-Cookie */
static ngx_int_t
fq_add_set_cookie(ngx_http_request_t *r, ngx_str_t *cookie)
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

/* valor firmado = "<rid>.<hmac_hex(prefix:rid)>" */
static ngx_int_t
fq_sign_value(ngx_pool_t *pool, ngx_str_t *secret, const char *prefix,
    ngx_str_t *rid, ngx_str_t *out)
{
    size_t   plen = ngx_strlen(prefix);
    u_char  *msg, *p, sig[40];

    msg = ngx_pnalloc(pool, plen + 1 + rid->len);
    if (msg == NULL) return NGX_ERROR;
    p = ngx_cpymem(msg, (u_char *) prefix, plen);
    *p++ = ':';
    ngx_memcpy(p, rid->data, rid->len);

    fq_hmac_hex(secret, msg, plen + 1 + rid->len, sig);

    out->data = ngx_pnalloc(pool, rid->len + 1 + 40);
    if (out->data == NULL) return NGX_ERROR;
    p = ngx_cpymem(out->data, rid->data, rid->len);
    *p++ = '.';
    ngx_memcpy(p, sig, 40);
    out->len = rid->len + 1 + 40;
    return NGX_OK;
}

/* lee cookie <cookiename>, verifica firma sobre prefix, devuelve rid */
static ngx_int_t
fq_cookie_verify(ngx_http_request_t *r, ngx_str_t *secret, ngx_str_t *cookiename,
    const char *prefix, ngx_str_t *rid)
{
    ngx_str_t  v, ridpart;
    size_t     plen = ngx_strlen(prefix);
    u_char    *msg, *p, *sig, calc[40];

    if (fq_cookie(r, cookiename, &v) != NGX_OK) return NGX_DECLINED;
    if (v.len < 1 + 1 + 40) return NGX_DECLINED;      /* rid + '.' + sig */
    if (v.data[v.len - 41] != '.') return NGX_DECLINED;

    ridpart.data = v.data;
    ridpart.len = v.len - 41;
    sig = v.data + v.len - 40;

    msg = ngx_pnalloc(r->pool, plen + 1 + ridpart.len);
    if (msg == NULL) return NGX_ERROR;
    p = ngx_cpymem(msg, (u_char *) prefix, plen);
    *p++ = ':';
    ngx_memcpy(p, ridpart.data, ridpart.len);

    fq_hmac_hex(secret, msg, plen + 1 + ridpart.len, calc);
    if (!fq_ct_eq(calc, sig, 40)) return NGX_DECLINED;

    *rid = ridpart;
    return NGX_OK;
}

/* emite cookie firmada name=<rid.sig> con atributos */
static ngx_int_t
fq_set_signed_cookie(ngx_http_request_t *r,
    ngx_http_fairqueue_loc_conf_t *flcf, const char *name, const char *prefix,
    ngx_str_t *rid, time_t max_age)
{
    ngx_str_t  val, cookie;
    u_char    *b, *p;
    size_t     cap;

    if (fq_sign_value(r->pool, &flcf->secret, prefix, rid, &val) != NGX_OK) {
        return NGX_ERROR;
    }
    cap = ngx_strlen(name) + 1 + val.len + 96;
    b = ngx_pnalloc(r->pool, cap);
    if (b == NULL) return NGX_ERROR;

    p = ngx_sprintf(b, "%s=%V; Path=/; SameSite=Lax; HttpOnly", name, &val);
    if (flcf->cookie_secure) {
        p = ngx_cpymem(p, "; Secure", 8);
    }
    if (max_age > 0) {
        p = ngx_sprintf(p, "; Max-Age=%T", max_age);
    }
    cookie.data = b;
    cookie.len = p - b;
    return fq_add_set_cookie(r, &cookie);
}

/* firma del token de admisión = HMAC(secret, "adm:scope:start:devid:rid:exp") */
static void
fq_adm_sig(ngx_http_request_t *r, ngx_http_fairqueue_loc_conf_t *flcf,
    ngx_str_t *rid, ngx_str_t *devid, time_t exp, u_char outhex[40])
{
    u_char  *msg, *p;
    size_t   cap;

    cap = 4 + flcf->scope.len + 1 + NGX_TIME_T_LEN + 1 + devid->len + 1
          + rid->len + 1 + NGX_TIME_T_LEN + 1;
    msg = ngx_pnalloc(r->pool, cap);
    if (msg == NULL) { ngx_memzero(outhex, 40); return; }

    p = ngx_sprintf(msg, "adm:%V:%T:%V:%V:%T",
                    &flcf->scope, flcf->start, devid, rid, exp);
    fq_hmac_hex(&flcf->secret, msg, p - msg, outhex);
}

static ngx_int_t
ngx_http_fq_issue_admission(ngx_http_request_t *r,
    ngx_http_fairqueue_loc_conf_t *flcf, ngx_str_t *rid, ngx_str_t *devid)
{
    time_t     exp = ngx_time() + (time_t) flcf->token_ttl;
    u_char     sig[40], *b, *p;
    ngx_str_t  val, cookie;

    fq_adm_sig(r, flcf, rid, devid, exp, sig);

    b = ngx_pnalloc(r->pool, rid->len + 1 + NGX_TIME_T_LEN + 1 + 40);
    if (b == NULL) return NGX_ERROR;
    p = ngx_sprintf(b, "%V.%T.", rid, exp);
    p = ngx_cpymem(p, sig, 40);
    val.data = b;
    val.len = p - b;

    b = ngx_pnalloc(r->pool, val.len + 96);
    if (b == NULL) return NGX_ERROR;
    p = ngx_sprintf(b, "fq_adm=%V; Path=/; SameSite=Lax; HttpOnly", &val);
    if (flcf->cookie_secure) p = ngx_cpymem(p, "; Secure", 8);
    p = ngx_sprintf(p, "; Max-Age=%ui", flcf->token_ttl);
    cookie.data = b;
    cookie.len = p - b;
    return fq_add_set_cookie(r, &cookie);
}

static ngx_int_t
ngx_http_fq_admission_valid(ngx_http_request_t *r,
    ngx_http_fairqueue_loc_conf_t *flcf, ngx_str_t *rid, ngx_str_t *devid)
{
    ngx_str_t   name = ngx_string("fq_adm");
    ngx_str_t   v, trid, expstr;
    u_char     *dot1, *dot2, *sig, calc[40];
    time_t      exp;

    if (fq_cookie(r, &name, &v) != NGX_OK) return NGX_DECLINED;
    if (v.len < 1 + 1 + 1 + 1 + 40) return NGX_DECLINED;
    if (v.data[v.len - 41] != '.') return NGX_DECLINED;

    dot2 = v.data + v.len - 41;                 /* '.' antes de la firma */
    sig = v.data + v.len - 40;
    dot1 = ngx_strlchr(v.data, dot2, '.');      /* '.' entre rid y exp */
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
    if (exp == NGX_ERROR || exp < ngx_time()) return NGX_DECLINED;

    fq_adm_sig(r, flcf, &trid, devid, exp, calc);
    if (!fq_ct_eq(calc, sig, 40)) return NGX_DECLINED;

    return NGX_OK;
}

static ngx_int_t
ngx_http_fq_resolve_identity(ngx_http_request_t *r,
    ngx_http_fairqueue_loc_conf_t *flcf, ngx_str_t *rid, ngx_str_t *devid)
{
    ngx_str_t  idn = ngx_string("fq_id");
    ngx_str_t  devn = ngx_string("fq_dev");

    if (fq_cookie_verify(r, &flcf->secret, &idn, "id", rid) != NGX_OK) {
        fq_new_id(r->pool, rid);
        if (rid->len == 0) return NGX_ERROR;
        if (fq_set_signed_cookie(r, flcf, "fq_id", "id", rid, 0) != NGX_OK) {
            return NGX_ERROR;
        }
    }
    if (fq_cookie_verify(r, &flcf->secret, &devn, "dev", devid) != NGX_OK) {
        fq_new_id(r->pool, devid);
        if (devid->len == 0) return NGX_ERROR;
        if (fq_set_signed_cookie(r, flcf, "fq_dev", "dev", devid,
                                 60 * 60 * 24 * 30) != NGX_OK)
        {
            return NGX_ERROR;
        }
    }
    return NGX_OK;
}


/* ===========================================================================
 * Fase 4: posición (frac) + redirect al waiting room
 * ======================================================================== */

/* frac determinístico en [0,1) a partir de 6 bytes (48 bits) del HMAC. */
static double
fq_frac(ngx_str_t *secret, u_char *data, size_t dlen)
{
    u_char    mac[20];
    uint64_t  v;

    fq_hmac_sha1(secret->data, secret->len, data, dlen, mac);
    v = ((uint64_t) mac[0] << 40) | ((uint64_t) mac[1] << 32)
      | ((uint64_t) mac[2] << 24) | ((uint64_t) mac[3] << 16)
      | ((uint64_t) mac[4] << 8)  | (uint64_t) mac[5];
    return (double) v / 281474976710656.0;      /* 2^48 */
}

/* 302 al waiting room (los Set-Cookie ya agregados viajan con la respuesta). */
static ngx_int_t
fq_redirect(ngx_http_request_t *r, ngx_str_t *uri)
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

/* busca un header de request por nombre (case-insensitive) */
static ngx_int_t
fq_req_header(ngx_http_request_t *r, ngx_str_t *name, ngx_str_t *val)
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

/* parsea un decimal 0..1 de un header (sin libm); clamp a [0,1] */
static double
fq_parse_risk(ngx_str_t *s)
{
    double   v = 0.0, scale = 0.1;
    u_char  *p = s->data, *last = s->data + s->len;
    ngx_int_t seen_dot = 0;

    for (; p < last; p++) {
        if (*p == '.') { seen_dot = 1; continue; }
        if (*p < '0' || *p > '9') break;
        if (!seen_dot) { v = v * 10.0 + (*p - '0'); }
        else { v += (*p - '0') * scale; scale /= 10.0; }
    }
    if (v < 0.0) v = 0.0;
    if (v > 1.0) v = 1.0;
    return v;
}

/* evaluate() compartido por gate() y /status. aging erosiona SOLO la
 * penalización; nadie admitido antes de start. */
static void
ngx_http_fq_evaluate(ngx_http_request_t *r, ngx_http_fairqueue_loc_conf_t *flcf,
    ngx_str_t *devid, time_t first_seen, ngx_uint_t N, ngx_uint_t rank,
    ngx_uint_t ip_devices, time_t now, ngx_http_fq_eval_t *e)
{
    double     span, base, penalty, aging, aging_cap, effpen, position, cursor, frac;
    double     risk = 0.0;
    time_t     anchor;
    u_char    *msg, *p;
    size_t     cap;
    ngx_uint_t volume;

    span = (double) N * (1000.0 + (double) flcf->headroom) / 1000.0;

    if (flcf->allocation == 1) {            /* fifo */
        base = (double) rank;
    } else {
        cap = flcf->scope.len + 1 + NGX_TIME_T_LEN + 1 + devid->len + 1;
        msg = ngx_pnalloc(r->pool, cap);
        if (msg == NULL) {
            base = 0;
        } else {
            p = ngx_sprintf(msg, "%V:%T:%V", &flcf->scope, flcf->start, devid);
            frac = fq_frac(&flcf->secret, msg, p - msg);
            base = (double) (ngx_uint_t) (frac * span);   /* floor sin libm */
        }
    }

    /* Señal de riesgo externa (gated con trust_xff: solo detrás de proxy fiable). */
    if (flcf->trust_xff && flcf->risk_header.len > 0) {
        ngx_str_t v;
        if (fq_req_header(r, &flcf->risk_header, &v) == NGX_OK) {
            risk = fq_parse_risk(&v);
        }
    }

    /* Penalización = volumen por IP + riesgo externo, ambos fracción de N.
     * (Conteo de cuentas por device se difiere: el frac anclado al device ya
     *  neutraliza multi-rid del mismo device.) */
    volume = (ip_devices > 1) ? ip_devices : 1;
    penalty = (double) (volume - 1) * (double) flcf->penalty / 1000.0 * (double) N
            + risk * (double) flcf->risk_weight / 1000.0 * (double) N;

    anchor = (first_seen > flcf->start) ? first_seen : flcf->start;
    aging = (now > anchor)
            ? (double) (now - anchor) * (double) flcf->aging / 1000.0 : 0.0;
    aging_cap = (double) flcf->aging_cap / 1000.0 * span;
    if (aging > aging_cap) aging = aging_cap;

    effpen = penalty - aging;
    if (effpen < 0) effpen = 0;
    position = base + effpen;
    if (position < 0) position = 0;

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


/* ===========================================================================
 * Fase 5: endpoint /__fairqueue/status (JSON, SOLO-LECTURA)
 * ======================================================================== */

/* lectura read-only del shm: NO registra ni crea nodos (cierra el CSRF de
 * encolado). Devuelve NGX_OK si el device ya estaba registrado. */
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

    fqn = fq_rb_lookup(&ctx->sh->rbtree, hash, devid, devlen);
    if (fqn) {
        *first_seen = fqn->first_seen;
        if (rank) *rank = fqn->rank;
        found = NGX_OK;
    }
    if (N) *N = (ngx_uint_t) ctx->sh->n;
    if (ip_devices) {
        ngx_uint_t c = fq_ip_touch(ctx, ip, iplen, 0, 0, 0, NULL);  /* read-only */
        *ip_devices = c ? c : 1;
    }

    ngx_shmtx_unlock(&ctx->shpool->mutex);
    return found;
}

/* IP del cliente: XFF (primer token) si trust_xff, si no la IP de conexión.
 * (trust_xff SOLO detrás de un proxy de confianza que reescriba el header.) */
static ngx_str_t
fq_client_ip(ngx_http_request_t *r, ngx_http_fairqueue_loc_conf_t *flcf)
{
    ngx_str_t  name = ngx_string("X-Forwarded-For");
    ngx_str_t  xff, ip;
    u_char    *p, *last, *e;

    if (flcf->trust_xff && fq_req_header(r, &name, &xff) == NGX_OK && xff.len) {
        p = xff.data; last = xff.data + xff.len; e = p;
        while (e < last && *e != ',' && *e != ' ') e++;
        if (e > p) {
            ip.data = p;
            ip.len = e - p;
            return ip;
        }
    }
    return r->connection->addr_text;
}

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

    /* identidad SOLO lectura (no acuña cookies). */
    if (fq_cookie_verify(r, &flcf->secret, &idn, "id", &rid) != NGX_OK
        || fq_cookie_verify(r, &flcf->secret, &devn, "dev", &devid) != NGX_OK)
    {
        ngx_str_set(&body, "{\"state\":\"redirect\",\"redirect\":\"/checkout\"}");
        return ngx_http_fq_send_json(r, &body);
    }

    if (ngx_http_fq_admission_valid(r, flcf, &rid, &devid) == NGX_OK) {
        ngx_str_set(&body, "{\"state\":\"admitted\",\"redirect\":\"/checkout\"}");
        return ngx_http_fq_send_json(r, &body);
    }

    closed_in = flcf->waiting_start - now;
    if (flcf->waiting_start > 0 && closed_in > 0) {
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

    /* peek read-only: si no está registrado, que entre por la ruta protegida. */
    ip = fq_client_ip(r, flcf);
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
        /* registro: NO se revela standing fino (anti-minado). */
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
