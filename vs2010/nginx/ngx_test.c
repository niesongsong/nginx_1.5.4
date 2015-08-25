

#include <ngx_config.h>
#include <ngx_core.h>

#include <ngx_http.h>
#include <ngx_event.h>

#include <imagehlp.h>

#pragma comment(lib,"Dbghelp.lib")

#define KB  (1024)
#define MB  ((1024)*KB)

extern ngx_module_t  ngx_core_module;
extern ngx_module_t  ngx_errlog_module;
extern ngx_module_t  ngx_conf_module;
extern ngx_module_t  ngx_events_module;
extern ngx_module_t  ngx_event_core_module;
extern ngx_module_t  ngx_iocp_module;
extern ngx_module_t  ngx_select_module;
extern ngx_module_t  ngx_regex_module;
extern ngx_module_t  ngx_http_module;
extern ngx_module_t  ngx_http_core_module;
extern ngx_module_t  ngx_http_log_module;
extern ngx_module_t  ngx_http_upstream_module;
extern ngx_module_t  ngx_http_static_module;
extern ngx_module_t  ngx_http_autoindex_module;
extern ngx_module_t  ngx_http_index_module;
extern ngx_module_t  ngx_http_auth_basic_module;
extern ngx_module_t  ngx_http_access_module;
extern ngx_module_t  ngx_http_limit_conn_module;
extern ngx_module_t  ngx_http_limit_req_module;
extern ngx_module_t  ngx_http_geo_module;
extern ngx_module_t  ngx_http_map_module;
extern ngx_module_t  ngx_http_split_clients_module;
extern ngx_module_t  ngx_http_referer_module;
extern ngx_module_t  ngx_http_rewrite_module;
extern ngx_module_t  ngx_http_proxy_module;
extern ngx_module_t  ngx_http_fastcgi_module;
extern ngx_module_t  ngx_http_uwsgi_module;
extern ngx_module_t  ngx_http_scgi_module;
extern ngx_module_t  ngx_http_memcached_module;
extern ngx_module_t  ngx_http_empty_gif_module;
extern ngx_module_t  ngx_http_browser_module;
extern ngx_module_t  ngx_http_upstream_ip_hash_module;
extern ngx_module_t  ngx_http_upstream_least_conn_module;
extern ngx_module_t  ngx_http_upstream_keepalive_module;
extern ngx_module_t  ngx_http_write_filter_module;
extern ngx_module_t  ngx_http_header_filter_module;
extern ngx_module_t  ngx_http_chunked_filter_module;
extern ngx_module_t  ngx_http_range_header_filter_module;
extern ngx_module_t  ngx_http_gzip_filter_module;
extern ngx_module_t  ngx_http_postpone_filter_module;
extern ngx_module_t  ngx_http_ssi_filter_module;
extern ngx_module_t  ngx_http_charset_filter_module;
extern ngx_module_t  ngx_http_userid_filter_module;
extern ngx_module_t  ngx_http_headers_filter_module;
extern ngx_module_t  ngx_http_copy_filter_module;
extern ngx_module_t  ngx_http_range_body_filter_module;
extern ngx_module_t  ngx_http_not_modified_filter_module;

static ngx_uint_t ngx_http_module_max;

typedef struct _rbtree_node_s{
    ngx_rbtree_node_t node;
    ngx_int_t value;
}rbtree_node_t;

typedef struct {
    ngx_uint_t                         max_cached;

    ngx_queue_t                        cache;
    ngx_queue_t                        free;

    ngx_http_upstream_init_pt          original_init_upstream;
    ngx_http_upstream_init_peer_pt     original_init_peer;

} ngx_http_upstream_keepalive_srv_conf_t;


typedef struct {
    ngx_http_upstream_keepalive_srv_conf_t  *conf;

    ngx_http_upstream_t               *upstream;

    void                              *data;

    ngx_event_get_peer_pt              original_get_peer;
    ngx_event_free_peer_pt             original_free_peer;

#if (NGX_HTTP_SSL)
    ngx_event_set_peer_session_pt      original_set_session;
    ngx_event_save_peer_session_pt     original_save_session;
#endif

} ngx_http_upstream_keepalive_peer_data_t;


typedef struct {
    ngx_http_upstream_keepalive_srv_conf_t  *conf;

    ngx_queue_t                        queue;
    ngx_connection_t                  *connection;

    socklen_t                          socklen;
    u_char                             sockaddr[NGX_SOCKADDRLEN];

} ngx_http_upstream_keepalive_cache_t;


static void get_proc_by_addr(DWORD64 a,char name[],int n);

static void do_test_os_init(ngx_log_t *log);

static void do_test_slab(ngx_log_t * log);
static void do_test_radix(ngx_log_t * log);
static void do_test_hash(ngx_log_t * log);

static void do_test_dump_modules(ngx_cycle_t *cycle);
static void do_test_dump_conf(ngx_cycle_t *cycle);


static void do_test_os_init(ngx_log_t *log)
{
    DWORD  error;
    HANDLE hProcess;

    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);
    hProcess = GetCurrentProcess();

    if (!SymInitialize(hProcess, NULL, TRUE)) {
        error = GetLastError();
        printf("SymInitialize returned error : %d\n", error);
    }
}

void ngx_test_case(ngx_cycle_t *cycle)
{
    do_test_os_init(cycle->log);

    do_test_slab(cycle->log);
    do_test_radix(cycle->log);
    do_test_hash(cycle->log);

    //do_test_dump_modules(cycle);
    do_test_dump_conf(cycle);
}

static int _ngx_dns_strcmp(const void *one,const void *two)
{
    ngx_hash_key_t  *first, *second;
    first = (ngx_hash_key_t *) one;
    second = (ngx_hash_key_t *) two;
    return strncmp(first->key.data, second->key.data,first->key.len);
}

static void do_test_hash(ngx_log_t * log) 
{
    ngx_pool_t * pool;
    ngx_hash_keys_arrays_t ha;
    ngx_int_t v[6] = {16,32,64,128,256,512}; /*must be aligned by 4*/
    ngx_int_t i,value;
    ngx_hash_init_t hash;
    ngx_hash_combined_t cmb;
    ngx_str_t test;
    ngx_uint_t key;

    /*key/value*/
    ngx_str_t keys[] = {
        ngx_string("www.test1.com"), /*hash*/
        ngx_string("*.test2.com"),   /*wildcard hash head*/
        ngx_string("*.test2.net"),
        ngx_string("*.test3.com"),
        ngx_string("www.test3.*"),   /*wildcard hash */
        ngx_string("mail.test3.*"),
    };

    pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE,log);
    ha.temp_pool = ha.pool = pool;
    ngx_hash_keys_array_init(&ha,NGX_HASH_LARGE);

    /*add keys*/
    for (i = 0;i < 6;i++) {
        ngx_str_t k;
        k.len = keys[i].len;
        k.data = ngx_pstrdup(pool,&keys[i]);
        ngx_hash_add_key(&ha,&k,(void *)v[i],1);
    }
    
    hash.key = ngx_hash_key;
    hash.pool = pool;
    hash.max_size = 1024;
    hash.bucket_size = 76;
    hash.name = "test_names_hash";
    ha.temp_pool = ha.pool = pool;

    /*create hash*/
    if (ha.keys.nelts) {
        hash.hash = &cmb.hash;
        hash.temp_pool = NULL;
        ngx_hash_init(&hash, ha.keys.elts, ha.keys.nelts);
    }

    /*create wildcard hash head*/
    if (ha.dns_wc_head.nelts) {
        ngx_qsort(ha.dns_wc_head.elts, (size_t) ha.dns_wc_head.nelts,
            sizeof(ngx_hash_key_t), _ngx_dns_strcmp);
        hash.hash = NULL;
        hash.temp_pool = ha.temp_pool;
        ngx_hash_wildcard_init(&hash,ha.dns_wc_head.elts,ha.dns_wc_head.nelts);
        cmb.wc_head = (ngx_hash_wildcard_t *) hash.hash;
    }

    /*create wildcard hash tail*/
    if (ha.dns_wc_tail.nelts) {
        ngx_qsort(ha.dns_wc_tail.elts, (size_t) ha.dns_wc_tail.nelts,
            sizeof(ngx_hash_key_t), _ngx_dns_strcmp);
        hash.hash = NULL;
        hash.temp_pool = ha.temp_pool;
        ngx_hash_wildcard_init(&hash, ha.dns_wc_tail.elts,ha.dns_wc_tail.nelts);
        cmb.wc_tail = (ngx_hash_wildcard_t *) hash.hash;
    }
    
    /*search www.test1.com*/
    ngx_str_set(&test,"www.test1.com");
    key = ngx_hash_key(test.data,test.len);
    value = (ngx_int_t)ngx_hash_find_combined(&cmb,key,test.data,test.len);
    printf("value: %d\n",value);

    /*search www.test2.com*/
    ngx_str_set(&test,"www.test2.com");
    key = ngx_hash_key(test.data,test.len);
    value = (ngx_int_t)ngx_hash_find_combined(&cmb,key,test.data,test.len);
    printf("value: %d\n",value);

    /*search mail.test2.com*/
    ngx_str_set(&test,"mail.test2.com");
    key = ngx_hash_key(test.data,test.len);
    value = (ngx_int_t)ngx_hash_find_combined(&cmb,key,test.data,test.len);
    printf("value: %d\n",value);

    /*search mail.test3.cn*/
    ngx_str_set(&test,"mail.test3.cn");
    key = ngx_hash_key(test.data,test.len);
    value = (ngx_int_t)ngx_hash_find_combined(&cmb,key,test.data,test.len);
    printf("value: %d\n",value);

    /*search mail.test3.org*/
    ngx_str_set(&test,"mail.test3.com");
    key = ngx_hash_key(test.data,test.len);
    value = (ngx_int_t)ngx_hash_find_combined(&cmb,key,test.data,test.len);
    printf("value: %d\n",value);

    ngx_destroy_pool(ha.temp_pool);
    return;
}

static void do_test_radix(ngx_log_t * log)
{
        ngx_radix_tree_t *tree;
        ngx_pool_t *pool;
        u_char * p;

        /*create memory pool*/
        pool = ngx_create_pool(1024,log);
        tree = ngx_radix_tree_create(pool,0);

        /*32 bit*/
        /**************************************************
         *insert 
         *C0 00 00 00 =>11000000 00000000 00000000 00000000
         *40 00 00 00 =>01000000 00000000 00000000 00000000
         *80 00 00 00 =>10000000 00000000 00000000 00000000
         * 
         *result
         *     r
         *   0   1
         *    1 0 1
         **************************************************/
        ngx_radix32tree_insert(tree,0xC0000000,0xE0000000,(uintptr_t)"test1");
        ngx_radix32tree_insert(tree,0x40000000,0xE0000000,(uintptr_t)"test2");
        ngx_radix32tree_insert(tree,0x80000000,0xE0000000,(uintptr_t)"test3");

        /*find*/
        p = (u_char *)ngx_radix32tree_find(tree,0xC0000000);
        printf("%s\n",p);

        p = (u_char *)ngx_radix32tree_find(tree,0x40000000);
        printf("%s\n",p);

        p = (u_char *)ngx_radix32tree_find(tree,0x80000000);
        printf("%s\n",p);

        return;
}


void _rbtree_insert(ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node,
    ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t  **p;
    rbtree_node_t *nd;

    for ( ;; ) {
        if (node->key < temp->key) {
            p = &temp->left;
        } else {
            p = &temp->right;
        }
        if (*p == sentinel) {
            /*insert here*/
            nd = (rbtree_node_t*)node;
            printf("insert [%d]:%c\n",nd->node.key,(char)nd->value);
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

static void do_test_rbtree(ngx_log_t * log)
{
    ngx_rbtree_t rbtree;
    ngx_rbtree_node_t sentinel,*node;
    rbtree_node_t *rbnode;
    ngx_pool_t *pool;
    ngx_int_t i;
    
    /*create memory pool*/
    pool = ngx_create_pool(1024,log);

    /*init ngx_rbtree*/
    ngx_rbtree_init(&rbtree, &sentinel,_rbtree_insert);

    /*insert*/
    for (i = 0;i < 5;i++) {
        rbnode = ngx_palloc(pool,sizeof(rbtree_node_t));
        rbnode->value = 'A'+i;
        rbnode->node.key = i;
        ngx_rbtree_insert(&rbtree,&rbnode->node);
    }

    /*find key 4*/
    for (node = rbtree.root;node != rbtree.sentinel;) {
        if (node->key > 4) {
            node = node->left;
        } else if (node->key < 4) {
            node = node->right;
        } else {
            break;
        }
    }
    /*find*/
    if (node != rbtree.sentinel) {
        rbnode = (rbtree_node_t *)node;
        printf("find [%d]:%c\n",node->key,(char)rbnode->value);
    } else {
        printf("node find\n");
    }

    /*delete data*/
    while (rbtree.root != rbtree.sentinel) {
        node = ngx_rbtree_min(rbtree.root,&sentinel);
        rbnode = (rbtree_node_t*)node;
        printf("remove [%d]:%c\n",node->key,(char)rbnode->value);
        ngx_rbtree_delete(&rbtree,node);
    }

    ngx_destroy_pool(pool);
    return ;
}

static void do_test_slab(ngx_log_t * log)
{
    ngx_shm_t shm;
    ngx_slab_pool_t  *sp;
    void *p1,*p2,*p3;
    u_char * file;

    ngx_memzero(&shm,sizeof(ngx_shm_t));

    shm.size = 10*MB; /*10MB*/
    ngx_str_set(&shm.name,"hello_zone");
    shm.log = log;
    ngx_shm_alloc(&shm);

    sp = (ngx_slab_pool_t *) shm.addr;
    if (shm.exists) {
        return ;
    }

    sp->end = shm.addr + shm.size;
    sp->min_shift = 3;
    sp->addr = shm.addr;
   
#if (NGX_HAVE_ATOMIC_OPS)
    file = NULL;
#else
    file = ngx_pnalloc(cycle->pool, cycle->lock_file.len + zn->shm.name.len);
    if (file == NULL) {
        return NGX_ERROR;
    }
    (void) ngx_sprintf(file, "%V%V%Z", &cycle->lock_file, &zn->shm.name);

#endif
    /*create mutex*/
    ngx_shmtx_create(&sp->mutex, &sp->lock,file);

    /*init slab*/
    ngx_slab_init(sp);

    p1 = ngx_slab_alloc(sp,5*MB);
    p2 = ngx_slab_alloc(sp,1*MB);
    ngx_slab_free(sp,p1);
    ngx_slab_free(sp,p2);
    p3 = ngx_slab_alloc(sp,6*MB);
    ngx_slab_free(sp,p3);

    p1 = ngx_slab_alloc(sp,1);

    return ;
}

static void ngx_dump_event_module(ngx_uint_t i,
    ngx_module_t *m,const char *n,ngx_cycle_t *cycle);
static void ngx_dump_http_module(ngx_uint_t i,
    ngx_module_t *m,const char *n,ngx_cycle_t *cycle);
static void ngx_dump_core_module(ngx_uint_t i,
    ngx_module_t *m,const char *n,ngx_cycle_t *cycle);
static void ngx_dump_conf_module(ngx_uint_t i,
    ngx_module_t *m,const char *n,ngx_cycle_t *cycle);
static void ngx_dump_conf(ngx_uint_t i,
    ngx_module_t *m,const char *n,ngx_cycle_t *cycle);

static void ngx_dump_conf_core(ngx_uint_t i,
    ngx_module_t *m,const char *n,ngx_cycle_t *cycle);
static void ngx_dump_conf_http(ngx_uint_t i,
    ngx_module_t *m,const char *n,ngx_cycle_t *cycle);
static void ngx_dump_conf_event(ngx_uint_t i,
    ngx_module_t *m,const char *n,ngx_cycle_t *cycle);
static void ngx_dump_conf_regex(ngx_uint_t i,
    ngx_module_t *m,const char *n,ngx_cycle_t *cycle);

static void do_test_dump_modules(ngx_cycle_t *cycle)
{
    ngx_uint_t     i,index;
    ngx_module_t  *m;
    char           name[256],*type_n;

    index = -1;
    for (i = 0;ngx_modules[i];i++) {

        memset(name,0,sizeof(name));
        m = ngx_modules[i];

        get_proc_by_addr((DWORD64)m,name,256);

        switch(m->type) {

        case NGX_EVENT_MODULE:
            type_n = "EVNT";
            index  = 1;
            break;

        case NGX_HTTP_MODULE:
            type_n = "HTTP";
            index  = 2;
            break;

        case NGX_CORE_MODULE:
            type_n = "CORE";
            index  = 0;
            break;

        case NGX_CONF_MODULE:
            type_n = "CONF";
            index  = 3;
            break;
        }

        if (index == -1) {
            printf("ignore[%d]!\n",i);
            continue;
        }

        printf("ngx_modules[%d]\n"
            "   .type      = %s\n"
            "   .ctx_index = (%d,%d)\n"
            "   .name      = %s\n",
            i,type_n,index,m->ctx_index,name);

        switch(m->type) {

        case NGX_EVENT_MODULE:
            ngx_dump_event_module(i,m,name,cycle);
            break;

        case NGX_HTTP_MODULE:
            ngx_dump_http_module(i,m,name,cycle);
            break;

        case NGX_CORE_MODULE:
            ngx_dump_core_module(i,m,name,cycle);
            break;

        case NGX_CONF_MODULE:
            ngx_dump_conf_module(i,m,name,cycle);
            break;
        }
    }
    
    return ;
}

static void get_proc_by_addr(DWORD64 addr,char name[],int n)
{
    DWORD64  dwDisplacement = 0;
    DWORD64  dwAddress = addr;
    char     buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
    char    *s,*e;
    PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;

    pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    pSymbol->MaxNameLen = MAX_SYM_NAME;

    strcpy(name,"(null)");

    if (!SymFromAddr(GetCurrentProcess(), dwAddress, 
        &dwDisplacement, pSymbol)) {

        if (addr != 0) {
            strcpy(name,"(error)");
        } 
    
        return ;
    }

    s = strchr(pSymbol->Name,'(');
    e = strchr(pSymbol->Name,')');

    if (s == NULL) {
        s = pSymbol->Name;
    } else {
        s++;
    }

    strcpy(name, s);
    if (e != NULL) {
        name[e - s] = 0;
    }
}

static void ngx_dump_core_module(ngx_uint_t i,ngx_module_t *m,
    const char *name,ngx_cycle_t *cycle)
{
    ngx_core_module_t *c;
    char               cname[256] = {0},iname[256] = {0};
    ngx_command_t     *cmd;
    ngx_uint_t         n = 0;

    c = (ngx_core_module_t *)m->ctx;
    get_proc_by_addr((DWORD64)m->init_master,cname,256);
    printf("   .init_master  = %s  \n",cname);

    get_proc_by_addr((DWORD64)m->init_module,cname,256);
    printf("   .init_module  = %s  \n",cname);

    get_proc_by_addr((DWORD64)m->init_process,cname,256);
    printf("   .init_process = %s  \n",cname);

    get_proc_by_addr((DWORD64)m->init_thread,cname,256);
    printf("   .init_thread  = %s  \n",cname);

    get_proc_by_addr((DWORD64)m->exit_thread,cname,256);
    printf("   .exit_thread  = %s  \n",cname);

    get_proc_by_addr((DWORD64)m->exit_process,cname,256);
    printf("   .exit_process = %s  \n",cname);

    get_proc_by_addr((DWORD64)m->exit_master,cname,256);
    printf("   .exit_master  = %s  \n",cname);

    get_proc_by_addr((DWORD64)c->create_conf,cname,256);
    get_proc_by_addr((DWORD64)c->init_conf,iname,256);

    printf("   .ctx  = (http_core_module_t) {  \n"
            "      .name        = \"%s\"   \n"
            "      .create_conf = %s   \n"
            "      .init_conf   = %s   \n"
            "    }\n",
            c->name.data,cname,iname);

    printf("   .cmd = (ngx_command_t) {\n");
    for (cmd = m->commands;cmd;cmd++) {
        if (cmd->name.len == 0) {
            break;
        }

        printf("     [%02d].name  = \"%s\" \n",n++,cmd->name.data);
    }
    printf("    }\n");
}

static void ngx_dump_event_module(ngx_uint_t i,
    ngx_module_t *m,const char *name,ngx_cycle_t *cycle)
{
    ngx_event_module_t *e;
    char               cname[256] = {0},iname[256] = {0};
    ngx_command_t     *cmd;
    ngx_uint_t         n = 0;

    e = (ngx_event_module_t *)m->ctx;
    get_proc_by_addr((DWORD64)m->init_master,cname,256);
    printf("   .init_master  = %s  \n",cname);

    get_proc_by_addr((DWORD64)m->init_module,cname,256);
    printf("   .init_module  = %s  \n",cname);

    get_proc_by_addr((DWORD64)m->init_process,cname,256);
    printf("   .init_process = %s  \n",cname);

    get_proc_by_addr((DWORD64)m->init_thread,cname,256);
    printf("   .init_thread  = %s  \n",cname);

    get_proc_by_addr((DWORD64)m->exit_thread,cname,256);
    printf("   .exit_thread  = %s  \n",cname);

    get_proc_by_addr((DWORD64)m->exit_process,cname,256);
    printf("   .exit_process = %s  \n",cname);

    get_proc_by_addr((DWORD64)m->exit_master,cname,256);
    printf("   .exit_master  = %s  \n",cname);

    get_proc_by_addr((DWORD64)e->create_conf,cname,256);
    get_proc_by_addr((DWORD64)e->init_conf,iname,256);

    printf("   .ctx  = (ngx_event_module_t) {  \n"
        "      .name        = \"%s\"   \n"
        "      .create_conf = %s   \n"
        "      .init_conf   = %s   \n",
        e->name->data,cname,iname);


    printf("      .actions  = (ngx_event_actions_t) {  \n");
    
    get_proc_by_addr((DWORD64)e->actions.add,cname,256);
    printf("        .add         = %s\n",cname);
    
    get_proc_by_addr((DWORD64)e->actions.del,cname,256);
    printf("        .del         = %s\n",cname);

    get_proc_by_addr((DWORD64)e->actions.enable,cname,256);
    printf("        .enable      = %s\n",cname);

    get_proc_by_addr((DWORD64)e->actions.disable,cname,256);
    printf("        .disable     = %s\n",cname);

    get_proc_by_addr((DWORD64)e->actions.add_conn,cname,256);
    printf("        .add_conn    = %s\n",cname);

    get_proc_by_addr((DWORD64)e->actions.del_conn,cname,256);
    printf("        .del_conn    = %s\n",cname);

    get_proc_by_addr((DWORD64)e->actions.process_changes,cname,256);
    printf("        .process_changes = %s\n",cname);

    get_proc_by_addr((DWORD64)e->actions.process_events,cname,256);
    printf("        .process_events  = %s\n",cname);

    get_proc_by_addr((DWORD64)e->actions.init,cname,256);
    printf("        .init        = %s\n",cname);

    get_proc_by_addr((DWORD64)e->actions.done,cname,256);
    printf("        .done        = %s\n",cname);

    printf("       }\n    }\n");
    printf("   .cmd = (ngx_command_t) {\n");
    for (cmd = m->commands;cmd;cmd++) {
        if (cmd->name.len == 0) {
            break;
        }

        printf("     [%02d].name  = \"%s\" \n",n++,cmd->name.data);
    }
    printf("    }\n");

    return ;
}

static void ngx_dump_http_module(ngx_uint_t i,
    ngx_module_t *m,const char *name,ngx_cycle_t *cycle)
{
    ngx_http_module_t  *h;
    char               cname[256] = {0},iname[256] = {0};
    ngx_command_t     *cmd;
    ngx_uint_t         n = 0;

    h = (ngx_http_module_t *)m->ctx;
    get_proc_by_addr((DWORD64)m->init_master,cname,256);
    printf("   .init_master  = %s  \n",cname);

    get_proc_by_addr((DWORD64)m->init_module,cname,256);
    printf("   .init_module  = %s  \n",cname);

    get_proc_by_addr((DWORD64)m->init_process,cname,256);
    printf("   .init_process = %s  \n",cname);

    get_proc_by_addr((DWORD64)m->init_thread,cname,256);
    printf("   .init_thread  = %s  \n",cname);

    get_proc_by_addr((DWORD64)m->exit_thread,cname,256);
    printf("   .exit_thread  = %s  \n",cname);

    get_proc_by_addr((DWORD64)m->exit_process,cname,256);
    printf("   .exit_process = %s  \n",cname);

    get_proc_by_addr((DWORD64)m->exit_master,cname,256);
    printf("   .exit_master  = %s  \n",cname);

    printf("   .ctx  = (ngx_http_module_t) {  \n");
    
    get_proc_by_addr((DWORD64)h->preconfiguration,cname,256);
    printf("      .preconfiguration  = %s  \n",cname);

    get_proc_by_addr((DWORD64)h->postconfiguration,cname,256);
    printf("      .postconfiguration = %s  \n",cname);

    get_proc_by_addr((DWORD64)h->create_main_conf,cname,256);
    printf("      .create_main_conf  = %s  \n",cname);

    get_proc_by_addr((DWORD64)h->init_main_conf,cname,256);
    printf("      .init_main_conf    = %s  \n",cname);

    get_proc_by_addr((DWORD64)h->create_srv_conf,cname,256);
    printf("      .create_srv_conf   = %s  \n",cname);

    get_proc_by_addr((DWORD64)h->merge_srv_conf,cname,256);
    printf("      .merge_srv_conf    = %s  \n",cname);

    get_proc_by_addr((DWORD64)h->create_loc_conf,cname,256);
    printf("      .create_loc_conf   = %s  \n",cname);

    get_proc_by_addr((DWORD64)h->merge_loc_conf,cname,256);
    printf("      .merge_loc_conf    = %s  \n",cname);

    printf("    }\n");
    printf("   .cmd = (ngx_command_t) {\n");
    for (cmd = m->commands;cmd;cmd++) {
        if (cmd->name.len == 0) {
            break;
        }

        printf("     [%02d].name  = \"%s\" \n",n++,cmd->name.data);
    }
    printf("    }\n");

    return ;
}

static void ngx_dump_conf_module(ngx_uint_t i,
    ngx_module_t *m,const char *name,ngx_cycle_t *cycle)
{
    char               cname[256] = {0},iname[256] = {0};
    ngx_command_t     *cmd;
    ngx_uint_t         n = 0;

    get_proc_by_addr((DWORD64)m->init_master,cname,256);
    printf("   .init_master  = %s  \n",cname);

    get_proc_by_addr((DWORD64)m->init_module,cname,256);
    printf("   .init_module  = %s  \n",cname);

    get_proc_by_addr((DWORD64)m->init_process,cname,256);
    printf("   .init_process = %s  \n",cname);

    get_proc_by_addr((DWORD64)m->init_thread,cname,256);
    printf("   .init_thread  = %s  \n",cname);

    get_proc_by_addr((DWORD64)m->exit_thread,cname,256);
    printf("   .exit_thread  = %s  \n",cname);

    get_proc_by_addr((DWORD64)m->exit_process,cname,256);
    printf("   .exit_process = %s  \n",cname);

    get_proc_by_addr((DWORD64)m->exit_master,cname,256);
    printf("   .exit_master  = %s  \n",cname);

    printf("   .ctx  = (null) {  \n"
        "    }\n");
    printf("   .cmd = (ngx_command_t) {\n");
    for (cmd = m->commands;cmd;cmd++) {
        if (cmd->name.len == 0) {
            break;
        }

        printf("     [%02d].name  = \"%s\" \n",n++,cmd->name.data);
    }
    printf("    }\n");

    return ;
}

static void do_test_dump_conf(ngx_cycle_t *cycle)
{
    ngx_uint_t     i,index;
    char           name[256],*type_n;
    ngx_module_t  *m;

    for (i = 0;ngx_modules[i];i++) {

        memset(name,0,sizeof(name));
        m = ngx_modules[i];

        if (cycle->conf_ctx[i] == NULL) {
            continue;
        }

        switch(m->type) {

        case NGX_EVENT_MODULE:
            type_n = "EVNT";
            index  = 1;
            break;

        case NGX_HTTP_MODULE:
            type_n = "HTTP";
            index  = 2;
            break;

        case NGX_CORE_MODULE:
            type_n = "CORE";
            index  = 0;
            break;

        case NGX_CONF_MODULE:
            type_n = "CONF";
            index  = 3;
            break;
        }

        if (index == -1) {
            printf("ignore[%d]!\n",i);
            continue;
        }

        get_proc_by_addr((DWORD64)m,name,256);

        printf("conf_ctx[%d]=%p \tname=%s \ttype=%s\n",
            i,cycle->conf_ctx[i],name,type_n);

        ngx_dump_conf(i,m,name,cycle);
    }

    return ;
}

static void ngx_dump_conf(ngx_uint_t i,
    ngx_module_t *m,const char *n,ngx_cycle_t *cycle)
{
    if (m->type != NGX_CORE_MODULE) {
        return ;
    }

    if (strcmp(n,"ngx_core_module") == 0) {
        ngx_dump_conf_core(i,m,n,cycle);
        return ;
    }

    if (strcmp(n,"ngx_events_module") == 0) {
        ngx_dump_conf_event(i,m,n,cycle);
        return ;
    }

    if (strcmp(n,"ngx_regex_module") == 0) {
        ngx_dump_conf_regex(i,m,n,cycle);
        return ;
    }

    if (strcmp(n,"ngx_http_module") == 0) {
        ngx_dump_conf_http(i,m,n,cycle);
        return ;
    }

    return ;
}

static void ngx_dump_conf_regex(ngx_uint_t i,
    ngx_module_t *m,const char *n,ngx_cycle_t *cycle)
{
    typedef struct {
        ngx_flag_t  pcre_jit;
    } ngx_regex_conf_t;

    ngx_regex_conf_t *conf;
    conf = (ngx_regex_conf_t *)cycle->conf_ctx[i];

    printf(" (ngx_regex_conf_t *) = %p {\n",conf);
    printf("    .pcre_jit        = %d\n",conf->pcre_jit);
    printf(" }\n");

    return ;
}

static void ngx_dump_conf_core(ngx_uint_t i,
    ngx_module_t *m,const char *n,ngx_cycle_t *cycle)
{
    ngx_core_conf_t *conf;
    conf = (ngx_core_conf_t *)cycle->conf_ctx[i];

    printf(" (ngx_core_conf_t *) = %p {\n",conf);
    printf("    .daemon            = %d\n",conf->daemon);
    printf("    .master            = %d\n",conf->master);
    printf("    .timer_resolution  = %d\n",conf->timer_resolution);
    printf("    .worker_processes  = %d\n",conf->worker_processes);
    printf("    .debug_points      = %d\n",conf->debug_points);
    printf("    .rlimit_nofile     = %d\n",conf->rlimit_nofile);
    printf("    .rlimit_sigpending = %d\n",conf->rlimit_sigpending);
    printf("    .rlimit_core       = %d\n",conf->rlimit_core);
    printf("    .priority          = %d\n",conf->priority);
    printf("    .cpu_affinity_n    = %d\n",conf->cpu_affinity_n);
    printf("    .cpu_affinity      = %p\n",conf->cpu_affinity);
    printf("    .username          = '%s'\n",conf->username);
    printf("    .working_directory = '%s'\n",conf->working_directory.data);
    printf("    .lock_file         = %d\n",conf->lock_file);
    printf("    .pid               = '%s'\n",conf->pid.data);
    printf("    .oldpid            = '%s'\n",conf->oldpid.data);
    printf("    .env               = %p\n",conf->env);
    printf("    .environment       = %p\n",conf->environment);
#if (NGX_THREADS)
    printf("    .worker_threads    = %d\n",conf->worker_threads);
    printf("    .thread_stack_size = %d\n",conf->thread_stack_size);
#endif
    printf(" }\n");
}


static void ngx_dump_conf_event(ngx_uint_t i,
    ngx_module_t *m,const char *n,ngx_cycle_t *cycle)
{
    ngx_uint_t    mi;
    void       ***conf,**conf_array;
    char          name[256];
    ngx_module_t *md;

    conf = (void ***)cycle->conf_ctx[i];
    conf_array = *conf;

    memset(name,0,sizeof(name));

    printf(" void** [] = %p,   *%p = %p\n",conf,conf,*conf);

    for (mi = 0;ngx_modules[mi];mi++) {

        md = ngx_modules[mi];
        if (md->type != NGX_EVENT_MODULE) {
            continue;
        }

        get_proc_by_addr((DWORD64)md,name,256);
        if (strcmp(name,"ngx_event_core_module") == 0) {
            ngx_event_conf_t  *ecf;
            ecf = (ngx_event_conf_t *)conf_array[md->ctx_index];

            printf("    void* []= %p  i = %d\n",conf_array,md->ctx_index);
            printf("        (ngx_event_conf_t *)    = %p {\n",ecf);
            printf("            .connections        = %d \n",ecf->connections);
            printf("            .use                = %d \n",ecf->use);
            printf("            .multi_accept       = %d \n",ecf->multi_accept);
            printf("            .accept_mutex       = %d \n",ecf->accept_mutex);
            printf("            .accept_mutex_delay = %d \n",ecf->accept_mutex_delay);
            printf("            .name               = '%s' \n",ecf->name);
            printf("        }\n");

            continue;
        }

        if (strcmp(name,"ngx_iocp_module") == 0) {
            ngx_iocp_conf_t  *iocpcf;
            iocpcf = (ngx_iocp_conf_t *)conf_array[md->ctx_index];

            printf("    void* []= %p  i = %d\n",conf_array,md->ctx_index);
            printf("        (ngx_iocp_conf_t *)     = %p {\n",iocpcf);
            printf("            .acceptex_read      = %d \n",iocpcf->acceptex_read);
            printf("            .post_acceptex      = %d \n",iocpcf->post_acceptex);
            printf("            .threads            = %d \n",iocpcf->threads);
            printf("        }\n");

            continue;
        }
    }
}

static void ngx_dump_conf_http_main(ngx_module_t *http_module,
    ngx_http_conf_ctx_t *conf,ngx_cycle_t *cycle);
static void ngx_dump_conf_http_srv(ngx_module_t *http_module,
    ngx_http_conf_ctx_t *conf,ngx_cycle_t *cycle);
static void ngx_dump_conf_http_loc(ngx_module_t *http_module,
    ngx_http_conf_ctx_t *conf,ngx_cycle_t *cycle);


static void ngx_dump_conf_http_main_core(ngx_module_t *http_module,
    ngx_http_conf_ctx_t *conf,ngx_cycle_t *cycle);

static void ngx_dump_conf_http_main_log(ngx_module_t *http_module,
    ngx_http_conf_ctx_t *conf,ngx_cycle_t *cycle);

static void ngx_dump_conf_http_main_upstream(ngx_module_t *http_module,
    ngx_http_conf_ctx_t *conf,ngx_cycle_t *cycle);

static void ngx_dump_conf_http_main_map(ngx_module_t *http_module,
    ngx_http_conf_ctx_t *conf,ngx_cycle_t *cycle);

static void ngx_dump_conf_http_main_ssi_filter(ngx_module_t *http_module,
    ngx_http_conf_ctx_t *conf,ngx_cycle_t *cycle);

static void ngx_dump_conf_http_main_charset_filter(ngx_module_t *http_module,
    ngx_http_conf_ctx_t *conf,ngx_cycle_t *cycle);

static void ngx_dump_conf_http(ngx_uint_t i,
    ngx_module_t *m,const char *n,ngx_cycle_t *cycle)
{
    ngx_http_conf_ctx_t *conf;
    ngx_uint_t           mi;

    for (mi = 0;ngx_modules[mi];mi++) {

        if (ngx_modules[mi]->type != NGX_HTTP_MODULE) {
            continue;
        }

        ngx_http_module_max++;
    }

    conf = (ngx_http_conf_ctx_t *)cycle->conf_ctx[i];

    printf(" (ngx_http_conf_ctx_t *) = %p {\n",conf);
    printf("    .main    =   %p (void **),%d\n",conf->main_conf, ngx_http_module_max);
    ngx_dump_conf_http_main(m,conf,cycle);
    printf("    .srv     =   %p (void **),%d\n",conf->srv_conf, ngx_http_module_max);
    ngx_dump_conf_http_srv(m,conf,cycle);
    printf("    .loc     =   %p (void **),%d\n",conf->loc_conf, ngx_http_module_max);
    ngx_dump_conf_http_loc(m,conf,cycle);
    printf(" }\n");

    return ;
}

static void ngx_dump_conf_http_main(ngx_module_t *http_module,
    ngx_http_conf_ctx_t *conf,ngx_cycle_t *cycle)
{
    ngx_uint_t                 i;

    for (i = 0;i < ngx_http_module_max;i++) {

        if (conf->main_conf[i] == NULL) {
            continue;
        }

        if (i == ngx_http_core_module.ctx_index) {

            printf("       [%02d](ngx_http_core_main_conf_t *) = %p {\n",i,conf->main_conf[i]);
            ngx_dump_conf_http_main_core(&ngx_http_core_module,conf,cycle);
            printf("       }\n");

            continue;
        }

        if (i == ngx_http_log_module.ctx_index) {

            printf("       [%02d](ngx_http_core_main_conf_t *) = %p {\n",i,conf->main_conf[i]);
            ngx_dump_conf_http_main_log(&ngx_http_log_module,conf,cycle);
            printf("       }\n");
            
            continue;
        }

        if (i == ngx_http_upstream_module.ctx_index) {
            
            printf("       [%02d](ngx_http_core_main_conf_t *) = %p {\n",i,conf->main_conf[i]);
            ngx_dump_conf_http_main_upstream(&ngx_http_upstream_module,conf,cycle);
            printf("       }\n");

            continue;
        }

        if (i == ngx_http_map_module.ctx_index) {
            
            printf("       [%02d](ngx_http_core_main_conf_t *) = %p {\n",i,conf->main_conf[i]);
            ngx_dump_conf_http_main_map(&ngx_http_map_module,conf,cycle);
            printf("       }\n");

            continue;
        }

        if (i == ngx_http_ssi_filter_module.ctx_index) {
            
            printf("       [%02d](ngx_http_core_main_conf_t *) = %p {\n",i,conf->main_conf[i]);
            ngx_dump_conf_http_main_ssi_filter(&ngx_http_ssi_filter_module,conf,cycle);
            printf("       }\n");

            continue;
        }

        if (i == ngx_http_charset_filter_module.ctx_index) {
            
            printf("       [%02d](ngx_http_core_main_conf_t *) = %p {\n",i,conf->main_conf[i]);
            ngx_dump_conf_http_main_charset_filter(&ngx_http_charset_filter_module,conf,cycle);
            printf("       }\n");

            continue;
        }

        printf("unknown \n");
    }

    return;
}

static void ngx_dump_conf_http_main_core(ngx_module_t *http_module,
    ngx_http_conf_ctx_t *conf,ngx_cycle_t *cycle)
{
    ngx_http_core_main_conf_t *cmcf;
    ngx_uint_t                 i;
    ngx_http_core_srv_conf_t **server;
    ngx_hash_t                *ha;
    void                      *value;
    char                       name[256];
    ngx_http_phase_handler_t  *ph;
    ngx_http_handler_pt       *h;

    cmcf = conf->main_conf[http_module->ctx_index];

    printf("            .server_names_hash_max_size   = %d \n",cmcf->server_names_hash_max_size);
    printf("            .variables_hash_max_size      = %d \n",cmcf->variables_hash_max_size);
    printf("            .variables_hash_bucket_size   = %d \n",cmcf->variables_hash_bucket_size);
    printf("            .try_files                    = %d \n",cmcf->try_files);
    printf("            .ncaptures                    = %d \n",cmcf->ncaptures);

    //headers_in_hash
    ha = &cmcf->headers_in_hash;
    printf("            .headers_in_hash = [%p] size = %d, (ngx_http_header_t *) {\n", ha,ha->size);
    for (i = 0; i < cmcf->headers_in_hash.size; i++) {
        ngx_hash_elt_t  *elt;

        elt = ha->buckets[i];
        if (elt == NULL) {
            continue;
        }

        while (elt->value) {
            value = elt->value;
            memcpy(name, elt->name, elt->len);
            name[elt->len] = 0;
            printf("                 %-28s => %p\n",name,elt->value);
            elt = (ngx_hash_elt_t *) ngx_align_ptr(&elt->name[0] + elt->len,
                             sizeof(void *));
        }
    }
    printf("            }\n");


    //variables_hash
    ha = &cmcf->variables_hash;
    printf("            .variables_hash = [%p] size = %d, (ngx_http_variable_t *){\n", ha,ha->size);
    for (i = 0; i < cmcf->variables_hash.size; i++) {
        ngx_hash_elt_t  *elt;

        elt = ha->buckets[i];
        if (elt == NULL) {
            continue;
        }

        while (elt->value) {
            value = elt->value;
            memcpy(name, elt->name, elt->len);
            name[elt->len] = 0;
            printf("                 %-28s => %p\n",name,elt->value);
            elt = (ngx_hash_elt_t *) ngx_align_ptr(&elt->name[0] + elt->len,
                sizeof(void *));
        }
    }
    printf("            }\n");

    //phase_engine
    printf("            .phase_engine = %p {\n", cmcf->phase_engine);

    ph = cmcf->phase_engine.handlers;
    for (i = 0; ph[i].checker; i++) {

        get_proc_by_addr((DWORD64)ph[i].checker, name, 255);

        printf("                [%2d] checker: %s\n", i, name);

        get_proc_by_addr((DWORD64)ph[i].handler, name, 255);
        printf("                     handler: %s\n", name);
        printf("                     next   : %d\n", ph[i].next);
    }
    printf("            }\n");

    printf("            .phase_log = %p {\n", cmcf->phase_engine);
    h = cmcf->phases[NGX_HTTP_LOG_PHASE].handlers.elts;

    //phase log
    for (i = 0; i < cmcf->phases[NGX_HTTP_LOG_PHASE].handlers.nelts; i++) {
        get_proc_by_addr((DWORD64)h[i], name, 255);
        printf("                     handler: %s\n", name);
    }
    printf("            }\n");

    server = cmcf->servers.elts;
    for (i = 0; i < cmcf->servers.nelts; i++) {      
        ngx_dump_conf_http_srv(http_module,server[i]->ctx,cycle);
    }

    return ;
}

typedef struct {
    ngx_str_t                   name;
    ngx_array_t                *flushes;    /* array of ngx_int_t */
    ngx_array_t                *ops;        /* array of ngx_http_log_op_t */
} ngx_http_log_fmt_t;

typedef struct {
    ngx_array_t                 formats;    /* array of ngx_http_log_fmt_t */
    ngx_uint_t                  combined_used; /* unsigned  combined_used:1 */
} ngx_http_log_main_conf_t;

static void ngx_dump_conf_http_main_log(ngx_module_t *http_module,
    ngx_http_conf_ctx_t *conf,ngx_cycle_t *cycle)
{
    ngx_http_log_main_conf_t *lmcf;
    ngx_http_log_fmt_t       *fmt;
    ngx_uint_t                i;

    lmcf = conf->main_conf[http_module->ctx_index];
    fmt = lmcf->formats.elts;
    for (i = 0; i < lmcf->formats.nelts; i++) {

    }

    return ;
}

static void ngx_dump_conf_http_main_upstream(ngx_module_t *http_module,
    ngx_http_conf_ctx_t *conf,ngx_cycle_t *cycle)
{
    return ;
}

static void ngx_dump_conf_http_main_map(ngx_module_t *http_module,
    ngx_http_conf_ctx_t *conf,ngx_cycle_t *cycle)
{
    return ;
}

static void ngx_dump_conf_http_main_ssi_filter(ngx_module_t *http_module,
    ngx_http_conf_ctx_t *conf,ngx_cycle_t *cycle)
{
    return ;
}

static void ngx_dump_conf_http_main_charset_filter(ngx_module_t *http_module,
    ngx_http_conf_ctx_t *conf,ngx_cycle_t *cycle)
{
    return ;
}

static void ngx_dump_conf_http_srv(ngx_module_t *http_module,
    ngx_http_conf_ctx_t *conf,ngx_cycle_t *cycle)
{
    ngx_uint_t                 i;
    char                       name[256];

    for (i = 0;i < ngx_http_module_max;i++) {

        if (conf->srv_conf[i] == NULL) {
            continue;
        }

        if (i == ngx_http_core_module.ctx_index) {
            ngx_http_core_srv_conf_t  *srv;

            srv = (ngx_http_core_srv_conf_t *)conf->srv_conf[i];

            strncpy(name, (char *)srv->server_name.data, 
                srv->server_name.len);

            name[srv->server_name.len] = 0;

            printf("             [%02d](ngx_http_core_srv_conf_t *) = %p {\n",i,conf->srv_conf[i]);
            printf("                  .connection_pool_size       = %d \n",srv->connection_pool_size);
            printf("                  .request_pool_size          = %d \n",srv->request_pool_size);
            printf("                  .client_header_buffer_size  = %d \n",srv->client_header_buffer_size);
            printf("                  .client_header_timeout      = %d \n",srv->client_header_timeout);
            printf("                  .ignore_invalid_headers     = %d \n",srv->ignore_invalid_headers);
            printf("                  .merge_slashes              = %d \n",srv->merge_slashes);
            printf("                  .underscores_in_headers     = %d \n",srv->underscores_in_headers);
            printf("                  .listen                     = %d \n",srv->listen);
            printf("                  .captures                   = %d \n",srv->captures);
            printf("             }\n");

            continue;
        }

        if (i == ngx_http_upstream_least_conn_module.ctx_index) {
            ngx_http_upstream_srv_conf_t *srv;

            srv = (ngx_http_upstream_srv_conf_t *)conf->srv_conf[i];

            continue;
        }

        if (i == ngx_http_upstream_keepalive_module.ctx_index) {
            ngx_http_upstream_keepalive_srv_conf_t *srv;

            srv = (ngx_http_upstream_keepalive_srv_conf_t *)conf->srv_conf[i];

            continue;
        }
    }

    ngx_dump_conf_http_loc(http_module,conf,cycle);

    return ;
}
static void ngx_dump_conf_http_loc(ngx_module_t *http_module,
    ngx_http_conf_ctx_t *conf,ngx_cycle_t *cycle)
{
    ngx_uint_t                 i;

    for (i = 0;i < ngx_http_module_max;i++) {

        if (conf->loc_conf[i] == NULL) {
            continue;
        }

        if (i == ngx_http_core_module.ctx_index) {
            continue;
        }

        if (i == ngx_http_upstream_least_conn_module.ctx_index) {
            continue;
        }

        if (i == ngx_http_upstream_keepalive_module.ctx_index) {
            continue;
        }
    }

    return ;
}
