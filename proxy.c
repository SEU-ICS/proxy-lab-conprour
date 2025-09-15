#include "csapp.h"
#include <stdbool.h>

#define MCS 1049000
#define MOS 102400
#define MC 10
#define NTH 4
#define QSZ 16

static const char *UA = 
    "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:10.0.3) "
    "Gecko/20120305 Firefox/10.0.3\r\n";

typedef struct {
    char h[MAXLINE];
    char p[MAXLINE];
    char path[MAXLINE];
} Uri;

typedef struct {
    int *arr;
    int cap;
    int f, r;
    sem_t m, slots, items;
} Q;

typedef struct {
    bool emp;
    Uri u;
    char buf[MOS];
    int lru, rc;
    sem_t m, w;
} CB;

Q q;
CB cs[MC];

/* 缓冲区操作 */
void qi(Q *qp, int n) {
    qp->arr = Calloc(n, sizeof(int));
    qp->cap = n;
    qp->f = qp->r = 0;
    Sem_init(&qp->m, 0, 1);
    Sem_init(&qp->slots, 0, n);
    Sem_init(&qp->items, 0, 0);
}
void qd(Q *qp) { Free(qp->arr); }
void qins(Q *qp, int x) {
    P(&qp->slots);
    P(&qp->m);
    qp->arr[(++qp->r) % qp->cap] = x;
    V(&qp->m);
    V(&qp->items);
}
int qrem(Q *qp) {
    int x;
    P(&qp->items);
    P(&qp->m);
    x = qp->arr[(++qp->f) % qp->cap];
    V(&qp->m);
    V(&qp->slots);
    return x;
}

/* 缓存相关 */
void ci() {
    for (int i = 0; i < MC; i++) {
        cs[i].emp = 1;
        cs[i].rc = 0;
        Sem_init(&cs[i].m, 0, 1);
        Sem_init(&cs[i].w, 0, 1);
    }
}
void ru(CB *c) {
    P(&c->m);
    if (++c->rc == 1) P(&c->w);
    V(&c->m);
}
void re(CB *c) {
    P(&c->m);
    if (--c->rc == 0) V(&c->w);
    V(&c->m);
}
void wu(CB *c) { P(&c->w); }
void we(CB *c) { V(&c->w); }

bool ue(const Uri *a, const Uri *b) {
    return !strcmp(a->h, b->h) && !strcmp(a->p, b->p) && !strcmp(a->path, b->path);
}
void uc(Uri *a, const Uri *b) {
    strncpy(a->h, b->h, MAXLINE);
    strncpy(a->p, b->p, MAXLINE);
    strncpy(a->path, b->path, MAXLINE);
}

CB *gc(Uri *u) {
    CB *res = NULL;
    for (int i = 0; i < MC && !res; i++) {
        ru(&cs[i]);
        if (!cs[i].emp && ue(&cs[i].u, u)) res = &cs[i];
        re(&cs[i]);
    }
    if (res) {
        static int clk = 0;
        wu(res);
        res->lru = ++clk;
        we(res);
    }
    return res;
}
void fc(CB *c, Uri *u, char *d) {
    wu(c);
    c->emp = 0;
    uc(&c->u, u);
    strncpy(c->buf, d, MOS);
    we(c);
    static int clk = 0;
    wu(c);
    c->lru = ++clk;
    we(c);
}
void ic(Uri *u, char *d) {
    CB *pos = NULL;
    for (int i = 0; i < MC && !pos; i++) {
        ru(&cs[i]);
        if (cs[i].emp) pos = &cs[i];
        re(&cs[i]);
    }
    if (!pos) {
        int minl = __INT_MAX__;
        for (int i = 0; i < MC; i++) {
            ru(&cs[i]);
            if (!cs[i].emp && cs[i].lru < minl) {
                minl = cs[i].lru;
                pos = &cs[i];
            }
            re(&cs[i]);
        }
    }
    if (pos) fc(pos, u, d);
}

/* URI解析 */
void pu(const char *s, Uri *u) {
    const char *p = strstr(s, "//");
    p = p ? p + 2 : s;

    const char *slash = strchr(p, '/');
    if (slash) strncpy(u->path, slash, MAXLINE);
    else strncpy(u->path, "/", MAXLINE);

    char tmp[MAXLINE];
    strncpy(tmp, p, MAXLINE);
    if (slash) tmp[slash - p] = '\0';

    char *col = strchr(tmp, ':');
    if (col) {
        *col = '\0';
        strncpy(u->h, tmp, MAXLINE);
        strncpy(u->p, col + 1, MAXLINE);
    } else {
        strncpy(u->h, tmp, MAXLINE);
        strncpy(u->p, "80", MAXLINE);
    }
}

/* 构建请求 */
void br(rio_t *rio, Uri *u, char *req) {
    char line[MAXLINE], m[MAXLINE], us[MAXLINE], v[MAXLINE];
    char hh[MAXLINE] = "", oh[MAXLINE] = "";

    Rio_readlineb(rio, line, MAXLINE);
    sscanf(line, "%s %s %s", m, us, v);
    pu(us, u);

    sprintf(hh, "Host: %s:%s\r\n", u->h, u->p);

    while (Rio_readlineb(rio, line, MAXLINE) > 0) {
        if (!strcmp(line, "\r\n")) break;
        if (!strncasecmp(line, "Host:", 5)) strncpy(hh, line, MAXLINE);
        else if (strncasecmp(line, "User-Agent:", 11) &&
                 strncasecmp(line, "Connection:", 11) &&
                 strncasecmp(line, "Proxy-Connection:", 17)) {
            strncat(oh, line, MAXLINE - strlen(oh) - 1);
        }
    }

    sprintf(req, "%s %s HTTP/1.0\r\n"
                 "%s"
                 "%s"
                 "Connection: close\r\n"
                 "Proxy-Connection: close\r\n"
                 "%s\r\n", m, u->path, hh, UA, oh);
}

/* 处理请求 */
void hc(int fd) {
    rio_t rio_c, rio_s;
    char buf[MAXLINE], req[MAXLINE];
    Uri u;

    Rio_readinitb(&rio_c, fd);
    br(&rio_c, &u, req);

    CB *blk = gc(&u);
    if (blk) {
        Rio_writen(fd, blk->buf, strlen(blk->buf));
        return;
    }

    int sfd = Open_clientfd(u.h, u.p);
    if (sfd < 0) return;

    Rio_readinitb(&rio_s, sfd);
    Rio_writen(sfd, req, strlen(req));

    int n, tot = 0;
    char obuf[MOS], *p = obuf;
    while ((n = Rio_readnb(&rio_s, buf, MAXLINE)) > 0) {
        Rio_writen(fd, buf, n);
        tot += n;
        if (tot < MOS) {
            memcpy(p, buf, n);
            p += n;
        }
    }
    if (tot < MOS) {
        *p = '\0';
        ic(&u, obuf);
    }

    Close(sfd);
}

/* 工作线程 */
void *th(void *arg) {
    Pthread_detach(pthread_self());
    while (1) {
        int fd = qrem(&q);
        hc(fd);
        Close(fd);
    }
    return NULL;
}

/* main函数 */
int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <port>\n", argv[0]);
        exit(1);
    }

    pthread_t tid;
    qi(&q, QSZ);
    ci();

    for (int i = 0; i < NTH; i++) Pthread_create(&tid, NULL, th, NULL);

    int lfd = Open_listenfd(argv[1]);
    while (1) {
        struct sockaddr_storage caddr;
        socklen_t clen = sizeof(caddr);
        int cfd = Accept(lfd, (SA *)&caddr, &clen);
        qins(&q, cfd);
    }
}
