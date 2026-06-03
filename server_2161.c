/*
 * IE2102 - Network Programming Assignment
 * Student: IT24102161
 * Server ID (SID): 1021
 * Port: 50161
 * File: server_2161.c
 */

#define _GNU_SOURCE          /* PTHREAD_PROCESS_SHARED, mmap MAP_ANONYMOUS */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mman.h>        /* Fix [3]: mmap shared memory               */
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>         /* Fix [3]: process-shared mutex              */

/* ── configuration ────────────────────────────────────────── */
#define PORT           50161
#define SID            "1021"
#define REGNO          "IT24102161"
#define MAX_PAYLOAD    4096
#define MAX_BUF        8192
#define TOKEN_EXPIRE   300          /* 5 minutes in seconds   */
#define MAX_FAIL       5            /* lockout after 5 fails  */
#define LOCKOUT_TIME   300          /* 5-minute lockout       */
#define RATE_LIMIT     20           /* max requests per minute*/
#define USER_DB        "/srv/ie2102/IT24102161/users.db"
#define LOG_FILE       "server_IT24102161.log"
#define DATA_DIR       "/srv/ie2102/IT24102161"

/* ── per-child session state ──────────────────────────────── */
typedef struct {
    char   username[64];
    char   token[65];
    time_t token_issued;
    int    logged_in;
} Session;

/* global rate-limit state in shared memory ───── */
typedef struct {
    pthread_mutex_t lock;
    int             req_count;
    time_t          rate_window;
} SharedRate;

static SharedRate *g_rate = NULL;   /* initialised in main() */

/* per-child socket receive buffer ─────────────── */
typedef struct {
    char buf[MAX_BUF * 2];
    int  len;
} RecvBuf;

/* ── forward declarations ─────────────────────────────────── */
static void  sigchld_handler(int s);
static void  log_event(const char *client_ip, int client_port,
                        pid_t pid, const char *username,
                        const char *cmd, const char *result);
static int   recv_all(int fd, char *buf, int len);
static int   send_msg(int fd, const char *msg);
static void  handle_client(int cfd, struct sockaddr_in *cli);

/* Fix [1]: buffered line reader */
static int   recv_line(int fd, RecvBuf *rb, char *line, int maxlen);

/* password hashing (SHA-256 via /usr/bin/sha256sum) — unchanged */
static void  hash_password(const char *pass, const char *salt, char *out, size_t outsz);
static void  gen_token(char *out, size_t sz);
static int   validate_username(const char *u);

/* user DB helpers */
static int   user_exists(const char *username);
static int   register_user(const char *username, const char *password);
static int   check_password(const char *username, const char *password);

/* command handlers */
static void  cmd_register(int cfd, Session *sess, char *args,
                           const char *ip, int port);
static void  cmd_login(int cfd, Session *sess, char *args,
                        const char *ip, int port);
static void  cmd_logout(int cfd, Session *sess,
                         const char *ip, int port);
static void  cmd_ping(int cfd, Session *sess,            /* Fix [2] */
                       const char *ip, int port);

/* ══════════════════════════════════════════════════════════ */
/*  MAIN                                                      */
/* ══════════════════════════════════════════════════════════ */
int main(void)
{
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t cli_len = sizeof(client_addr);
    int opt = 1;

    /* create data directory */
    mkdir("/srv",              0755);
    mkdir("/srv/ie2102",       0755);
    mkdir(DATA_DIR,            0755);

    /* Fix [3]: allocate shared rate-limit struct before first fork() */
    g_rate = mmap(NULL, sizeof(SharedRate),
                  PROT_READ | PROT_WRITE,
                  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (g_rate == MAP_FAILED) { perror("mmap"); exit(1); }

    pthread_mutexattr_t mattr;
    pthread_mutexattr_init(&mattr);
    pthread_mutexattr_setpshared(&mattr, PTHREAD_PROCESS_SHARED);
    pthread_mutex_init(&g_rate->lock, &mattr);
    pthread_mutexattr_destroy(&mattr);
    g_rate->req_count   = 0;
    g_rate->rate_window = time(NULL);

    /* SIGCHLD — reap zombie children */
    struct sigaction sa;
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGCHLD, &sa, NULL);

    /* create TCP socket */
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) { perror("socket"); exit(1); }

    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family      = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port        = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&server_addr,
             sizeof(server_addr)) < 0) {
        perror("bind"); exit(1);
    }

    if (listen(server_fd, 20) < 0) { perror("listen"); exit(1); }

    printf("[SID:%s] Server IT24102161 listening on port %d\n", SID, PORT);
    fflush(stdout);

    /* ── accept loop ──────────────────────────────────────── */
    while (1) {
        client_fd = accept(server_fd,
                           (struct sockaddr *)&client_addr, &cli_len);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            continue;
        }

        pid_t pid = fork();
        if (pid < 0) {
            perror("fork");
            close(client_fd);
            continue;
        }
        if (pid == 0) {
            /* child */
            close(server_fd);
            handle_client(client_fd, &client_addr);
            close(client_fd);
            exit(0);
        }
        /* parent */
        close(client_fd);
    }

    close(server_fd);
    munmap(g_rate, sizeof(SharedRate));
    return 0;
}

/* ══════════════════════════════════════════════════════════ */
/*  SIGCHLD — avoid zombie processes                          */
/* ══════════════════════════════════════════════════════════ */
static void sigchld_handler(int s)
{
    (void)s;
    int saved_errno = errno;
    while (waitpid(-1, NULL, WNOHANG) > 0);
    errno = saved_errno;
}

/* ══════════════════════════════════════════════════════════ */
/*  LOGGING                                                   */
/* ══════════════════════════════════════════════════════════ */
static void log_event(const char *client_ip, int client_port,
                       pid_t pid, const char *username,
                       const char *cmd, const char *result)
{
    FILE *f = fopen(LOG_FILE, "a");
    if (!f) return;

    time_t now = time(NULL);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&now));

    fprintf(f, "[%s] CLIENT=%s:%d PID=%d USER=%s CMD=%s RESULT=%s\n",
            ts,
            client_ip, client_port,
            (int)pid,
            username[0] ? username : "-",
            cmd, result);
    fclose(f);
}

/* ══════════════════════════════════════════════════════════ */
/*  NETWORK HELPERS                                           */
/* ══════════════════════════════════════════════════════════ */

/* reliable recv exactly `len` bytes */
static int recv_all(int fd, char *buf, int len)
{
    int total = 0;
    while (total < len) {
        int n = recv(fd, buf + total, len - total, 0);
        if (n <= 0) return n;
        total += n;
    }
    return total;
}

/* send a null-terminated string */
static int send_msg(int fd, const char *msg)
{
    int len = strlen(msg);
    int sent = 0;
    while (sent < len) {
        int n = send(fd, msg + sent, len - sent, 0);
        if (n < 0) return -1;
        sent += n;
    }
    return 0;
}

/*
 * Fix [1]: recv_line
 * Reads one '\n'-terminated line from the socket into `line` (NUL-terminated,
 * newline excluded).  Any bytes that arrive after the newline in the same
 * recv() call are kept in rb->buf for the next invocation, so no data is lost
 * between requests even under TCP segmentation or pipelining.
 */
static int recv_line(int fd, RecvBuf *rb, char *line, int maxlen)
{
    while (1) {
        /* Check whether a full line already sits in the buffer */
        char *nl = memchr(rb->buf, '\n', rb->len);
        if (nl) {
            int linelen = nl - rb->buf;
            if (linelen >= maxlen) linelen = maxlen - 1;
            memcpy(line, rb->buf, linelen);
            line[linelen] = '\0';
            int consumed = (nl - rb->buf) + 1;  /* include the '\n' */
            rb->len -= consumed;
            memmove(rb->buf, rb->buf + consumed, rb->len);
            return linelen;
        }

        /* Need more data from the network */
        if (rb->len >= (int)sizeof(rb->buf) - 1) return -1; /* overflow */
        int n = recv(fd, rb->buf + rb->len,
                     sizeof(rb->buf) - rb->len - 1, 0);
        if (n <= 0) return n;
        rb->len += n;
    }
}

/* ══════════════════════════════════════════════════════════ */
/*  TOKEN + USERNAME UTILITIES  (unchanged)                   */
/* ══════════════════════════════════════════════════════════ */
static void gen_token(char *out, size_t sz)
{
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) { snprintf(out, sz, "STATIC_TOKEN_%ld", time(NULL)); return; }
    unsigned char raw[32];
    fread(raw, 1, sizeof(raw), f);
    fclose(f);
    for (int i = 0; i < 32 && (size_t)(i*2+2) < sz; i++)
        sprintf(out + i*2, "%02x", raw[i]);
    out[64] = '\0';
}

static int validate_username(const char *u)
{
    if (!u || strlen(u) < 3 || strlen(u) > 32) return 0;
    for (const char *p = u; *p; p++)
        if (!isalnum(*p) && *p != '_') return 0;
    return 1;
}

/* ══════════════════════════════════════════════════════════ */
/*  PASSWORD HASHING  (SHA-256 via sha256sum — unchanged)    */
/* ══════════════════════════════════════════════════════════ */
static void hash_password(const char *pass, const char *salt,
                           char *out, size_t outsz)
{
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "printf '%%s%%s' '%s' '%s' | sha256sum | awk '{print $1}'",
             salt, pass);
    FILE *p = popen(cmd, "r");
    if (!p) { snprintf(out, outsz, "ERROR"); return; }
    fgets(out, outsz, p);
    pclose(p);
    out[strcspn(out, "\n")] = '\0';
}

/* ══════════════════════════════════════════════════════════ */
/*  USER DATABASE  (flat file: username:salt:hash — unchanged)*/
/* ══════════════════════════════════════════════════════════ */
static int user_exists(const char *username)
{
    FILE *f = fopen(USER_DB, "r");
    if (!f) return 0;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char *tok = strtok(line, ":");
        if (tok && strcmp(tok, username) == 0) { fclose(f); return 1; }
    }
    fclose(f);
    return 0;
}

static int register_user(const char *username, const char *password)
{
    if (user_exists(username)) return -1;

    char salt[9];
    FILE *r = fopen("/dev/urandom", "rb");
    if (!r) return -2;
    unsigned char raw[4];
    fread(raw, 1, sizeof(raw), r);
    fclose(r);
    snprintf(salt, sizeof(salt), "%02x%02x%02x%02x",
             raw[0], raw[1], raw[2], raw[3]);

    char hash[128];
    hash_password(password, salt, hash, sizeof(hash));

    char udir[256];
    snprintf(udir, sizeof(udir), "%s/%s", DATA_DIR, username);
    mkdir(udir, 0700);

    FILE *f = fopen(USER_DB, "a");
    if (!f) return -2;
    fprintf(f, "%s:%s:%s\n", username, salt, hash);
    fclose(f);
    return 0;
}

static int check_password(const char *username, const char *password)
{
    FILE *f = fopen(USER_DB, "r");
    if (!f) return 0;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char tmp[256];
        strncpy(tmp, line, sizeof(tmp));
        tmp[sizeof(tmp)-1] = '\0';

        char *uname  = strtok(tmp, ":");
        char *salt   = strtok(NULL, ":");
        char *stored = strtok(NULL, ":\n");

        if (uname && salt && stored &&
            strcmp(uname, username) == 0) {
            fclose(f);
            char computed[128];
            hash_password(password, salt, computed, sizeof(computed));
            return (strcmp(computed, stored) == 0) ? 1 : 0;
        }
    }
    fclose(f);
    return 0;
}

/* ══════════════════════════════════════════════════════════ */
/*  CLIENT HANDLER (runs in child process)                    */
/* ══════════════════════════════════════════════════════════ */
static void handle_client(int cfd, struct sockaddr_in *cli)
{
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &cli->sin_addr, client_ip, sizeof(client_ip));
    int client_port = ntohs(cli->sin_port);
    pid_t mypid = getpid();

    Session sess;
    memset(&sess, 0, sizeof(sess));

    int    fail_count   = 0;
    time_t locked_until = 0;

    /* Fix [1]: per-child receive buffer — initialise once */
    RecvBuf rb;
    memset(&rb, 0, sizeof(rb));

    log_event(client_ip, client_port, mypid, "", "CONNECT", "OK");

    /* ── message receive loop ─────────────────────────────── */
    while (1) {
        /* ── Fix [3]: rate limiting via shared memory ────── */
        pthread_mutex_lock(&g_rate->lock);
        time_t now = time(NULL);
        if (now - g_rate->rate_window > 60) {
            g_rate->rate_window = now;
            g_rate->req_count   = 0;
        }
        int over = (g_rate->req_count >= RATE_LIMIT);
        if (!over) g_rate->req_count++;
        pthread_mutex_unlock(&g_rate->lock);

        if (over) {
            char resp[256];
            snprintf(resp, sizeof(resp),
                     "ERR 429 SID:%s Rate limit exceeded\n", SID);
            send_msg(cfd, resp);
            log_event(client_ip, client_port, mypid,
                      sess.username, "RATE_LIMIT", "BLOCKED");
            break;
        }
        /* ─────────────────────────────────────────────────── */

        /* ── Fix [1]: read LEN:<n> header via recv_line ──── */
        char header[64];
        int hlen = recv_line(cfd, &rb, header, sizeof(header));
        if (hlen <= 0) goto disconnect;

        if (strncmp(header, "LEN:", 4) != 0) {
            char resp[128];
            snprintf(resp, sizeof(resp),
                     "ERR 400 SID:%s Invalid framing\n", SID);
            send_msg(cfd, resp);
            log_event(client_ip, client_port, mypid,
                      sess.username, "FRAMING", "INVALID");
            continue;
        }

        int payload_len = atoi(header + 4);

        /* ── reject oversized payload ── */
        if (payload_len <= 0 || payload_len > MAX_PAYLOAD) {
            char resp[128];
            snprintf(resp, sizeof(resp),
                     "ERR 413 SID:%s Payload too large or invalid\n", SID);
            send_msg(cfd, resp);
            log_event(client_ip, client_port, mypid,
                      sess.username, "PAYLOAD_SIZE", "REJECTED");
            if (payload_len > 0 && payload_len <= 65536) {
                char *drain = malloc(payload_len);
                if (drain) { recv_all(cfd, drain, payload_len); free(drain); }
            }
            continue;
        }

        /* ── recv payload — drain rb first, then socket ──── */
        char payload[MAX_PAYLOAD + 1];
        memset(payload, 0, sizeof(payload));

        int from_buf = rb.len < payload_len ? rb.len : payload_len;
        if (from_buf > 0) {
            memcpy(payload, rb.buf, from_buf);
            rb.len -= from_buf;
            memmove(rb.buf, rb.buf + from_buf, rb.len);
        }
        if (from_buf < payload_len) {
            int got = recv_all(cfd, payload + from_buf,
                               payload_len - from_buf);
            if (got <= 0) goto disconnect;
        }
        payload[payload_len] = '\0';

        /* ── check token expiry ── */
        if (sess.logged_in) {
            if (time(NULL) - sess.token_issued > TOKEN_EXPIRE) {
                sess.logged_in = 0;
                memset(sess.token, 0, sizeof(sess.token));
                char resp[128];
                snprintf(resp, sizeof(resp),
                         "ERR 401 SID:%s Session expired, please login again\n",
                         SID);
                send_msg(cfd, resp);
                log_event(client_ip, client_port, mypid,
                          sess.username, "TOKEN_EXPIRE", "SESSION_CLEARED");
                continue;
            }
            sess.token_issued = time(NULL);
        }

        /* ── parse command ── */
        char cmd[32];
        char args[MAX_PAYLOAD];
        memset(cmd,  0, sizeof(cmd));
        memset(args, 0, sizeof(args));

        char *sp = strchr(payload, ' ');
        if (sp) {
            int clen = sp - payload;
            if (clen >= (int)sizeof(cmd)) clen = sizeof(cmd)-1;
            strncpy(cmd, payload, clen);
            strncpy(args, sp + 1, sizeof(args) - 1);
        } else {
            strncpy(cmd, payload, sizeof(cmd) - 1);
        }
        args[strcspn(args, "\n")] = '\0';

        /* ── dispatch ── */
        if (strcmp(cmd, "REGISTER") == 0) {
            cmd_register(cfd, &sess, args, client_ip, client_port);

        } else if (strcmp(cmd, "LOGIN") == 0) {
            if (time(NULL) < locked_until) {
                char resp[128];
                snprintf(resp, sizeof(resp),
                         "ERR 423 SID:%s Account locked due to failed attempts\n",
                         SID);
                send_msg(cfd, resp);
                log_event(client_ip, client_port, mypid,
                          sess.username, "LOGIN", "LOCKED");
                continue;
            }
            char uarg[64], parg[64];
            memset(uarg, 0, sizeof(uarg));
            memset(parg, 0, sizeof(parg));
            sscanf(args, "%63s %63s", uarg, parg);

            int ok = check_password(uarg, parg);
            if (!ok) {
                fail_count++;
                if (fail_count >= MAX_FAIL) {
                    locked_until = time(NULL) + LOCKOUT_TIME;
                    char resp[128];
                    snprintf(resp, sizeof(resp),
                             "ERR 423 SID:%s Too many failed attempts. Locked for 5 min\n",
                             SID);
                    send_msg(cfd, resp);
                    log_event(client_ip, client_port, mypid,
                              uarg, "LOGIN", "LOCKOUT");
                } else {
                    char resp[128];
                    snprintf(resp, sizeof(resp),
                             "ERR 401 SID:%s Invalid username or password\n", SID);
                    send_msg(cfd, resp);
                    log_event(client_ip, client_port, mypid,
                              uarg, "LOGIN", "FAILED");
                }
            } else {
                fail_count = 0;
                cmd_login(cfd, &sess, args, client_ip, client_port);
            }

        } else if (strcmp(cmd, "LOGOUT") == 0) {
            cmd_logout(cfd, &sess, client_ip, client_port);

        /* Fix [2]: PING — token-protected command */
        } else if (strcmp(cmd, "PING") == 0) {
            cmd_ping(cfd, &sess, client_ip, client_port);

        } else if (strcmp(cmd, "QUIT") == 0 ||
                   strcmp(cmd, "EXIT") == 0) {
            char resp[128];
            snprintf(resp, sizeof(resp),
                     "OK 200 SID:%s Goodbye\n", SID);
            send_msg(cfd, resp);
            log_event(client_ip, client_port, mypid,
                      sess.username, cmd, "DISCONNECTED");
            break;

        } else {
            if (!sess.logged_in) {
                char resp[128];
                snprintf(resp, sizeof(resp),
                         "ERR 403 SID:%s Authentication required\n", SID);
                send_msg(cfd, resp);
                log_event(client_ip, client_port, mypid,
                          sess.username, cmd, "AUTH_REQUIRED");
            } else {
                char resp[128];
                snprintf(resp, sizeof(resp),
                         "ERR 400 SID:%s Unknown command\n", SID);
                send_msg(cfd, resp);
                log_event(client_ip, client_port, mypid,
                          sess.username, cmd, "UNKNOWN_CMD");
            }
        }
    }

disconnect:
    log_event(client_ip, client_port, mypid,
              sess.username, "DISCONNECT", "OK");
}

/* ══════════════════════════════════════════════════════════ */
/*  COMMAND IMPLEMENTATIONS                                   */
/* ══════════════════════════════════════════════════════════ */
static void cmd_register(int cfd, Session *sess, char *args,
                          const char *ip, int port)
{
    (void)sess;
    char user[64], pass[128];
    memset(user, 0, sizeof(user));
    memset(pass, 0, sizeof(pass));

    if (sscanf(args, "%63s %127s", user, pass) != 2) {
        char resp[128];
        snprintf(resp, sizeof(resp),
                 "ERR 400 SID:%s Usage: REGISTER <user> <pass>\n", SID);
        send_msg(cfd, resp);
        log_event(ip, port, getpid(), "", "REGISTER", "BAD_ARGS");
        return;
    }

    if (!validate_username(user)) {
        char resp[128];
        snprintf(resp, sizeof(resp),
                 "ERR 400 SID:%s Invalid username (3-32 alphanumeric/_)\n", SID);
        send_msg(cfd, resp);
        log_event(ip, port, getpid(), user, "REGISTER", "INVALID_USER");
        return;
    }

    int result = register_user(user, pass);
    char resp[256];
    if (result == 0) {
        snprintf(resp, sizeof(resp),
                 "OK 201 SID:%s User %s registered successfully\n", SID, user);
        log_event(ip, port, getpid(), user, "REGISTER", "OK");
    } else if (result == -1) {
        snprintf(resp, sizeof(resp),
                 "ERR 409 SID:%s Username already exists\n", SID);
        log_event(ip, port, getpid(), user, "REGISTER", "DUPLICATE");
    } else {
        snprintf(resp, sizeof(resp),
                 "ERR 500 SID:%s Server error during registration\n", SID);
        log_event(ip, port, getpid(), user, "REGISTER", "SERVER_ERROR");
    }
    send_msg(cfd, resp);
}

static void cmd_login(int cfd, Session *sess, char *args,
                       const char *ip, int port)
{
    char user[64], pass[128];
    memset(user, 0, sizeof(user));
    memset(pass, 0, sizeof(pass));

    if (sscanf(args, "%63s %127s", user, pass) != 2) {
        char resp[128];
        snprintf(resp, sizeof(resp),
                 "ERR 400 SID:%s Usage: LOGIN <user> <pass>\n", SID);
        send_msg(cfd, resp);
        log_event(ip, port, getpid(), "", "LOGIN", "BAD_ARGS");
        return;
    }

    strncpy(sess->username, user, sizeof(sess->username) - 1);
    gen_token(sess->token, sizeof(sess->token));
    sess->token_issued = time(NULL);
    sess->logged_in    = 1;

    char resp[256];
    snprintf(resp, sizeof(resp),
             "OK 200 SID:%s Login successful. TOKEN:%s\n",
             SID, sess->token);
    send_msg(cfd, resp);
    log_event(ip, port, getpid(), user, "LOGIN", "OK");
}

static void cmd_logout(int cfd, Session *sess,
                        const char *ip, int port)
{
    char resp[128];
    if (!sess->logged_in) {
        snprintf(resp, sizeof(resp),
                 "ERR 400 SID:%s Not logged in\n", SID);
        send_msg(cfd, resp);
        log_event(ip, port, getpid(), "", "LOGOUT", "NOT_LOGGED_IN");
        return;
    }

    char user[64];
    strncpy(user, sess->username, sizeof(user));

    memset(sess, 0, sizeof(Session));

    snprintf(resp, sizeof(resp),
             "OK 200 SID:%s Logged out successfully\n", SID);
    send_msg(cfd, resp);
    log_event(ip, port, getpid(), user, "LOGOUT", "OK");
}

/*
 * cmd_ping — protected command that requires a valid session.
 * Unauthenticated → ERR 403.
 * Authenticated   → OK 200 PONG with username and active token.
 */
static void cmd_ping(int cfd, Session *sess,
                      const char *ip, int port)
{
    char resp[256];
    if (!sess->logged_in) {
        snprintf(resp, sizeof(resp),
                 "ERR 403 SID:%s Authentication required\n", SID);
        send_msg(cfd, resp);
        log_event(ip, port, getpid(), "", "PING", "AUTH_REQUIRED");
        return;
    }
    snprintf(resp, sizeof(resp),
             "OK 200 SID:%s PONG user:%s token:%s\n",
             SID, sess->username, sess->token);
    send_msg(cfd, resp);
    log_event(ip, port, getpid(), sess->username, "PING", "OK");
}
